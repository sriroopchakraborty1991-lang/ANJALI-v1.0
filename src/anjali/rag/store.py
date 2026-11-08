"""Knowledge base: ingestion, temporal filtering, hybrid retrieval.

Retrieval is deliberately *not* "embed everything and hope". Three signals combine:

1. **Lexical (BM25 over FTS5)** — legal queries are full of exact tokens
   (``§ 1010.314``, ``structuring``, ``AMLD6``) that dense vectors blur.
2. **Dense (hashed TF-IDF cosine)** — catches paraphrase ("smurfing" vs
   "structuring below threshold").
3. **Reciprocal-rank fusion + MMR** — prevents eight near-duplicate chunks of the
   same provision crowding out the second jurisdiction, which is exactly where
   cross-border conflicts hide.

On top of that sits a hard **temporal filter**: only provisions in force ``as_of``
a given date are retrievable by default. Querying the past is explicit
(``--as-of 2023-01-01``), and superseded text comes back flagged ``stale``.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from anjali.core.db import Database
from anjali.core.models import (
    Chunk,
    Citation,
    DocStatus,
    Jurisdiction,
    RegulatoryDocument,
)
from anjali.core.util import (
    clamp,
    content_tokens,
    sha256_hex,
    stable_id,
    today,
)
from anjali.rag.chunker import chunk_text, snippet_for
from anjali.rag.embedder import (
    LocalTfidfEmbedder,
    build_embedder,
    cosine,
    dumps_idf,
    loads_idf,
    pack_vector,
    unpack_vector,
)
from anjali.rag.ontology import (
    JURISDICTION_BOOST,
    detect_jurisdictions,
    expand,
    tag_overlap,
)

RRF_K = 60.0
STALE_STATUSES = {DocStatus.SUPERSEDED.value, DocStatus.REPEALED.value}


@dataclass
class RetrievedChunk:
    chunk: Chunk
    score: float
    lexical_rank: int | None = None
    vector_score: float = 0.0
    coverage: float = 0.0
    matched_terms: list[str] = field(default_factory=list)

    @property
    def stale(self) -> bool:
        return self.chunk.status.value in STALE_STATUSES

    @property
    def future(self) -> bool:
        return self.chunk.effective_from > today()

    def to_citation(self, *, width: int = 320) -> Citation:
        return Citation(
            doc_id=self.chunk.doc_id,
            citation=self.chunk.citation,
            title=self.chunk.title,
            jurisdiction=self.chunk.jurisdiction,
            regulator=self.chunk.regulator or "",
            source_url=self.chunk.source_url,
            effective_from=self.chunk.effective_from,
            snippet=snippet_for(self.chunk.text, self.matched_terms, width),
            score=round(self.score, 4),
            verified=True,
            stale=self.stale,
            future=self.future,
        )


def _fts_query(tokens: Sequence[str]) -> str:
    safe = []
    for tok in tokens:
        cleaned = "".join(ch for ch in tok if ch.isalnum() or ch in "._-/§")
        cleaned = cleaned.strip("._-/§")
        if len(cleaned) > 1:
            safe.append(f'"{cleaned}"')
    return " OR ".join(dict.fromkeys(safe))


class KnowledgeBase:
    def __init__(self, db: Database, embedder: Any | None = None) -> None:
        self.db = db
        self._embedder = embedder
        self._vec_cache: dict[str, list[float]] | None = None

    # ------------------------------------------------------------------ #
    # Embedder state
    # ------------------------------------------------------------------ #
    @property
    def embedder(self) -> Any:
        if self._embedder is None:
            state = self.db.get_meta("embedder_state")
            self._embedder = loads_idf(state) if state else LocalTfidfEmbedder()
        return self._embedder

    def _save_embedder(self) -> None:
        if isinstance(self.embedder, LocalTfidfEmbedder):
            self.db.set_meta("embedder_state", dumps_idf(self.embedder))
        self.db.set_meta("embedder_tag", self.embedder.tag)

    # ------------------------------------------------------------------ #
    # Ingestion
    # ------------------------------------------------------------------ #
    def upsert_document(self, doc: RegulatoryDocument, *, reindex: bool = False) -> int:
        """Store a document + its chunks. Returns number of chunks written."""
        with self.db.tx() as conn:
            conn.execute(
                """
                INSERT INTO documents(
                    doc_id, citation, title, jurisdiction, regulator, doc_type, status,
                    effective_from, effective_to, amended_by, supersedes, obligations,
                    penalties, source_url, tags, text, digest, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(doc_id) DO UPDATE SET
                    citation=excluded.citation, title=excluded.title,
                    jurisdiction=excluded.jurisdiction, regulator=excluded.regulator,
                    doc_type=excluded.doc_type, status=excluded.status,
                    effective_from=excluded.effective_from, effective_to=excluded.effective_to,
                    amended_by=excluded.amended_by, supersedes=excluded.supersedes,
                    obligations=excluded.obligations, penalties=excluded.penalties,
                    source_url=excluded.source_url, tags=excluded.tags, text=excluded.text,
                    digest=excluded.digest, updated_at=excluded.updated_at
                """,
                (
                    doc.doc_id,
                    doc.citation,
                    doc.title,
                    doc.jurisdiction.value,
                    doc.regulator,
                    doc.doc_type,
                    doc.status.value,
                    doc.effective_from.isoformat(),
                    doc.effective_to.isoformat() if doc.effective_to else None,
                    json.dumps(doc.amended_by),
                    json.dumps(doc.supersedes),
                    json.dumps(doc.obligations),
                    doc.penalties,
                    doc.source_url,
                    json.dumps(doc.tags),
                    doc.text,
                    doc.digest(),
                    today().isoformat(),
                ),
            )
        # Replace any existing chunks for this document (FTS rows included).
        self._delete_fts_for_doc(doc.doc_id)
        with self.db.tx() as conn:
            conn.execute("DELETE FROM chunks WHERE doc_id=?", (doc.doc_id,))

        pieces = chunk_text(doc.text, heading=doc.title)
        written = 0
        with self.db.tx() as conn:
            for piece in pieces:
                chunk_id = stable_id(doc.doc_id, piece.ordinal, piece.text[:80], prefix="chk_")
                conn.execute(
                    """
                    INSERT OR REPLACE INTO chunks(
                        chunk_id, doc_id, citation, title, jurisdiction, regulator, doc_type,
                        status, effective_from, effective_to, source_url, tags, section,
                        ordinal, text, embedder, vec
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        chunk_id,
                        doc.doc_id,
                        doc.citation,
                        doc.title,
                        doc.jurisdiction.value,
                        doc.regulator,
                        doc.doc_type,
                        doc.status.value,
                        doc.effective_from.isoformat(),
                        doc.effective_to.isoformat() if doc.effective_to else None,
                        doc.source_url,
                        json.dumps(doc.tags),
                        piece.section,
                        piece.ordinal,
                        piece.text,
                        None,
                        None,
                    ),
                )
                conn.execute(
                    "INSERT INTO chunks_fts(chunk_id, text, citation, title, tags) "
                    "VALUES(?,?,?,?,?)",
                    (
                        chunk_id,
                        f"{piece.text} {doc.citation} {doc.title}",
                        doc.citation,
                        doc.title,
                        " ".join(doc.tags),
                    ),
                )
                written += 1
        if reindex:
            self.rebuild_vectors()
        return written

    def _delete_fts_for_doc(self, doc_id: str) -> None:
        """Remove FTS rows for a document. Must run before chunks are deleted."""
        rows = self.db.query("SELECT chunk_id FROM chunks WHERE doc_id=?", (doc_id,))
        doc = self.db.one("SELECT citation, title FROM documents WHERE doc_id=?", (doc_id,))
        with self.db.tx() as conn:
            for row in rows:
                conn.execute("DELETE FROM chunks_fts WHERE chunk_id=?", (row["chunk_id"],))
            if doc:
                conn.execute(
                    "DELETE FROM chunks_fts WHERE citation=? AND title=?",
                    (doc["citation"], doc["title"]),
                )

    def ingest(self, docs: Iterable[RegulatoryDocument], *, show_progress: bool = False) -> dict[str, int]:
        docs = list(docs)
        chunks = 0
        for i, doc in enumerate(docs, 1):
            chunks += self.upsert_document(doc)
            if show_progress and i % 10 == 0:
                from rich.console import Console

                Console(stderr=True).print(f"  … ingested {i}/{len(docs)} documents", style="dim")
        self.rebuild_vectors()
        return {"documents": len(docs), "chunks": chunks}

    # ------------------------------------------------------------------ #
    # Index rebuild
    # ------------------------------------------------------------------ #
    def rebuild_vectors(self) -> int:
        rows = self.db.query("SELECT chunk_id, text FROM chunks")
        if not rows:
            return 0
        texts = [r["text"] for r in rows]
        embedder = self.embedder
        if isinstance(embedder, LocalTfidfEmbedder):
            embedder = LocalTfidfEmbedder()  # refit so IDF reflects the full corpus
            embedder.fit(texts)
            self._embedder = embedder
            vectors = embedder.embed_many(texts)
        else:
            vectors = embedder.embed_many(texts)
        with self.db.tx() as conn:
            for row, vec in zip(rows, vectors):
                conn.execute(
                    "UPDATE chunks SET vec=?, embedder=? WHERE chunk_id=?",
                    (pack_vector(vec), embedder.tag, row["chunk_id"]),
                )
        self._save_embedder()
        self._vec_cache = None
        self.db.set_meta("indexed_at", today().isoformat())
        self.db.set_meta("chunk_count", str(len(rows)))
        return len(rows)

    def _vectors(self) -> dict[str, list[float]]:
        if self._vec_cache is None:
            tag = self.embedder.tag
            self._vec_cache = {
                r["chunk_id"]: unpack_vector(r["vec"])
                for r in self.db.query(
                    "SELECT chunk_id, vec FROM chunks WHERE vec IS NOT NULL AND embedder=?",
                    (tag,),
                )
            }
        return self._vec_cache

    # ------------------------------------------------------------------ #
    # Retrieval
    # ------------------------------------------------------------------ #
    def search(
        self,
        query: str,
        *,
        top_k: int = 8,
        candidate_k: int = 40,
        jurisdictions: Sequence[str] | None = None,
        as_of: date | None = None,
        include_superseded: bool = False,
        doc_types: Sequence[str] | None = None,
        mmr_lambda: float = 0.72,
        min_score: float = 0.0,
    ) -> list[RetrievedChunk]:
        as_of = as_of or today()
        query = (query or "").strip()
        if not query:
            return []

        clauses = ["effective_from <= ?"]
        params: list[Any] = [as_of.isoformat()]
        if include_superseded:
            clauses.append("status IN ('in_force','amended','superseded','repealed')")
        else:
            clauses.append("status IN ('in_force','amended')")
            clauses.append("(effective_to IS NULL OR effective_to >= ?)")
            params.append(as_of.isoformat())
        if jurisdictions:
            placeholders = ",".join("?" for _ in jurisdictions)
            clauses.append(f"jurisdiction IN ({placeholders})")
            params.extend([j.upper() for j in jurisdictions])
        if doc_types:
            placeholders = ",".join("?" for _ in doc_types)
            clauses.append(f"doc_type IN ({placeholders})")
            params.extend(doc_types)
        where = " AND ".join(clauses)

        rows = self.db.query(f"SELECT * FROM chunks WHERE {where}", tuple(params))
        if not rows:
            return []
        allowed = {r["chunk_id"]: r for r in rows}

        literal_tokens = content_tokens(query)
        expanded = expand(literal_tokens)
        # Two-letter jurisdiction acronyms are handled by the jurisdiction hint, not by
        # BM25 — as bare FTS terms they match almost everything and swamp the ranking.
        fts_terms = [t.term for t in expanded if len(t.term) > 2]
        hinted = detect_jurisdictions(query)
        focus_tokens = [t for t in literal_tokens if len(t) >= 3]

        lexical_ranks: dict[str, int] = {}
        matched_terms: dict[str, list[str]] = {}
        fts_query = _fts_query(fts_terms)
        if fts_query:
            try:
                hits = self.db.query(
                    "SELECT chunk_id, bm25(chunks_fts) AS score FROM chunks_fts "
                    "WHERE chunks_fts MATCH ? ORDER BY score LIMIT ?",
                    (fts_query, max(candidate_k * 3, 120)),
                )
            except sqlite3.OperationalError:
                hits = []
            rank = 0
            for hit in hits:
                cid = hit["chunk_id"]
                if cid not in allowed:
                    continue
                lexical_ranks[cid] = rank
                rank += 1
                text_lower = allowed[cid]["text"].lower()
                matched_terms[cid] = [t for t in literal_tokens if t in text_lower][:8]

        vecs = self._vectors()
        qvec = self.embedder.embed(query)
        vector_scores: dict[str, float] = {}
        for cid in allowed:
            vec = vecs.get(cid)
            if vec:
                score = cosine(qvec, vec)
                if score > 0.0:
                    vector_scores[cid] = score

        vec_order = sorted(vector_scores.items(), key=lambda kv: kv[1], reverse=True)
        vec_ranks = {cid: i for i, (cid, _) in enumerate(vec_order[: candidate_k * 3])}

        # Reciprocal rank fusion of the lexical and dense rankings.
        fused: dict[str, float] = {}
        for cid in set(lexical_ranks) | set(vec_ranks):
            score = 0.0
            if cid in lexical_ranks:
                score += 1.0 / (RRF_K + lexical_ranks[cid] + 1)
            if cid in vec_ranks:
                score += 1.0 / (RRF_K + vec_ranks[cid] + 1)
            fused[cid] = score

        if not fused:
            return self._future_named_hits(literal_tokens, as_of, jurisdictions)

        max_fused = max(fused.values()) or 1.0
        candidates: list[RetrievedChunk] = []
        for cid, score in fused.items():
            row = allowed[cid]
            text_lower = row["text"].lower()
            coverage = (
                sum(1 for t in focus_tokens if t in text_lower) / len(focus_tokens)
                if focus_tokens
                else 0.0
            )
            tags = json.loads(row["tags"] or "[]")
            # Curated tags are the highest-precision signal in the corpus.
            tag_boost = min(0.24, 0.06 * tag_overlap(focus_tokens, tags))
            title_hits = sum(1 for t in focus_tokens if t in (row["title"] or "").lower())
            title_boost = min(0.12, 0.06 * title_hits)
            base = (
                (score / max_fused)
                + 0.18 * vector_scores.get(cid, 0.0)
                + 0.12 * coverage
                + tag_boost
                + title_boost
            )
            if hinted and row["jurisdiction"] in hinted:
                base *= JURISDICTION_BOOST
            candidates.append(
                RetrievedChunk(
                    chunk=self._row_to_chunk(row),
                    score=clamp(base, 0.0, 2.0),
                    lexical_rank=lexical_ranks.get(cid),
                    vector_score=vector_scores.get(cid, 0.0),
                    coverage=coverage,
                    matched_terms=matched_terms.get(cid, []),
                )
            )
        candidates.sort(key=lambda c: c.score, reverse=True)
        candidates = [c for c in candidates if c.score >= min_score] or candidates

        # MMR: relevance vs. novelty, using dense vectors for similarity.
        selected: list[RetrievedChunk] = []
        pool = candidates[: max(top_k * 4, candidate_k)]
        per_doc: dict[str, int] = {}
        max_per_doc = 2
        while pool and len(selected) < top_k:
            best_idx, best_val = 0, float("-inf")
            for i, cand in enumerate(pool):
                if per_doc.get(cand.chunk.doc_id, 0) >= max_per_doc:
                    continue
                if not selected:
                    val = cand.score
                else:
                    sim = max(
                        cosine(vecs.get(cand.chunk.chunk_id, []), vecs.get(s.chunk.chunk_id, []))
                        for s in selected
                    )
                    val = mmr_lambda * cand.score - (1 - mmr_lambda) * sim
                if val > best_val:
                    best_idx, best_val = i, val
            if best_val == float("-inf"):  # every remaining candidate is a duplicate doc
                break
            chosen = pool.pop(best_idx)
            per_doc[chosen.chunk.doc_id] = per_doc.get(chosen.chunk.doc_id, 0) + 1
            selected.append(chosen)

        # Surface provisions the analyst asked for by name that are not yet in force.
        for extra in self._future_named_hits(literal_tokens, as_of, jurisdictions):
            if all(extra.chunk.doc_id != s.chunk.doc_id for s in selected):
                selected.append(extra)
        return selected

    def _future_named_hits(
        self,
        tokens: list[str],
        as_of: date,
        jurisdictions: Sequence[str] | None,
        *,
        limit: int = 2,
    ) -> list[RetrievedChunk]:
        """Provisions explicitly named in the query but not yet in force.

        A temporal filter that silently drops AMLD6 when an analyst asks about AMLD6 is
        worse than useless — it looks like the corpus has never heard of it. Instead the
        provision is returned, flagged ``future``, so the answer can say "not in force
        until 10 July 2027" rather than quietly citing the wrong regime.
        """
        if not tokens:
            return []
        wanted = {t for t in tokens if len(t) > 2}
        if not wanted:
            return []
        clauses = ["effective_from > ?"]
        params: list[Any] = [as_of.isoformat()]
        if jurisdictions:
            placeholders = ",".join("?" for _ in jurisdictions)
            clauses.append(f"jurisdiction IN ({placeholders})")
            params.extend([j.upper() for j in jurisdictions])
        rows = self.db.query(
            f"SELECT * FROM chunks WHERE {' AND '.join(clauses)} ORDER BY effective_from", tuple(params)
        )
        scored: dict[str, tuple[int, float]] = {}
        best_row: dict[str, Any] = {}
        for row in rows:
            identity = f"{row['doc_id']} {row['citation']}".lower()
            # Must be named by identity ("AMLD6", "2024/1640"), not merely share vocabulary
            # with the body — otherwise every future provision matches every AML question.
            distinctive = sum(1 for t in wanted if len(t) >= 3 and t in identity)
            if distinctive == 0:
                continue
            tag_hits = tag_overlap(tokens, json.loads(row["tags"] or "[]"))
            if row["doc_id"] not in scored or (row["ordinal"] == 0 and scored[row["doc_id"]][1] < 1.0):
                scored[row["doc_id"]] = (distinctive * 2 + tag_hits, 1.0 if row["ordinal"] == 0 else 0.5)
                best_row[row["doc_id"]] = row
        ranked = sorted(scored.items(), key=lambda kv: (kv[1][0], kv[1][1]), reverse=True)[:limit]
        out: list[RetrievedChunk] = []
        for doc_id, (hits, _) in ranked:
            row = best_row[doc_id]
            out.append(
                RetrievedChunk(
                    chunk=self._row_to_chunk(row),
                    score=0.30,
                    coverage=min(1.0, hits / max(1, len(wanted))),
                    matched_terms=[t for t in tokens if t in row["text"].lower()][:8],
                )
            )
        return out

    @staticmethod
    def _row_to_chunk(row: sqlite3.Row) -> Chunk:
        return Chunk(
            chunk_id=row["chunk_id"],
            doc_id=row["doc_id"],
            citation=row["citation"],
            title=row["title"],
            jurisdiction=Jurisdiction(row["jurisdiction"]),
            regulator=row["regulator"] or "",
            doc_type=row["doc_type"] or "regulation",
            status=DocStatus(row["status"]),
            effective_from=date.fromisoformat(row["effective_from"]),
            effective_to=date.fromisoformat(row["effective_to"]) if row["effective_to"] else None,
            source_url=row["source_url"],
            tags=json.loads(row["tags"] or "[]"),
            section=row["section"],
            text=row["text"],
            ordinal=row["ordinal"] or 0,
        )

    def search_citations(self, query: str, **kwargs: Any) -> list[Citation]:
        return [hit.to_citation() for hit in self.search(query, **kwargs)]

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    def get_document(self, doc_id: str) -> dict[str, Any] | None:
        row = self.db.one("SELECT * FROM documents WHERE doc_id=?", (doc_id,))
        return dict(row) if row else None

    def find_by_citation(self, citation: str, *, as_of: date | None = None) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM documents WHERE citation LIKE ? ORDER BY effective_from DESC",
            (f"%{citation.strip()}%",),
        )
        return [dict(r) for r in rows]

    def list_documents(
        self,
        *,
        jurisdiction: str | None = None,
        status: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if jurisdiction:
            clauses.append("jurisdiction=?")
            params.append(jurisdiction.upper())
        if status:
            clauses.append("status=?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.db.query(
            f"SELECT doc_id, citation, title, jurisdiction, regulator, doc_type, status, "
            f"effective_from, effective_to FROM documents {where} "
            f"ORDER BY jurisdiction, citation LIMIT ?",
            (*params, limit),
        )
        return [dict(r) for r in rows]

    def stats(self) -> dict[str, Any]:
        by_juris = {
            r["jurisdiction"]: r["n"]
            for r in self.db.query(
                "SELECT jurisdiction, COUNT(*) AS n FROM documents GROUP BY jurisdiction"
            )
        }
        by_status = {
            r["status"]: r["n"]
            for r in self.db.query("SELECT status, COUNT(*) AS n FROM documents GROUP BY status")
        }
        return {
            "documents": self.db.scalar("SELECT COUNT(*) FROM documents") or 0,
            "chunks": self.db.scalar("SELECT COUNT(*) FROM chunks") or 0,
            "vectorised": self.db.scalar("SELECT COUNT(*) FROM chunks WHERE vec IS NOT NULL") or 0,
            "with_vectors": self.db.scalar("SELECT COUNT(*) FROM chunks WHERE vec IS NOT NULL") or 0,
            "by_jurisdiction": by_juris,
            "by_status": by_status,
            "indexed_at": self.db.get_meta("indexed_at"),
            "embedder": self.embedder.tag,
            "index_digest": self.index_digest(),
        }

    def index_digest(self) -> str:
        ids = [r["chunk_id"] for r in self.db.query("SELECT chunk_id FROM chunks ORDER BY chunk_id")]
        docs = [r["digest"] for r in self.db.query("SELECT digest FROM documents ORDER BY doc_id")]
        return sha256_hex("|".join(ids) + "#" + "|".join(d or "" for d in docs))[:16]

    def delete_document(self, doc_id: str) -> bool:
        self._delete_fts_for_doc(doc_id)
        with self.db.tx() as conn:
            conn.execute("DELETE FROM chunks WHERE doc_id=?", (doc_id,))
            cur = conn.execute("DELETE FROM documents WHERE doc_id=?", (doc_id,))
        self._vec_cache = None
        return cur.rowcount > 0

    def as_of_dates(self) -> dict[str, int]:
        """Corpus freshness histogram by year — powers ``anjali kb timeline``."""
        rows = self.db.query(
            "SELECT substr(effective_from,1,4) AS yr, COUNT(*) AS n FROM documents "
            "GROUP BY yr ORDER BY yr"
        )
        return {r["yr"]: r["n"] for r in rows}


def open_kb(settings: Any) -> KnowledgeBase:
    db = Database(settings.db_path)
    embedder = build_embedder(settings)
    if isinstance(embedder, LocalTfidfEmbedder):
        state = db.get_meta("embedder_state")
        if state:
            embedder = loads_idf(state)
        return KnowledgeBase(db, embedder)
    return KnowledgeBase(db, None)
