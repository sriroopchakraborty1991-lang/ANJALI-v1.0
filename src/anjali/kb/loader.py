"""Load the bundled regulatory corpus plus any local additions.

Bundle discovery order:
1. the packaged corpus (``anjali/kb/corpus/*.yaml``) — versioned with the release;
2. ``$ANJALI_HOME/corpus/*.yaml`` — institution-specific policies, always additive;
3. explicit paths passed on the command line.

Local files may override a bundled document by reusing its ``doc_id``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from anjali.core.errors import IngestError
from anjali.core.models import (
    DocStatus,
    Jurisdiction,
    RegulatoryDocument,
)
from anjali.core.util import sha256_hex, slug, today

BUNDLED_CORPUS = Path(__file__).parent / "corpus"


def bundled_files() -> list[Path]:
    return sorted(BUNDLED_CORPUS.glob("*.yaml"))


def _parse_yaml(path: Path) -> list[dict[str, Any]]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise IngestError(f"Cannot parse {path.name}: {exc}") from exc
    except OSError as exc:
        raise IngestError(f"Cannot read {path}: {exc}") from exc
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return raw.get("documents") or []
    raise IngestError(f"{path.name}: expected a mapping with a 'documents' key or a list")


def _coerce(doc: dict[str, Any], source: str) -> RegulatoryDocument:
    payload = dict(doc)
    payload.setdefault("jurisdiction", "INTL")
    payload.setdefault("doc_type", "guidance")
    payload.setdefault("status", "in_force")
    payload.setdefault("regulator", "Unspecified")
    if "doc_id" not in payload and "citation" in payload:
        payload["doc_id"] = f"local-{slug(payload['citation'])}"
    if "effective_from" not in payload:
        payload["effective_from"] = today().isoformat()
    try:
        return RegulatoryDocument.model_validate(payload)
    except Exception as exc:
        raise IngestError(f"Invalid document in {source}: {exc}") from exc


def load_documents(
    *,
    home_corpus: Path | None = None,
    extra_paths: list[Path] | None = None,
) -> list[RegulatoryDocument]:
    docs: dict[str, RegulatoryDocument] = {}
    paths = bundled_files()
    if home_corpus and home_corpus.exists():
        paths += sorted(home_corpus.glob("*.yaml"))
    for path in extra_paths or []:
        if path.is_dir():
            paths += sorted(list(path.glob("*.yaml")) + list(path.glob("*.yml")))
        elif path.suffix.lower() in {".yaml", ".yml"}:
            paths.append(path)
        elif path.exists():
            docs[slug(path.stem)] = document_from_text_file(path)
    for path in paths:
        for raw in _parse_yaml(path):
            doc = _coerce(raw, path.name)
            docs[doc.doc_id] = doc
    return list(docs.values())


def document_from_text_file(
    path: Path,
    *,
    jurisdiction: str = "INTL",
    citation: str | None = None,
    title: str | None = None,
) -> RegulatoryDocument:
    """Wrap a plain-text or markdown policy in the corpus schema."""
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        raise IngestError(f"{path} is empty")
    return RegulatoryDocument(
        doc_id=f"local-{slug(path.stem)}",
        citation=citation or f"Internal policy: {path.stem}",
        title=title or path.stem.replace("_", " ").replace("-", " ").title(),
        jurisdiction=Jurisdiction(jurisdiction.upper()),
        regulator="Internal",
        doc_type="guidance",
        status=DocStatus.IN_FORCE,
        effective_from=today(),
        source_url=None,
        tags=["internal", "policy"],
        text=text,
        confidence_note=f"Local file ingested {today().isoformat()} (sha256 {sha256_hex(text)[:12]}).",
    )


def corpus_manifest() -> list[dict[str, Any]]:
    """Summarise the bundled corpus without touching the database."""
    rows: list[dict[str, Any]] = []
    for path in bundled_files():
        raws = _parse_yaml(path)
        rows.append(
            {
                "file": path.name,
                "documents": len(raws),
                "jurisdictions": sorted({str(r.get("jurisdiction", "INTL")) for r in raws}),
            }
        )
    return rows


def export_corpus_json(dest: Path) -> int:
    docs = load_documents()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps([d.to_dict() for d in docs], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return len(docs)
