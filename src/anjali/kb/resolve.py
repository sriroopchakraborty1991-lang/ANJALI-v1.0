"""Resolve ``doc_id`` keys to full, verifiable citations.

Detectors and risk dimensions reference corpus ids rather than free-text citations.
This module is the single place where those ids become citations, so an unknown id is
always visible (it raises in strict mode) instead of silently degrading an answer into
an uncited assertion.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import date

from anjali.core.models import Citation, DocStatus, Jurisdiction
from anjali.core.util import truncate
from anjali.rag.store import KnowledgeBase


def resolve(
    kb: KnowledgeBase,
    keys: Sequence[str],
    *,
    as_of: date | None = None,
    strict: bool = False,
) -> list[Citation]:
    out: list[Citation] = []
    seen: set[str] = set()
    for key in keys:
        if not key or key in seen:
            continue
        seen.add(key)
        row = kb.get_document(key)
        if row is None and "/" in key:
            matches = kb.find_by_citation(key, as_of=as_of)
            row = matches[0] if matches else None
        if row is None:
            if strict:
                raise KeyError(f"Unknown regulatory reference '{key}' — corpus is out of sync.")
            continue
        effective_from = date.fromisoformat(row["effective_from"]) if row.get("effective_from") else None
        effective_to = date.fromisoformat(row["effective_to"]) if row.get("effective_to") else None
        status = row.get("status") or "in_force"
        stale = status in (DocStatus.SUPERSEDED.value, DocStatus.REPEALED.value)
        future = bool(effective_from and effective_from > (as_of or date.today()))
        out.append(
            Citation(
                doc_id=row["doc_id"],
                citation=row["citation"],
                title=row["title"],
                jurisdiction=Jurisdiction(row["jurisdiction"]),
                regulator=row.get("regulator") or "",
                source_url=row.get("source_url"),
                effective_from=effective_from,
                snippet=truncate(row.get("text") or "", 300),
                score=1.0,
                verified=True,
                stale=stale or bool(effective_to and effective_to < (as_of or date.today())),
                future=future,
            )
        )
    return out


def verify_citation(kb: KnowledgeBase, citation: str, *, as_of: date | None = None) -> dict[str, object]:
    """Used by ``anjali kb verify`` and by the agent's citation guardrail."""
    rows = kb.find_by_citation(citation, as_of=as_of)
    if not rows:
        return {"query": citation, "found": False, "documents": []}
    docs = []
    for row in rows:
        status = row.get("status") or "in_force"
        eff_from = row.get("effective_from")
        eff_to = row.get("effective_to")
        current = status in ("in_force", "amended") and (
            not eff_from or eff_from <= (as_of or date.today()).isoformat()
        ) and (not eff_to or eff_to >= (as_of or date.today()).isoformat())
        docs.append(
            {
                "doc_id": row["doc_id"],
                "citation": row["citation"],
                "title": row["title"],
                "jurisdiction": row["jurisdiction"],
                "status": status,
                "effective_from": eff_from,
                "effective_to": eff_to,
                "in_force_at_as_of": current,
                "source_url": row.get("source_url"),
                "tags": json.loads(row["tags"] or "[]"),
            }
        )
    return {"query": citation, "found": True, "documents": docs}
