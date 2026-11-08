"""Hash-chained, append-only audit trail.

Every decision points to the record that produced it: the retrieval, the screening, the
score, the narrative draft, the human approval. Records are chained so that deleting or
editing one breaks every subsequent hash — which is what makes the log usable as evidence
rather than as a log file someone could quietly tidy up.

Storage is a JSONL file next to the case database (never a remote service), plus a
lightweight index in SQLite for fast lookups. No personal data is written to the chain
beyond what the decision record already contains; payloads are stored as digests with the
details in a bounded, reviewable structure.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from anjali.core.db import Database
from anjali.core.models import AuditRecord
from anjali.core.util import atomic_write, sha256_hex, utcnow

GENESIS = "0" * 64


@dataclass
class VerificationResult:
    valid: bool
    records: int
    first_break: int | None = None
    issues: list[str] | None = None
    head_hash: str = GENESIS

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "records": self.records,
            "first_break": self.first_break,
            "issues": self.issues or [],
            "head_hash": self.head_hash,
        }


def _canonical(details: dict[str, Any]) -> str:
    return json.dumps(details, sort_keys=True, separators=(",", ":"), default=str)


class AuditTrail:
    def __init__(self, path: Path, db: Database | None = None, actor: str = "analyst") -> None:
        self.path = Path(path)
        self.db = db
        self.actor = actor
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    def _read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append({"__corrupt__": True, "raw": line[:200]})
        return records

    def head(self) -> tuple[int, str]:
        records = self._read_all()
        if not records or "__corrupt__" in records[-1]:
            return 0, GENESIS
        last = records[-1]
        return int(last.get("seq", 0)), str(last.get("hash", GENESIS))

    def append(
        self,
        action: str,
        *,
        subject: str | None = None,
        details: dict[str, Any] | None = None,
        actor: str | None = None,
    ) -> AuditRecord:
        seq, prev_hash = self.head()
        details = details or {}
        digest = sha256_hex(_canonical(details))
        timestamp = utcnow()
        body = "|".join(
            [str(seq + 1), timestamp.isoformat(), actor or self.actor, action, subject or "", digest, prev_hash]
        )
        record = AuditRecord(
            seq=seq + 1,
            timestamp=timestamp,
            actor=actor or self.actor,
            action=action,
            subject=subject,
            payload_digest=digest,
            prev_hash=prev_hash,
            hash=sha256_hex(body),
            details=details,
        )
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(record.model_dump_json() + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        if self.db is not None:
            with self.db.tx() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO audit_index(seq, timestamp, actor, action, subject, hash) "
                    "VALUES(?,?,?,?,?,?)",
                    (
                        record.seq,
                        record.timestamp.isoformat(),
                        record.actor,
                        record.action,
                        record.subject,
                        record.hash,
                    ),
                )
        return record

    # ------------------------------------------------------------------ #
    def verify(self) -> VerificationResult:
        records = self._read_all()
        prev = GENESIS
        issues: list[str] = []
        for index, raw in enumerate(records, start=1):
            if raw.get("__corrupt__"):
                return VerificationResult(
                    valid=False, records=len(records), first_break=index,
                    issues=[f"Record {index} is not valid JSON: {raw.get('raw')}"], head_hash=prev,
                )
            try:
                record = AuditRecord.model_validate(raw)
            except Exception as exc:
                return VerificationResult(
                    valid=False, records=len(records), first_break=index,
                    issues=[f"Record {index} fails schema validation: {exc}"], head_hash=prev,
                )
            if record.seq != index:
                issues.append(f"Record {index}: expected seq {index}, found {record.seq}")
            if record.prev_hash != prev:
                return VerificationResult(
                    valid=False, records=len(records), first_break=index,
                    issues=[*issues, f"Record {index}: broken chain link"], head_hash=prev,
                )
            digest = sha256_hex(_canonical(record.details))
            if digest != record.payload_digest:
                return VerificationResult(
                    valid=False, records=len(records), first_break=index,
                    issues=[*issues, f"Record {index}: payload digest mismatch (content edited)"],
                    head_hash=prev,
                )
            body = "|".join(
                [
                    str(record.seq), record.timestamp.isoformat(), record.actor, record.action,
                    record.subject or "", record.payload_digest, record.prev_hash,
                ]
            )
            if sha256_hex(body) != record.hash:
                return VerificationResult(
                    valid=False, records=len(records), first_break=index,
                    issues=[*issues, f"Record {index}: record hash mismatch"], head_hash=prev,
                )
            prev = record.hash
        return VerificationResult(valid=True, records=len(records), issues=issues, head_hash=prev)

    def records(self, *, limit: int | None = None, action: str | None = None) -> list[dict[str, Any]]:
        rows = self._read_all()
        if action:
            rows = [r for r in rows if r.get("action") == action]
        if limit:
            rows = rows[-limit:]
        return rows

    def export_json(self, dest: Path) -> Path:
        payload = {
            "exported_at": utcnow().isoformat(),
            "verification": self.verify().to_dict(),
            "records": self._read_all(),
        }
        dest.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(dest, json.dumps(payload, indent=2, default=str) + "\n")
        return dest

    def export_markdown(self, dest: Path, *, limit: int | None = 500) -> Path:
        verification = self.verify()
        lines = ["# ANJALI-AI audit trail", ""]
        lines.append(f"**Records:** {verification.records}  ")
        lines.append(f"**Chain status:** {'VALID' if verification.valid else 'BROKEN'}  ")
        lines.append(f"**Head hash:** `{verification.head_hash}`  ")
        lines.append(f"**Exported:** {utcnow().isoformat()}Z")
        lines.append("")
        if not verification.valid:
            lines.append(f"> **WARNING** — integrity failure at record {verification.first_break}: "
                         f"{'; '.join(verification.issues or [])}")
            lines.append("")
        lines.append("| Seq | Timestamp (UTC) | Actor | Action | Subject | Hash (short) |")
        lines.append("|-----|-----------------|-------|--------|---------|--------------|")
        for record in self.records(limit=limit):
            lines.append(
                f"| {record.get('seq')} | {record.get('timestamp')} | {record.get('actor')} | "
                f"{record.get('action')} | {record.get('subject') or '—'} | "
                f"`{str(record.get('hash'))[:12]}` |"
            )
        lines.append("")
        lines.append(
            "Each record hashes its predecessor, so any insertion, deletion or edit breaks the "
            "chain from that point forward. Verify with `anjali audit verify`."
        )
        dest.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(dest, "\n".join(lines) + "\n")
        return dest

    def stats(self) -> dict[str, Any]:
        records = self._read_all()
        actions: dict[str, int] = {}
        for record in records:
            actions[record.get("action", "?")] = actions.get(record.get("action", "?"), 0) + 1
        verification = self.verify()
        return {
            "records": len(records),
            "actions": dict(sorted(actions.items(), key=lambda kv: kv[1], reverse=True)),
            "valid": verification.valid,
            "head_hash": verification.head_hash,
            "path": str(self.path),
        }


def open_trail(settings: Any, *, actor: str | None = None, db: Database | None = None) -> AuditTrail:
    return AuditTrail(settings.audit_path, db=db, actor=actor or os.environ.get("ANJALI_ACTOR", "analyst"))


def retention_report(db: Database, records: Iterable[dict[str, Any]], *, years: int = 5) -> dict[str, Any]:
    """Which cases are past their retention period and due for deletion."""
    from datetime import date, timedelta

    cutoff = (date.today() - timedelta(days=365 * years)).isoformat()
    stale = [r for r in records if str(r.get("timestamp", ""))[:10] < cutoff]
    return {
        "policy_years": years,
        "cutoff": cutoff,
        "records_past_retention": len(stale),
        "note": (
            "Retention is set by 31 CFR 1010.430 (US), MLR 2017 reg. 40 (UK) and the AMLR (EU) "
            "at five years. Records under legal hold must not be deleted even when past this "
            "cutoff — check for open cases before purging."
        ),
    }
