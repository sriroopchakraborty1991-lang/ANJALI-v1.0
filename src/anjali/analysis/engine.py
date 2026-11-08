"""Analysis orchestration: transactions in, cited findings and a risk assessment out."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from anjali.analysis.patterns import (
    DETECTOR_DESCRIPTIONS,
    DETECTORS,
    AnalysisContext,
    Detection,
    DetectorConfig,
)
from anjali.analysis.risk import RiskWeights, assess, volume_summary
from anjali.core.db import Database
from anjali.core.models import Finding, RiskAssessment, Severity
from anjali.core.util import stable_id, utcnow

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class AnalysisResult:
    findings: list[Finding]
    risk: RiskAssessment
    detectors_run: list[str]
    detectors_skipped: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    citation_keys: list[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=utcnow)
    corpus_digest: str | None = None
    case_id: str | None = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.CRITICAL)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "generated_at": self.generated_at.isoformat(),
            "corpus_digest": self.corpus_digest,
            "summary": self.summary,
            "detectors_run": self.detectors_run,
            "detectors_skipped": self.detectors_skipped,
            "risk": self.risk.model_dump(mode="json"),
            "findings": [f.model_dump(mode="json") for f in self.findings],
        }


def build_context(
    transactions: Sequence,
    customers: Sequence = (),
    accounts: Sequence = (),
    *,
    config: DetectorConfig | None = None,
) -> AnalysisContext:
    return AnalysisContext(
        transactions=list(transactions),
        customers={c.customer_id: c for c in customers},
        accounts={a.account_id: a for a in accounts},
        config=config or DetectorConfig(),
    )


def analyze(
    ctx: AnalysisContext,
    *,
    kb: Any | None = None,
    detectors: Sequence[str] | None = None,
    weights: RiskWeights | None = None,
    jurisdiction: str | None = None,
    case_id: str | None = None,
    db: Database | None = None,
    as_of: Any | None = None,
) -> AnalysisResult:
    requested = list(detectors) if detectors else list(DETECTORS)
    unknown = [d for d in requested if d not in DETECTORS]
    if unknown:
        from anjali.core.errors import ConfigError

        raise ConfigError(
            f"Unknown detector(s): {', '.join(unknown)}",
            hint=f"Available: {', '.join(DETECTORS)}",
        )

    detections: list[Detection] = []
    skipped: list[str] = []
    for name in requested:
        fn = DETECTORS[name]
        try:
            produced = fn(ctx)
        except Exception as exc:  # a broken detector must not silently zero the case
            skipped.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        detections.extend(produced)

    # Deduplicate: identical finding ids (same typology + evidence) collapse to the
    # highest-severity instance.
    by_id: dict[str, Detection] = {}
    for det in detections:
        existing = by_id.get(det.finding.finding_id)
        if existing is None or SEVERITY_ORDER[det.finding.severity] < SEVERITY_ORDER[existing.finding.severity]:
            by_id[det.finding.finding_id] = det
    ordered = sorted(
        by_id.values(),
        key=lambda d: (SEVERITY_ORDER[d.finding.severity], -d.finding.confidence, d.finding.typology),
    )

    resolver = None
    if kb is not None:
        from anjali.kb.resolve import resolve as _resolve

        resolver = lambda keys: _resolve(kb, keys, as_of=as_of)  # noqa: E731

    findings: list[Finding] = []
    all_keys: list[str] = []
    for det in ordered:
        finding = det.finding
        all_keys.extend(det.citation_keys)
        if resolver:
            finding.regulatory_refs = resolver(det.citation_keys)
            if not finding.regulatory_refs:
                # A finding without a legal hook is a product defect, not a style issue.
                finding.explanation.append(
                    "WARNING: no regulatory citation could be resolved for this finding — "
                    "corpus may be out of date. Treat as uncited."
                )
        findings.append(finding)

    risk_result = assess(ctx, findings, weights=weights, jurisdiction=jurisdiction, resolve=resolver)
    all_keys.extend(risk_result.citation_keys)

    summary = volume_summary(ctx)
    summary.update(
        {
            "findings_total": len(findings),
            "by_severity": {
                sev.value: sum(1 for f in findings if f.severity is sev) for sev in Severity
            },
            "by_typology": _count(findings),
            "risk_score": risk_result.assessment.overall,
            "risk_band": risk_result.assessment.band.value,
        }
    )

    result = AnalysisResult(
        findings=findings,
        risk=risk_result.assessment,
        detectors_run=[d for d in requested if not any(s.startswith(d) for s in skipped)],
        detectors_skipped=skipped,
        summary=summary,
        citation_keys=list(dict.fromkeys(all_keys)),
        case_id=case_id,
        corpus_digest=kb.index_digest() if kb is not None else None,
    )

    if db is not None:
        persist_result(db, result)
    return result


def _count(findings: Sequence[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.typology] = out.get(f.typology, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: kv[1], reverse=True))


def persist_result(db: Database, result: AnalysisResult, *, case_id: str | None = None) -> int:
    case_id = case_id or result.case_id or f"case-{result.generated_at:%Y%m%d-%H%M%S}"
    result.case_id = case_id
    with db.tx() as conn:
        for finding in result.findings:
            conn.execute(
                """
                INSERT INTO findings(finding_id, case_id, severity, typology, created_at, payload)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(finding_id) DO UPDATE SET payload=excluded.payload,
                    severity=excluded.severity, case_id=excluded.case_id
                """,
                (
                    finding.finding_id,
                    case_id,
                    finding.severity.value,
                    finding.typology,
                    result.generated_at.isoformat(),
                    json.dumps(finding.model_dump(mode="json"), default=str),
                ),
            )
        payload = result.to_dict()
        conn.execute(
            """
            INSERT INTO cases(case_id, title, created_at, updated_at, status, payload)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(case_id) DO UPDATE SET updated_at=excluded.updated_at, payload=excluded.payload
            """,
            (
                case_id,
                f"Analysis {case_id}",
                result.generated_at.isoformat(),
                result.generated_at.isoformat(),
                "open",
                json.dumps(payload, default=str),
            ),
        )
    return len(result.findings)


def load_case(db: Database, case_id: str) -> dict[str, Any] | None:
    row = db.one("SELECT payload FROM cases WHERE case_id=?", (case_id,))
    return json.loads(row["payload"]) if row else None


def list_cases(db: Database, limit: int = 50) -> list[dict[str, Any]]:
    rows = db.query(
        "SELECT case_id, title, created_at, updated_at, status FROM cases "
        "ORDER BY updated_at DESC LIMIT ?",
        (limit,),
    )
    return [dict(r) for r in rows]


def detector_catalogue() -> list[dict[str, str]]:
    return [
        {"name": name, "description": DETECTOR_DESCRIPTIONS.get(name, ""), "requires": "transactions"}
        for name in DETECTORS
    ]


def stable_case_id(prefix: str = "CASE") -> str:
    return stable_id(utcnow().isoformat(), prefix=f"{prefix}-", length=8).upper()
