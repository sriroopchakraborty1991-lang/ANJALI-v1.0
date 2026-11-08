from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

import pytest

from anjali.audit.trail import AuditTrail, retention_report
from anjali.compliance import conflicts
from anjali.compliance.goaml import build_ctr, ctr_to_markdown, to_goaml
from anjali.compliance.sar import SARInput, build_report, quality_check, to_markdown
from anjali.core.models import Direction, Jurisdiction, Severity, Transaction


# --------------------------------------------------------------------------- #
# Cross-jurisdiction conflicts
# --------------------------------------------------------------------------- #
def test_conflict_library_is_populated():
    all_conflicts = conflicts.all_conflicts()
    assert len(all_conflicts) >= 10
    assert len({c.id for c in all_conflicts}) == len(all_conflicts)


def test_conflicts_can_be_looked_up_by_id_and_topic():
    assert conflicts.get("sar-group-disclosure") is not None
    assert conflicts.get("does-not-exist") is None
    assert conflicts.find("gdpr")
    assert conflicts.find(jurisdictions=["EU"])


def test_known_cross_border_questions_are_covered():
    ids = {c.id for c in conflicts.all_conflicts()}
    assert {
        "sar-group-disclosure",
        "ownership-50-percent-control",
        "retention-vs-gdpr",
        "automated-decisions",
    } <= ids


def test_conflicts_map_to_findings_by_typology():
    from anjali.analysis.patterns import Detection  # noqa: F401

    class FakeFinding:
        typology = "structuring"
        severity = Severity.CRITICAL

    matched = conflicts.relevant_to_findings([FakeFinding()])
    assert matched
    assert all(hasattr(c, "resolution") for c in matched)


def test_memo_names_every_position_and_resolution(kb):
    memo = conflicts.memo(conflicts.get("sar-group-disclosure"), kb)
    assert len(memo) > 1000
    for jurisdiction in ("US", "EU", "UK"):
        assert jurisdiction in memo
    assert "resolution" in memo.lower()


def test_matrix_rows_are_complete():
    rows = conflicts.matrix()
    assert len(rows) == len(conflicts.all_conflicts())
    for row in rows:
        assert row["id"] and row["severity"] and row["topic"] and row["jurisdictions"]


def test_coverage_by_topic_sums_to_the_library():
    coverage = conflicts.coverage_by_topic()
    assert sum(coverage.values()) == len(conflicts.all_conflicts())


# --------------------------------------------------------------------------- #
# SAR
# --------------------------------------------------------------------------- #
def _demo_sar_input(demo_context, demo_result) -> SARInput:
    return SARInput(
        case_id="demo-case",
        findings=demo_result.findings,
        transactions=demo_context.transactions,
        customers=list(demo_context.customers.values()),
        accounts=list(demo_context.accounts or []),
        risk=demo_result.risk,
        jurisdiction=Jurisdiction.US,
    )


@pytest.fixture(scope="module")
def sar_report(demo_context, demo_result, kb):
    from anjali.kb.resolve import resolve

    citations = resolve(kb, ["us-31cfr-1020-320", "us-fincen-sar-narrative", "us-31cfr-1010-306"])
    return build_report(_demo_sar_input(demo_context, demo_result), citations=citations)


def test_sar_identifies_the_right_subjects(sar_report):
    subject_dobs = {s.name: s.dob for s in sar_report.subjects}
    assert "Ravi Menon" in subject_dobs
    assert subject_dobs["Ravi Menon"] == "1990-11-04"
    # The structuring subject holds one account in the demo, not the whole bank.
    ravi = next(s for s in sar_report.subjects if s.name == "Ravi Menon")
    assert ravi.accounts == ["ACC-1001"]


def test_sar_totals_and_window_are_consistent(sar_report):
    assert sar_report.total_amount > 0
    assert sar_report.activity_start <= sar_report.activity_end
    assert sar_report.due_date >= sar_report.activity_end


def test_sar_narrative_covers_the_six_elements(sar_report):
    narrative = sar_report.narrative
    for name in ("Ravi Menon", "structuring"):
        assert name in narrative or name.lower() in narrative.lower()
    assert len(narrative) > 1200


def test_sar_quality_gate_scores_high(sar_report):
    quality = quality_check(sar_report)
    assert quality["total"] >= 8
    assert quality["score"] >= 80
    assert quality["grade"] in {"A", "B"}


def test_sar_markdown_is_regulator_ready(sar_report):
    text = to_markdown(sar_report)
    assert "SAR" in text
    assert "31 CFR" in text
    assert "Prepared by" in text
    assert sar_report.report_id in text


def test_sar_json_serialises(sar_report):
    payload = json.loads(json.dumps(sar_report.model_dump(mode="json"), default=str))
    assert payload["report_id"] == sar_report.report_id


def test_goaml_export_is_well_formed_xml(sar_report):
    xml = to_goaml(sar_report, [])
    root = ET.fromstring(xml)
    assert root.tag.endswith("report")
    assert len(list(root)) > 3


# --------------------------------------------------------------------------- #
# CTR
# --------------------------------------------------------------------------- #
def _cash_deposits(amounts: list[str], account: str = "ACC-1") -> list[Transaction]:
    start = datetime(2026, 1, 5, 10)
    return [
        Transaction(
            txn_id=f"C{index}",
            timestamp=start + timedelta(hours=index),
            amount=amount,
            currency="USD",
            direction=Direction.CREDIT,
            txn_type="cash_deposit",
            to_account=account,
            channel="teller",
        )
        for index, amount in enumerate(amounts)
    ]


def test_ctr_aggregates_cash_by_business_day():
    payload = build_ctr(_cash_deposits(["6000", "5000", "4000"]))
    assert payload["filings"], "aggregate cash over 10,000 must require a CTR"
    filing = payload["filings"][0]
    assert filing["cash_in"] == "15000.00"
    assert filing["due_date"] > filing["business_day"]
    assert filing["reportable"] is True


def test_ctr_ignores_non_cash_and_sub_threshold_activity():
    assert build_ctr(_cash_deposits(["4000", "3000"]))["filings"] == []
    wires = [
        Transaction(
            txn_id="W1",
            timestamp=datetime(2026, 1, 5, 10),
            amount="50000",
            currency="USD",
            txn_type="wire",
            from_account="ACC-9",
            to_account="ACC-8",
        )
    ]
    assert build_ctr(wires)["filings"] == []


def test_ctr_markdown_states_that_nothing_is_filed_automatically():
    payload = build_ctr(_cash_deposits(["14250"]))
    text = ctr_to_markdown(payload)
    assert "14250" in text.replace(",", "") or "14,250" in text
    assert "not" in text.lower()


# --------------------------------------------------------------------------- #
# Audit trail
# --------------------------------------------------------------------------- #
def test_audit_chain_verifies(tmp_path):
    trail = AuditTrail(tmp_path / "audit.jsonl", actor="tester")
    for index in range(3):
        trail.append("analysis.run", subject=f"case-{index}", details={"findings": index})
    result = trail.verify()
    assert result.valid is True
    assert result.records == 3
    assert len(result.head_hash) == 64


def test_tampering_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    trail = AuditTrail(path, actor="tester")
    trail.append("analysis.run", subject="case-1", details={"findings": 1})
    trail.append("sar.draft", subject="SAR-1", details={"score": 90})
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["details"]["findings"] = 999
    lines[0] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = trail.verify()
    assert result.valid is False
    assert result.first_break == 1


def test_chain_detects_a_deleted_record(tmp_path):
    path = tmp_path / "audit.jsonl"
    trail = AuditTrail(path, actor="tester")
    for index in range(3):
        trail.append("analysis.run", subject=f"case-{index}", details={})
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    assert trail.verify().valid is False


def test_audit_stats_and_export(tmp_path):
    trail = AuditTrail(tmp_path / "audit.jsonl", actor="tester")
    trail.append("analysis.run", subject="case-1", details={})
    trail.append("sar.draft", subject="SAR-1", details={})
    stats = trail.stats()
    assert stats["records"] == 2
    assert stats["actions"]["analysis.run"] >= 1
    exported = trail.export_markdown(tmp_path / "audit.md")
    assert exported.exists() and "audit" in exported.read_text(encoding="utf-8").lower()


def test_retention_report_flags_records_past_the_clock():
    old = (datetime.utcnow() - timedelta(days=365 * 6)).isoformat()
    recent = datetime.utcnow().isoformat()
    records = [
        {"seq": 1, "timestamp": old, "action": "analysis.run"},
        {"seq": 2, "timestamp": recent, "action": "analysis.run"},
    ]
    report = retention_report(None, records, years=5)
    assert report["policy_years"] == 5
    assert report["records_past_retention"] == 1
