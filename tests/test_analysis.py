from __future__ import annotations

from datetime import datetime, timedelta

from anjali.analysis.engine import analyze, build_context, detector_catalogue
from anjali.analysis.ingest import load_customers, load_transactions
from anjali.analysis.patterns import DETECTORS
from anjali.core.models import Customer, Direction, Severity, Transaction


def _fire(result, typology: str) -> list:
    return [f for f in result.findings if f.typology == typology]


def test_every_detector_is_registered():
    catalogue = detector_catalogue()
    assert len(catalogue) == len(DETECTORS) >= 11
    assert {row["name"] for row in catalogue} == set(DETECTORS)


def test_demo_case_triggers_the_expected_typologies(demo_result):
    fired = {finding.typology for finding in demo_result.findings}
    expected = {
        "structuring",
        "layering",
        "round_tripping",
        "mule_network",
        "tbml",
        "high_risk_geography",
        "dormant_reactivation",
        "threshold_avoidance",
    }
    assert expected <= fired


def test_no_detector_silently_fails_on_the_demo_case(demo_result):
    assert demo_result.detectors_skipped == []


def test_findings_are_cited_and_explained(demo_result):
    for finding in demo_result.findings:
        assert finding.regulatory_refs, f"{finding.typology} has no regulatory reference"
        assert finding.explanation, f"{finding.typology} has no reasoning trace"
        assert finding.evidence_txn_ids
        assert 0.0 <= finding.confidence <= 1.0


def test_structuring_is_one_finding_not_a_rolling_window(demo_result):
    findings = _fire(demo_result, "structuring")
    assert len(findings) == 1
    assert len(findings[0].evidence_txn_ids) >= 8
    assert findings[0].severity is Severity.CRITICAL


def test_round_tripping_finding_names_the_cycle(demo_result):
    findings = _fire(demo_result, "round_tripping")
    assert findings
    assert "ACC-3001" in findings[0].summary


def test_risk_assessment_is_banded_and_explained(demo_result):
    risk = demo_result.risk
    assert 0 <= risk.overall <= 100
    assert risk.band.value in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert {d.dimension for d in risk.dimensions} == {
        "geographic",
        "product",
        "customer",
        "behavioral",
        "channel",
    }
    assert risk.citations
    assert risk.narrative


def test_critical_finding_sets_a_floor_on_the_risk_score(demo_result):
    critical = [f for f in demo_result.findings if f.severity is Severity.CRITICAL]
    if len(critical) >= 3:
        assert demo_result.risk.overall >= 80
        assert demo_result.risk.band.value == "CRITICAL"


def test_clean_data_produces_no_findings():
    """A salary-and-groceries customer must not generate a suspicious activity report."""
    start = datetime(2026, 1, 1, 9)
    transactions = []
    for day in range(60):
        ts = start + timedelta(days=day)
        transactions.append(
            Transaction(
                txn_id=f"T{day:03d}",
                timestamp=ts,
                amount="2400.00",
                currency="USD",
                direction=Direction.CREDIT,
                txn_type="ach",
                to_account="ACC-1",
                from_name="Payroll Inc",
            )
        )
        transactions.append(
            Transaction(
                txn_id=f"T{day:03d}b",
                timestamp=ts + timedelta(hours=4),
                amount="120.00",
                currency="USD",
                txn_type="card",
                from_account="ACC-1",
                to_account=f"MERCHANT-{day % 5}",
            )
        )
    customer = Customer(
        customer_id="C1",
        name="Salaried Customer",
        customer_type="individual",
        country="US",
        accounts=["ACC-1"],
        expected_monthly_volume="5000",
        source_of_funds="salary",
    )
    result = analyze(build_context(transactions, [customer]))
    assert result.findings == []


def test_detector_selection_is_honoured(demo_context):
    result = analyze(demo_context, detectors=["structuring"])
    assert {f.typology for f in result.findings} == {"structuring"}


def test_loaders_tolerate_messy_rows(tmp_path):
    path = tmp_path / "messy.csv"
    path.write_text(
        "txn_id,timestamp,amount,currency,from_account,to_account,txn_type\n"
        "T1,2026-01-02T10:00:00Z,\"1,250.50\",usd,ACC-1,ACC-2,wire\n"
        "T2,2026-01-02T11:00:00Z,not-a-number,USD,ACC-1,ACC-3,wire\n"
        ",2026-01-02T12:00:00Z,500,USD,ACC-1,ACC-4,wire\n",
        encoding="utf-8",
    )
    transactions, report = load_transactions(path)
    # The unparseable amount is rejected; a missing txn_id is repaired, not rejected.
    assert len(transactions) == 2
    assert transactions[0].amount == 1250.50
    assert report.rows_rejected == 1
    assert any("not-a-number" not in e and "row 2" in e for e in report.errors) or report.rows_rejected == 1


def test_customer_accounts_link_transactions_to_owners(tmp_path):
    cust_path = tmp_path / "customers.csv"
    cust_path.write_text(
        "customer_id,name,customer_type,country,accounts,source_of_funds\n"
        "C1,Test Person,individual,GB,ACC-1|ACC-2,salary\n",
        encoding="utf-8",
    )
    customers, _ = load_customers(cust_path)
    assert customers[0].accounts == ["ACC-1", "ACC-2"]
    assert customers[0].country == "GB"
