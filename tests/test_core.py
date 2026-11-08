from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest
from pydantic import ValidationError

from anjali.core import util
from anjali.core.models import (
    Customer,
    Finding,
    RiskBand,
    Severity,
    Transaction,
)


def test_normalise_name_strips_accents_and_suffixes():
    assert util.normalise_name("  José  Núñez-López  ") == "jose nunez lopez"
    assert "llc" not in util.normalise_name("Acme Global Trading LLC")


def test_money_and_percent_helpers():
    assert util.money(Decimal("1234.567")) == Decimal("1234.57")
    assert util.fmt_money(Decimal("1234.5"), "USD") == "USD 1,234.50"
    assert util.clamp(1.5) == 1.0
    assert util.safe_div(1, 0, default=9) == 9


def test_business_days_skip_weekends():
    start = date(2026, 1, 1)  # Thursday
    assert util.add_business_days(start, 1) == date(2026, 1, 2)  # Friday
    assert util.add_business_days(start, 2) == date(2026, 1, 5)  # Monday
    assert util.business_days_between(date(2026, 1, 1), date(2026, 1, 8)) == 6


def test_sha256_hex_is_stable_and_order_sensitive():
    assert util.sha256_hex("a|b") == util.sha256_hex("a|b")
    assert util.sha256_hex("a|b") != util.sha256_hex("b|a")
    assert len(util.sha256_hex("a|b")) == 64


def test_stable_id_is_deterministic_and_prefixed():
    one = util.stable_id("case", "typology", prefix="F-", length=8)
    assert one == util.stable_id("case", "typology", prefix="F-", length=8)
    assert one.startswith("F-") and len(one) == 10


def test_atomic_write_leaves_no_partial_file(tmp_path):
    target = tmp_path / "nested" / "out.txt"
    util.atomic_write(target, "hello")
    assert target.read_text() == "hello"
    assert list(target.parent.iterdir()) == [target]


def test_median_accepts_decimals():
    assert util.median([Decimal("1"), Decimal("2"), Decimal("6")]) == 2.0


def test_severity_rank_orders_critically():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank


def test_risk_band_thresholds():
    assert RiskBand.from_score(80) is RiskBand.CRITICAL
    assert RiskBand.from_score(60) is RiskBand.HIGH
    assert RiskBand.from_score(35) is RiskBand.MEDIUM
    assert RiskBand.from_score(0) is RiskBand.LOW


def test_transaction_coerces_amount_currency_and_timestamp():
    txn = Transaction(
        txn_id="T1",
        timestamp="2026-01-01T10:00:00Z",
        amount="100.10",
        currency="usd",
        from_account="A",
        to_account="B",
    )
    assert txn.amount == Decimal("100.10")
    assert txn.currency == "USD"
    assert txn.timestamp.tzinfo is not None


def test_customer_coerces_string_lists_and_dates():
    customer = Customer(customer_id="C1", name="Test Ltd", accounts="ACC-1;ACC-2",
                        onboarded_at="2024-03-01", expected_monthly_volume="5000")
    assert customer.accounts == ["ACC-1", "ACC-2"]
    assert customer.onboarded_at == date(2024, 3, 1)
    assert float(customer.expected_monthly_volume) == 5000.0


def test_finding_rejects_out_of_range_confidence():
    with pytest.raises(ValidationError):
        Finding(
            finding_id="F1",
            typology="structuring",
            severity=Severity.HIGH,
            title="t",
            summary="s",
            confidence=1.4,
            evidence_txn_ids=["T1"],
        )


def test_finding_explanation_and_references_are_lists():
    finding = Finding(
        finding_id="F1",
        typology="structuring",
        severity=Severity.HIGH,
        title="t",
        summary="s",
        confidence=0.8,
        evidence_txn_ids=["T1"],
    )
    assert finding.explanation == []
    assert finding.regulatory_refs == []


def test_utcnow_is_timezone_aware():
    assert util.utcnow().tzinfo is not None
