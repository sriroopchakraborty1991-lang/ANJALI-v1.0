"""Adversarial red-team harness.

Every other AML tool asks "did the alert fire?". This asks the harder question: **if an
adversary deliberately attacked this monitoring configuration, what would get through?**

The harness generates synthetic cases with a known ground truth — a structuring pattern
here, a mule cluster there, a benign salary stream as a distractor — runs the *production*
detectors over them, and reports recall per typology plus the false positives the benign
traffic produced. Misses are the interesting output: they are the control gaps an examiner
would find, surfaced before the examiner does.

Determinism matters, so every case is seeded and reproducible.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from anjali.analysis.engine import analyze, build_context
from anjali.analysis.patterns import DetectorConfig
from anjali.core.models import Account, Customer, Finding, Transaction
from anjali.core.util import money, utcnow

D = Decimal
BASE_DATE = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)


@dataclass
class GroundTruth:
    scenario: str
    typology: str
    txn_ids: list[str]
    description: str
    difficulty: str = "medium"


@dataclass
class SimCase:
    name: str
    seed: int
    transactions: list[Transaction]
    customers: list[Customer]
    accounts: list[Account]
    ground_truth: list[GroundTruth]
    notes: list[str] = field(default_factory=list)


@dataclass
class SimResult:
    cases: list[dict[str, Any]]
    per_typology: dict[str, dict[str, Any]]
    overall: dict[str, Any]
    seed: int
    generated_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "generated_at": self.generated_at.isoformat(),
            "overall": self.overall,
            "per_typology": self.per_typology,
            "cases": self.cases,
        }


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #
class _Builder:
    def __init__(self, rng: random.Random, case: str) -> None:
        self.rng = rng
        self.case = case
        self.txns: list[Transaction] = []
        self.customers: list[Customer] = []
        self.accounts: list[Account] = []
        self.truth: list[GroundTruth] = []
        self._n = 0

    def txn(
        self,
        *,
        amount: float | Decimal,
        ts: datetime,
        from_account: str | None = None,
        to_account: str | None = None,
        txn_type: str = "wire",
        direction: str = "debit",
        channel: str = "online",
        country_from: str = "US",
        country_to: str = "US",
        branch: str | None = None,
        device_id: str | None = None,
        ip_address: str | None = None,
        from_name: str | None = None,
        to_name: str | None = None,
        description: str | None = None,
        **extra: Any,
    ) -> Transaction:
        self._n += 1
        txn = Transaction(
            txn_id=f"{self.case}-T{self._n:04d}",
            timestamp=ts,
            amount=money(amount),
            direction=direction,  # type: ignore[arg-type]
            txn_type=txn_type,
            from_account=from_account,
            to_account=to_account,
            from_name=from_name,
            to_name=to_name,
            channel=channel,
            country_from=country_from,
            country_to=country_to,
            branch=branch,
            device_id=device_id,
            ip_address=ip_address,
            description=description,
            **extra,
        )
        self.txns.append(txn)
        return txn

    def customer(self, name: str, *, accounts: list[str], **kw: Any) -> Customer:
        cid = f"{self.case}-C{len(self.customers) + 1:02d}"
        customer = Customer(customer_id=cid, name=name, accounts=accounts, **kw)
        self.customers.append(customer)
        for acct in accounts:
            self.accounts.append(
                Account(account_id=acct, customer_id=cid, account_type=kw.get("account_type", "checking"))
            )
        return customer

    def label(self, scenario: str, typology: str, txns: Sequence[Transaction], description: str, difficulty: str = "medium") -> None:
        self.truth.append(
            GroundTruth(
                scenario=scenario,
                typology=typology,
                txn_ids=[t.txn_id for t in txns],
                description=description,
                difficulty=difficulty,
            )
        )


def _benign(b: _Builder) -> None:
    """Normal retail traffic. Any finding raised here is a false positive."""
    names = [("Priya Sharma", "ACC-B01"), ("Daniel Okafor", "ACC-B02"), ("Elena Rossi", "ACC-B03")]
    for name, acct in names:
        b.customer(name, accounts=[acct], country="US", customer_type="individual")
    for day in range(28):
        ts = BASE_DATE + timedelta(days=day)
        b.txn(
            amount=b.rng.uniform(2000, 2600), ts=ts, to_account="ACC-B01", txn_type="ach",
            direction="credit", from_name="Northwind Payroll Inc", description="salary",
        )
        b.txn(
            amount=b.rng.uniform(40, 220), ts=ts + timedelta(hours=3), from_account="ACC-B01",
            to_account="MERCHANT-01", txn_type="card", description="groceries",
        )
        if day % 7 == 0:
            b.txn(
                amount=1450.0, ts=ts + timedelta(hours=6), from_account="ACC-B02",
                to_account="LANDLORD-LLC", txn_type="ach", description="rent",
            )
        b.txn(
            amount=b.rng.uniform(15, 90), ts=ts + timedelta(hours=8), from_account="ACC-B03",
            to_account="MERCHANT-02", txn_type="card", description="coffee",
        )

    # --- adversarial negatives -------------------------------------------------
    # Each block looks like a typology but is legitimate on the facts. Staying quiet on
    # these is the other half of a control test: a detector that fires on a café taking
    # cash is not "conservative", it is wrong.

    # 1. A café that declares cash sales and trades in line with its expected turnover.
    b.customer(
        "Bean & Barrel Café", accounts=["ACC-B10"], country="US", customer_type="business",
        industry="restaurant", source_of_funds="cash sales", expected_monthly_volume=60000,
    )
    for day in range(0, 28, 1):
        b.txn(amount=b.rng.uniform(1200, 2400), ts=BASE_DATE + timedelta(days=day, hours=18),
              to_account="ACC-B10", txn_type="cash_deposit", direction="credit", channel="teller",
              branch="BR-04", description="Daily takings")

    # 2. A landlord collecting rent from six tenants: fan-in, but the money is retained.
    b.customer("Harborview Lettings", accounts=["ACC-B11"], country="US",
               customer_type="business", industry="real estate", source_of_funds="rental income",
               expected_monthly_volume=12000)
    made_rent = []
    for tenant in range(6):
        made_rent.append(
            b.txn(amount=1450.0, ts=BASE_DATE + timedelta(days=tenant, hours=10),
                  from_account=f"ACC-TEN{tenant}", to_account="ACC-B11", txn_type="ach",
                  direction="credit", channel="ach", description="Monthly rent")
        )
    b.txn(amount=3200.0, ts=BASE_DATE + timedelta(days=20), from_account="ACC-B11",
          to_account="PROPERTY-MGMT", txn_type="ach", description="Maintenance and fees")

    # 3. An importer invoicing at market parity (±6%) — trade finance that reconciles.
    b.customer("Norwood Components Inc", accounts=["ACC-B12"], country="US",
               customer_type="business", industry="industrial equipment")
    for i in range(3):
        b.txn(amount=48000.0, ts=BASE_DATE + timedelta(days=5 + i * 6), from_account="ACC-B12",
              to_account=f"ACC-SUP{i}", txn_type="letter_of_credit", direction="debit",
              channel="branch", country_to="DE", description="Supplier invoice",
              goods_description="Hydraulic valves", hs_code="8481.20", quantity="400",
              unit_price=str(round(100 * (1 + (i - 1) * 0.06), 2)), benchmark_price="100.00",
              route="DEHAM-USNYC", vessel="MV Rhine Trader")

    # 4. Two family members sharing a phone (below the mule-cluster minimum of three).
    for i in range(12):
        b.txn(amount=b.rng.uniform(60, 180), ts=BASE_DATE + timedelta(days=i, hours=12),
              from_account=f"ACC-B1{3 + i % 2}", to_account="MERCHANT-02", txn_type="card",
              device_id="DEV-FAMILY-1", ip_address="192.0.2.44", description="Household spend")


# -- individual scenario generators ---------------------------------------- #
def _structuring(b: _Builder) -> None:
    acct = "ACC-S01"
    b.customer("Marcus Reed", accounts=[acct], country="US", customer_type="individual",
               expected_monthly_volume=D("12000"), industry="consulting")
    made = []
    for i in range(7):
        made.append(
            b.txn(
                amount=b.rng.uniform(8200, 9800),
                ts=BASE_DATE + timedelta(days=i * 2, hours=10 + i),
                to_account=acct, txn_type="cash_deposit", direction="credit",
                channel="teller", branch=f"BR-{7 if i % 2 else 12:02d}",
                description="cash deposit",
            )
        )
    b.label("structuring-classic", "structuring", made,
            "Seven cash deposits of 8.2k–9.8k over 14 days across two branches.", "easy")


def _smurfing(b: _Builder) -> None:
    target = "ACC-SM01"
    b.customer("Bright Horizon LLC", accounts=[target], country="US", customer_type="business",
               industry="money services business")
    made = []
    for i in range(9):
        sender = f"ACC-SRC{i:02d}"
        made.append(
            b.txn(
                amount=b.rng.uniform(2400, 3900),
                ts=BASE_DATE + timedelta(days=i % 4, hours=9 + i),
                from_account=sender, to_account=target, txn_type="p2p", direction="credit",
                channel="mobile", device_id=f"DEV-M{i % 3}",
                from_name=f"Sender {i}",
            )
        )
    # A real mule account is a conduit: the collected funds are swept out within days.
    for i in range(4):
        b.txn(
            amount=b.rng.uniform(6000, 8000),
            ts=BASE_DATE + timedelta(days=2 + i, hours=16),
            from_account=target, to_account=f"ACC-SINK{i:02d}", txn_type="wire",
            direction="debit", channel="online", country_to="AE",
            to_name=f"Beneficiary {i}",
        )
    b.label("smurfing-fan-in", "smurfing", made,
            "Nine unrelated senders fund one account in four days, all below threshold, "
            "and the balance is swept offshore within days.", "medium")


def _layering(b: _Builder) -> None:
    a, c, d = "ACC-L01", "ACC-L02", "ACC-L03"
    b.customer("Omar Haddad", accounts=[a], country="US")
    b.customer("Vertex Consulting Ltd", accounts=[c], country="AE", customer_type="business")
    made = []
    for i in range(3):
        t0 = BASE_DATE + timedelta(days=i * 5, hours=9)
        made.append(b.txn(amount=80000, ts=t0, from_account="ACC-EXT01", to_account=a,
                          txn_type="wire", direction="credit", country_to="US", country_from="AE"))
        made.append(b.txn(amount=78500, ts=t0 + timedelta(hours=3), from_account=a, to_account=c,
                          txn_type="wire", channel="online", country_from="US", country_to="AE"))
        made.append(b.txn(amount=77000, ts=t0 + timedelta(hours=5), from_account=c, to_account=d,
                          txn_type="wire", country_from="AE", country_to="TR"))
    b.label("layering-passthrough", "layering", made,
            "Three 80k inflows re-sent within five hours at 97% of value through an AE entity.", "medium")


def _round_trip(b: _Builder) -> None:
    a, c, d = "ACC-R01", "ACC-R02", "ACC-R03"
    b.customer("Cascade Trading Inc", accounts=[a], country="US", customer_type="business")
    b.accounts.append(Account(account_id=c, customer_id="X1", account_type="business"))
    b.accounts.append(Account(account_id=d, customer_id="X2", account_type="business"))
    made = []
    t0 = BASE_DATE + timedelta(days=3, hours=10)
    made.append(b.txn(amount=250000, ts=t0, from_account=a, to_account=c, txn_type="wire", country_to="AE"))
    made.append(b.txn(amount=248000, ts=t0 + timedelta(days=2), from_account=c, to_account=d, txn_type="wire"))
    made.append(b.txn(amount=245000, ts=t0 + timedelta(days=5), from_account=d, to_account=a,
                      txn_type="wire", direction="credit", country_to="US"))
    b.label("round-tripping", "round_tripping", made,
            "250k leaves, returns to origin as 245k within five days through two intermediaries.", "hard")


def _mule_network(b: _Builder) -> None:
    accounts = [f"ACC-M{i:02d}" for i in range(1, 6)]
    for i, acct in enumerate(accounts):
        b.customer(f"Mule Holder {i}", accounts=[acct], country="US")
    made = []
    for i in range(14):
        acct = accounts[i % len(accounts)]
        made.append(
            b.txn(
                amount=b.rng.uniform(400, 1800), ts=BASE_DATE + timedelta(days=i // 3, hours=9 + i % 8),
                from_account=f"ACC-VICTIM{i:02d}", to_account=acct, txn_type="p2p",
                direction="credit", channel="mobile", device_id="DEV-SHARED-9",
                ip_address="203.0.113.44", from_name=f"Victim {i}",
            )
        )
    b.label("mule-cluster", "mule_network", made,
            "Five accounts on one device/IP receive small payments from fourteen senders.", "medium")


def _tbml(b: _Builder) -> None:
    b.customer("Golden Gate Imports LLC", accounts=["ACC-T01"], country="US", customer_type="business",
               industry="imports")
    made = []
    for i in range(2):
        made.append(
            b.txn(
                amount=180000, ts=BASE_DATE + timedelta(days=6 + i * 9),
                from_account="ACC-T01", to_account="ACC-T02", txn_type="letter_of_credit",
                channel="branch", goods_description="Industrial ball bearings", hs_code="8482.10",
                quantity=D("1000"), unit_price=D("180.00"), benchmark_price=D("72.00"),
                vessel="MV Nordstar", route="CNSHA-AEJEA",
            )
        )
    b.label("tbml-overinvoicing", "tbml", made,
            "Ball bearings invoiced at 180/unit against a 72/unit benchmark (+150%).", "medium")


def _velocity(b: _Builder) -> None:
    acct = "ACC-V01"
    b.customer("Sofia Almeida", accounts=[acct], country="US")
    made = []
    for day in range(20):
        b.txn(amount=b.rng.uniform(50, 300), ts=BASE_DATE + timedelta(days=day, hours=12),
              from_account=acct, to_account="MERCHANT-01", txn_type="card")
    burst_day = BASE_DATE + timedelta(days=22)
    for i in range(16):
        made.append(
            b.txn(amount=b.rng.uniform(400, 1900), ts=burst_day + timedelta(minutes=i * 7),
                  from_account=acct, to_account=f"ACC-NEW{i:02d}", txn_type="p2p",
                  channel="mobile", device_id="DEV-NEW-1")
        )
    b.label("velocity-burst", "velocity_anomaly", made,
            "Established account jumps from ~1 to 16 payments per day on a new device.", "easy")


def _dormant(b: _Builder) -> None:
    acct = "ACC-D01"
    b.customer("Henrik Lund", accounts=[acct], country="US")
    made = []
    for i in range(4):
        b.txn(amount=b.rng.uniform(100, 400), ts=BASE_DATE + timedelta(days=i * 3),
              from_account=acct, to_account="MERCHANT-01", txn_type="card")
    reactivation = BASE_DATE + timedelta(days=250)
    for i in range(3):
        made.append(
            b.txn(amount=45000 + i * 5000, ts=reactivation + timedelta(days=i),
                  from_account=acct, to_account="ACC-OFFSHORE", txn_type="wire",
                  country_to="PA", channel="online")
        )
    b.label("dormant-reactivation", "dormant_reactivation", made,
            "Account idle for 250 days resumes with three 45k+ wires offshore.", "easy")


def _high_risk_geo(b: _Builder) -> None:
    b.customer("Delta Freight SA", accounts=["ACC-H01"], country="US", customer_type="business",
               industry="logistics")
    made = []
    for i in range(4):
        made.append(
            b.txn(amount=b.rng.uniform(20000, 60000), ts=BASE_DATE + timedelta(days=i * 4),
                  from_account="ACC-H01", to_account=f"ACC-IR{i:02d}", txn_type="wire",
                  country_from="US", country_to="IR", channel="branch")
        )
    b.label("high-risk-geography", "high_risk_geography", made,
            "Four wires totalling ~150k to IR counterparties.", "easy")


def _threshold_avoidance(b: _Builder) -> None:
    b.customer("Pavel Novak", accounts=["ACC-W01"], country="US")
    made = []
    for i in range(6):
        made.append(
            b.txn(amount=b.rng.uniform(2600, 2950), ts=BASE_DATE + timedelta(days=i * 2, hours=11),
                  from_account="ACC-W01", to_account=f"ACC-BEN{i:02d}", txn_type="wire",
                  channel="online", country_to="DE")
        )
    b.label("wire-threshold", "threshold_avoidance", made,
            "Six wires of 2.6k–2.95k just under the 3,000 travel-rule threshold.", "hard")


def _cash_intensity(b: _Builder) -> None:
    for i in range(3):
        b.customer(f"Peer {i}", accounts=[f"ACC-P{i}"], country="US", customer_type="individual")
        for d in range(10):
            # Peers also bank cash — just far less of it. Without a non-zero peer baseline
            # "100% cash" is not an anomaly, it is the only data point.
            cash = d >= 8
            b.txn(
                amount=500,
                ts=BASE_DATE + timedelta(days=d),
                from_account=f"ACC-P{i}",
                to_account="MERCHANT-03" if cash else "MERCHANT-01",
                txn_type="cash_withdrawal" if cash else "card",
                channel="branch" if cash else "card",
            )
    b.customer("Vikram Cash Business", accounts=["ACC-CI1"], country="US",
               customer_type="individual", industry="consulting")
    made = []
    for d in range(10):
        made.append(
            b.txn(amount=b.rng.uniform(3000, 4500), ts=BASE_DATE + timedelta(days=d, hours=15),
                  from_account="ACC-CI1", to_account="MERCHANT-03", txn_type="cash_withdrawal",
                  direction="debit", channel="branch", branch="BR-01")
        )
    b.label("cash-intensity", "cash_intensity", made,
            "Customer settles ~95% of value in cash against a near-zero peer median.", "hard")


SCENARIOS: dict[str, tuple[str, Callable[[_Builder], None]]] = {
    "structuring-classic": ("structuring", _structuring),
    "smurfing-fan-in": ("smurfing", _smurfing),
    "layering-passthrough": ("layering", _layering),
    "round-tripping": ("round_tripping", _round_trip),
    "mule-cluster": ("mule_network", _mule_network),
    "tbml-overinvoicing": ("tbml", _tbml),
    "velocity-burst": ("velocity_anomaly", _velocity),
    "dormant-reactivation": ("dormant_reactivation", _dormant),
    "high-risk-geography": ("high_risk_geography", _high_risk_geo),
    "wire-threshold": ("threshold_avoidance", _threshold_avoidance),
    "cash-intensity": ("cash_intensity", _cash_intensity),
}


def build_case(scenario: str, *, seed: int = 7, include_benign: bool = True) -> SimCase:
    if scenario not in SCENARIOS:
        raise KeyError(f"Unknown scenario '{scenario}'. Options: {', '.join(SCENARIOS)}")
    rng = random.Random(seed)
    b = _Builder(rng, case=f"SIM{seed}")
    if include_benign:
        _benign(b)
    SCENARIOS[scenario][1](b)
    return SimCase(
        name=scenario,
        seed=seed,
        transactions=b.txns,
        customers=b.customers,
        accounts=b.accounts,
        ground_truth=b.truth,
    )


def evaluate_case(
    case: SimCase,
    *,
    kb: Any = None,
    config: DetectorConfig | None = None,
    detectors: Sequence[str] | None = None,
) -> dict[str, Any]:
    ctx = build_context(case.transactions, case.customers, case.accounts, config=config)
    result = analyze(ctx, kb=kb, detectors=detectors)
    findings = result.findings

    matched_finding_ids: set[str] = set()
    rows: list[dict[str, Any]] = []
    for truth in case.ground_truth:
        evidence = set(truth.txn_ids)
        best: Finding | None = None
        overlap = 0
        for finding in findings:
            common = len(evidence & set(finding.evidence_txn_ids))
            typology_match = finding.typology == truth.typology
            if common > overlap or (common == overlap and typology_match and best is None):
                overlap = common
                best = finding
        correct = bool(best and best.typology == truth.typology and overlap > 0)
        if best and correct:
            matched_finding_ids.add(best.finding_id)
        rows.append(
            {
                "scenario": truth.scenario,
                "typology": truth.typology,
                "difficulty": truth.difficulty,
                "detected": correct,
                "matched_typology": best.typology if best else None,
                "overlap_txns": overlap,
                "confidence": best.confidence if best else None,
                "severity": best.severity.value if best else None,
                "finding_id": best.finding_id if best else None,
                "description": truth.description,
            }
        )

    # A finding that touches the injected money is not a false positive, even if it is not
    # the typology we injected — a mule ring legitimately produces both a fan-in finding
    # and a layering finding. A true false positive hits nothing but benign activity.
    injected_evidence: set[str] = set()
    for truth in case.ground_truth:
        injected_evidence |= set(truth.txn_ids)
    false_positives = [
        f for f in findings
        if f.finding_id not in matched_finding_ids
        and not (set(f.evidence_txn_ids) & injected_evidence)
    ]
    return {
        "case": case.name,
        "seed": case.seed,
        "injected": len(case.ground_truth),
        "detected": sum(1 for r in rows if r["detected"]),
        "transactions": len(case.transactions),
        "findings_total": len(findings),
        "risk_score": result.risk.overall,
        "risk_band": result.risk.band.value,
        "rows": rows,
        "false_positives": [
            {
                "typology": f.typology,
                "severity": f.severity.value,
                "summary": f.summary[:180],
                "evidence": f.evidence_txn_ids[:4],
            }
            for f in false_positives
        ],
        "detectors_skipped": result.detectors_skipped,
    }


def run(
    *,
    seed: int = 7,
    scenarios: Sequence[str] | None = None,
    kb: Any = None,
    config: DetectorConfig | None = None,
    detectors: Sequence[str] | None = None,
) -> SimResult:
    chosen = list(scenarios or SCENARIOS)
    cases = [evaluate_case(build_case(name, seed=seed), kb=kb, config=config, detectors=detectors) for name in chosen]

    per_typology: dict[str, dict[str, Any]] = {}
    for case in cases:
        for row in case["rows"]:
            bucket = per_typology.setdefault(
                row["typology"], {"injected": 0, "detected": 0, "difficulties": [], "scenarios": []}
            )
            bucket["injected"] += 1
            bucket["detected"] += 1 if row["detected"] else 0
            bucket["difficulties"].append(row["difficulty"])
            bucket["scenarios"].append(
                {"scenario": row["scenario"], "detected": row["detected"], "confidence": row["confidence"]}
            )
    for bucket in per_typology.values():
        bucket["recall"] = round(bucket["detected"] / bucket["injected"], 3) if bucket["injected"] else 0.0

    total_injected = sum(c["injected"] for c in cases)
    total_detected = sum(c["detected"] for c in cases)
    total_fp = sum(len(c["false_positives"]) for c in cases)
    recall = round(total_detected / total_injected, 3) if total_injected else 0.0
    precision = round(total_detected / (total_detected + total_fp), 3) if (total_detected + total_fp) else 0.0

    gaps = [row for case in cases for row in case["rows"] if not row["detected"]]
    overall = {
        "scenarios": len(cases),
        "injected": total_injected,
        "detected": total_detected,
        "recall": recall,
        "precision_estimate": precision,
        "false_positives": total_fp,
        "missed": gaps,
        "verdict": _verdict(recall, precision),
    }
    return SimResult(cases=cases, per_typology=per_typology, overall=overall, seed=seed)


def _verdict(recall: float, precision: float) -> str:
    if recall >= 0.9 and precision >= 0.7:
        return "Controls are effective against the injected scenarios; review the misses for edge cases."
    if recall >= 0.7:
        return "Material detection gaps: at least one typology is not reliably detected. Tune thresholds."
    if recall >= 0.4:
        return "Significant control gap: a determined adversary would evade monitoring. Escalate to the MLRO."
    return "Critical: the monitoring configuration does not reliably detect the tested typologies."


def to_markdown(result: SimResult) -> str:
    overall = result.overall
    lines = ["# Adversarial control test report", ""]
    lines.append(f"**Seed:** {result.seed} (reproducible)  ")
    lines.append(f"**Scenarios run:** {overall['scenarios']}  ")
    lines.append(f"**Recall:** {overall['recall']:.0%} ({overall['detected']}/{overall['injected']})  ")
    lines.append(f"**Precision estimate:** {overall['precision_estimate']:.0%}  ")
    lines.append(f"**Verdict:** {overall['verdict']}")
    lines.append("")
    lines.append("## Recall by typology")
    lines.append("")
    lines.append("| Typology | Injected | Detected | Recall |")
    lines.append("|----------|----------|----------|--------|")
    for typology, bucket in sorted(result.per_typology.items(), key=lambda kv: kv[1]["recall"]):
        bar = "█" * int(bucket["recall"] * 10) + "░" * (10 - int(bucket["recall"] * 10))
        lines.append(
            f"| {typology} | {bucket['injected']} | {bucket['detected']} | "
            f"{bucket['recall']:.0%} {bar} |"
        )
    lines.append("")
    missed = overall["missed"]
    if missed:
        lines.append("## Control gaps (missed scenarios)")
        lines.append("")
        for row in missed:
            lines.append(f"### {row['scenario']} — {row['typology']} ({row['difficulty']})")
            lines.append("")
            lines.append(f"{row['description']}")
            lines.append("")
            if row["matched_typology"]:
                lines.append(
                    f"Routed to the wrong detector: the closest finding was `{row['matched_typology']}`."
                )
            else:
                lines.append("No detector produced a finding with overlapping evidence.")
            lines.append("")
        lines.append(
            "**Remediation:** each gap above maps to a monitoring scenario that needs a "
            "threshold change, an added data field, or a new detector. Re-run with the same "
            "seed after tuning to confirm the fix."
        )
        lines.append("")
    if overall["false_positives"]:
        lines.append("## False positives on benign traffic")
        lines.append("")
        for fp in [fp for case in result.cases for fp in case["false_positives"]][:10]:
            lines.append(f"- **{fp['typology']}** ({fp['severity']}): {fp['summary']}")
        lines.append("")
    lines.append("## Case detail")
    lines.append("")
    lines.append("| Scenario | Typology | Detected | Confidence | Risk | Findings |")
    lines.append("|----------|----------|----------|------------|------|----------|")
    for case in result.cases:
        for row in case["rows"]:
            lines.append(
                f"| {row['scenario']} | {row['typology']} | "
                f"{'yes' if row['detected'] else '**NO**'} | "
                f"{row['confidence'] if row['confidence'] is not None else '—'} | "
                f"{case['risk_score']} | {case['findings_total']} |"
            )
    lines.append("")
    lines.append(
        "> Synthetic data only. A high recall against these scenarios is evidence that the "
        "configuration works on *these patterns*; it is not evidence of fitness for a "
        "production population, which requires back-testing against the institution's own "
        "historical alerts."
    )
    lines.append("")
    return "\n".join(lines)
