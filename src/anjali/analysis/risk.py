"""Explainable, multi-dimensional risk scoring.

The score is a *weighted composite of named factors*, not a model output. That choice is
deliberate:

* GDPR Art. 22 and AI Act Art. 13/14 require meaningful information about the logic of
  decisions that affect people; a factor table satisfies that, a probability does not.
* A supervisor can disagree with a weight and re-run the score. They cannot re-run a black box.
* Every dimension cites the provision that makes it relevant, so the narrative writes itself.

Weights are configurable per jurisdiction profile (``anjali risk explain``).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from decimal import Decimal

from anjali.analysis.patterns import (
    HIGH_RISK_COUNTRIES,
    HIGH_RISK_INDUSTRIES,
    AnalysisContext,
    _is_cash,
)
from anjali.core.models import (
    DimensionScore,
    Finding,
    RiskAssessment,
    RiskBand,
    Severity,
)
from anjali.core.util import clamp, median, money, safe_div

DEFAULT_WEIGHTS: dict[str, float] = {
    "geographic": 0.22,
    "product": 0.16,
    "customer": 0.18,
    "behavioral": 0.30,
    "channel": 0.14,
}

# How each jurisdiction's regime weights the dimensions. The differences are real:
# the US regime is dominated by threshold/currency logic (BSA), the EU regime by
# risk-based EDD and geography, the UK by CDD completeness and the MLR risk assessment.
JURISDICTION_PROFILES: dict[str, dict[str, float]] = {
    "US": {"geographic": 0.20, "product": 0.22, "customer": 0.16, "behavioral": 0.30, "channel": 0.12},
    "EU": {"geographic": 0.28, "product": 0.14, "customer": 0.22, "behavioral": 0.26, "channel": 0.10},
    "UK": {"geographic": 0.24, "product": 0.16, "customer": 0.26, "behavioral": 0.24, "channel": 0.10},
}

PRODUCT_RISK = {
    "crypto": 92,
    "virtual_asset": 92,
    "prepaid": 80,
    "cash_deposit": 72,
    "cash_withdrawal": 72,
    "cash": 72,
    "wire": 62,
    "swift": 66,
    "remittance": 68,
    "trade_finance": 70,
    "letter_of_credit": 70,
    "ach": 34,
    "sepa": 32,
    "card": 30,
    "internal_transfer": 22,
    "check": 28,
}

CHANNEL_RISK = {
    "branch": 45,
    "teller": 50,
    "atm": 45,
    "online": 40,
    "mobile": 38,
    "api": 55,
    "third_party": 65,
    "agent": 62,
    "correspondent": 70,
    "non_face_to_face": 60,
}


@dataclass
class RiskWeights:
    values: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))

    def normalised(self) -> dict[str, float]:
        total = sum(self.values.values()) or 1.0
        return {k: v / total for k, v in self.values.items()}

    def for_jurisdiction(self, jurisdiction: str) -> dict[str, float]:
        profile = JURISDICTION_PROFILES.get(jurisdiction.upper(), self.values)
        total = sum(profile.values()) or 1.0
        return {k: v / total for k, v in profile.items()}


def _uc(value: str | None) -> str:
    return (value or "").strip().upper()


def _dim(
    dimension: str,
    score: float,
    weight: float,
    rationale: str,
    drivers: list[str],
    keys: list[str],
) -> tuple[DimensionScore, list[str]]:
    return (
        DimensionScore(
            dimension=dimension,
            score=round(clamp(score, 0.0, 100.0), 1),
            weight=round(weight, 4),
            rationale=rationale,
            drivers=drivers,
        ),
        keys,
    )


# --------------------------------------------------------------------------- #
# Dimensions
# --------------------------------------------------------------------------- #
def geographic_dimension(ctx: AnalysisContext, weight: float) -> tuple[DimensionScore, list[str]]:
    countries = Counter()
    volume = defaultdict(float)
    for txn in ctx.transactions:
        for code in (txn.country_from, txn.country_to):
            if code:
                countries[_uc(code)] += 1
                volume[_uc(code)] += float(txn.amount)
    total_volume = sum(volume.values()) or 1.0
    high_risk = {c: v for c, v in volume.items() if c in HIGH_RISK_COUNTRIES}
    hr_share = safe_div(sum(high_risk.values()), total_volume)
    distinct = len(countries)
    spread = clamp((distinct - 2) / 10.0)
    score = 100 * clamp(0.72 * hr_share * 2.2 + 0.18 * spread + (0.10 if high_risk else 0.0))

    drivers: list[str] = []
    for code, vol in sorted(high_risk.items(), key=lambda kv: kv[1], reverse=True)[:4]:
        drivers.append(f"{code} — {HIGH_RISK_COUNTRIES[code]} ({vol / total_volume:.1%} of value)")
    if not drivers:
        drivers.append(f"No FATF call-for-action or sanctions-programme jurisdiction in volume "
                       f"({distinct} distinct countries seen).")
    keys = ["eu-high-risk-third-countries", "fatf-r1-rba"]
    if high_risk:
        keys.append("us-31usc-5318a")
    rationale = (
        f"{hr_share:.1%} of transaction value touches a high-risk jurisdiction across "
        f"{distinct} countries. Geographic risk drives enhanced due diligence, not a finding "
        "of wrongdoing."
    )
    return _dim("geographic", score, weight, rationale, drivers, keys)


def product_dimension(ctx: AnalysisContext, weight: float) -> tuple[DimensionScore, list[str]]:
    volume = defaultdict(float)
    for txn in ctx.transactions:
        volume[(txn.txn_type or "unknown").lower()] += float(txn.amount)
    total = sum(volume.values()) or 1.0
    weighted = sum(PRODUCT_RISK.get(kind, 35) * (val / total) for kind, val in volume.items())
    drivers = [
        f"{kind}: {val / total:.0%} of value — inherent risk {PRODUCT_RISK.get(kind, 35)}/100"
        for kind, val in sorted(volume.items(), key=lambda kv: kv[1], reverse=True)[:4]
    ]
    cash_share = safe_div(
        float(sum(t.amount for t in ctx.transactions if _is_cash(t))),
        float(sum(t.amount for t in ctx.transactions) or 1),
    )
    score = clamp(weighted + (12 if cash_share > 0.5 else 0))
    keys = ["fatf-r1-rba", "us-31cfr-1010-311"]
    if any(k in volume for k in ("crypto", "virtual_asset")):
        keys.append("us-fincen-cvc-advisory")
    rationale = (
        f"Value-weighted inherent risk across {len(volume)} product types is {weighted:.0f}/100; "
        f"cash accounts for {cash_share:.0%} of value."
    )
    return _dim("product", score, weight, rationale, drivers, keys)


def customer_dimension(ctx: AnalysisContext, weight: float) -> tuple[DimensionScore, list[str]]:
    if not ctx.customers:
        return _dim(
            "customer",
            30.0,
            weight,
            "No customer master supplied — customer dimension scored at the neutral baseline 30/100.",
            ["Provide a customer file (`anjali data load --customers`) to score this dimension properly."],
            ["fatf-r10-cdd"],
        )
    scores: list[float] = []
    drivers: list[str] = []
    keys = ["fatf-r10-cdd", "uk-mlr-2017-reg27"]
    for cust in ctx.customers.values():
        s = 15.0
        reasons: list[str] = []
        if cust.pep:
            s += 40
            reasons.append("PEP")
            keys.append("fatf-r12-pep")
        industry = (cust.industry or "").lower()
        if any(bad in industry for bad in HIGH_RISK_INDUSTRIES):
            s += 22
            reasons.append(f"high-risk sector ({cust.industry})")
        if cust.customer_type == "business" and not cust.beneficial_owners:
            s += 18
            reasons.append("legal entity with no beneficial ownership on file")
            keys.append("us-31cfr-1010-230")
        if cust.customer_type == "business" and not cust.edd_completed:
            s += 8
            reasons.append("EDD not completed")
            keys.append("us-ffiec-edd-pep")
        if _uc(cust.country) in HIGH_RISK_COUNTRIES:
            s += 20
            reasons.append(f"domiciled in {cust.country}")
        if not cust.kyc_verified_at:
            s += 12
            reasons.append("no KYC verification date recorded")
        scores.append(clamp(s, 0, 100))
        if reasons:
            drivers.append(f"{cust.name}: " + "; ".join(reasons))
    avg = sum(scores) / len(scores)
    if not drivers:
        drivers.append("No PEP, high-risk sector or missing-CDD indicators across the customer base.")
    rationale = (
        f"Average customer inherent risk {avg:.0f}/100 across {len(ctx.customers)} customers, "
        "driven by PEP status, sector, domicile and CDD completeness."
    )
    return _dim("customer", avg, weight, rationale, drivers[:6], keys)


def behavioral_dimension(
    ctx: AnalysisContext, findings: Sequence[Finding], weight: float
) -> tuple[DimensionScore, list[str]]:
    if not findings:
        return _dim(
            "behavioral",
            20.0,
            weight,
            "No typology findings were raised; behavioural risk is at the low baseline.",
            ["All detectors ran clean against the supplied data."],
            ["fatf-r1-rba"],
        )
    severity_weight = {
        Severity.CRITICAL: 26.0,
        Severity.HIGH: 16.0,
        Severity.MEDIUM: 8.0,
        Severity.LOW: 3.0,
        Severity.INFO: 0.5,
    }
    base = sum(severity_weight[f.severity] * f.confidence for f in findings)
    # Diversity of typologies matters: five structuring hits is one behaviour, five
    # different typologies is a much stronger signal of a genuinely risky relationship.
    distinct = len({f.typology for f in findings})
    score = clamp(base * 0.85 + distinct * 4.0, 0, 100)
    by_type = Counter(f.typology for f in findings)
    drivers = [f"{typ} × {n}" for typ, n in by_type.most_common(6)]
    drivers.append(f"{len(findings)} findings across {distinct} distinct typologies")
    keys = ["fatf-r1-rba", "uk-fca-sysc-6-3"]
    keys += ["us-31cfr-1020-320"] if by_type.get("structuring") else []
    rationale = (
        f"{len(findings)} findings across {distinct} typologies; severity-weighted score "
        f"{base:.1f} before the diversity adjustment, final {score:.0f}/100."
    )
    return _dim("behavioral", score, weight, rationale, drivers, list(dict.fromkeys(keys)))


def channel_dimension(ctx: AnalysisContext, weight: float) -> tuple[DimensionScore, list[str]]:
    volume = defaultdict(float)
    shared_devices = sum(1 for accts in ctx.device_accounts.values() if len(accts) >= 3)
    shared_ips = sum(1 for accts in ctx.ip_accounts.values() if len(accts) >= 3)
    for txn in ctx.transactions:
        key = (txn.channel or "unstated").lower().replace("-", "_")
        volume[key] += float(txn.amount)
    total = sum(volume.values()) or 1.0
    weighted = sum(CHANNEL_RISK.get(k, 40) * (v / total) for k, v in volume.items())
    score = clamp(weighted + min(25, (shared_devices + shared_ips) * 7))
    drivers = [
        f"{chan or 'unstated'}: {val / total:.0%} of value — inherent risk {CHANNEL_RISK.get(chan, 40)}/100"
        for chan, val in sorted(volume.items(), key=lambda kv: kv[1], reverse=True)[:4]
    ]
    if shared_devices or shared_ips:
        drivers.append(
            f"{shared_devices} device and {shared_ips} IP identifiers shared across 3+ accounts"
        )
    rationale = (
        f"Value-weighted channel risk {weighted:.0f}/100"
        + (f", increased by {shared_devices + shared_ips} shared access identifiers." if shared_devices or shared_ips else ".")
    )
    keys = ["fatf-r15-new-tech", "fatf-digital-id", "intl-shadow-fintech-risk"]
    return _dim("channel", score, weight, rationale, drivers, keys)


# --------------------------------------------------------------------------- #
# Composite
# --------------------------------------------------------------------------- #
@dataclass
class RiskResult:
    assessment: RiskAssessment
    citation_keys: list[str] = field(default_factory=list)


def assess(
    ctx: AnalysisContext,
    findings: Sequence[Finding],
    *,
    weights: RiskWeights | None = None,
    jurisdiction: str | None = None,
    resolve: Callable[[Sequence[str]], list] | None = None,
) -> RiskResult:
    weights = weights or RiskWeights()
    weight_map = weights.for_jurisdiction(jurisdiction) if jurisdiction else weights.normalised()

    builders: list[tuple[str, tuple[DimensionScore, list[str]]]] = [
        ("geographic", geographic_dimension(ctx, weight_map["geographic"])),
        ("product", product_dimension(ctx, weight_map["product"])),
        ("customer", customer_dimension(ctx, weight_map["customer"])),
        ("behavioral", behavioral_dimension(ctx, findings, weight_map["behavioral"])),
        ("channel", channel_dimension(ctx, weight_map["channel"])),
    ]

    dimensions: list[DimensionScore] = []
    keys: list[str] = []
    for _name, (dim, dim_keys) in builders:
        dimensions.append(dim)
        keys.extend(dim_keys)

    total_weight = sum(w for _n, (d, _k) in builders for w in [d.weight]) or 1.0
    overall = sum(d.score * d.weight for d in dimensions) / total_weight

    # Severity floor. A weighted average can otherwise dilute a CRITICAL finding into a
    # MEDIUM score, which would be indefensible in review. Any critical finding puts the
    # assessment in at least HIGH; three or more put it in CRITICAL territory.
    critical = sum(1 for f in findings if f.severity is Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity is Severity.HIGH)
    if critical >= 3:
        overall = max(overall, 80.0)
    elif critical >= 1:
        overall = max(overall, 68.0)
    elif high >= 3:
        overall = max(overall, 55.0)
    band = RiskBand.from_score(overall)

    views: dict[str, float] = {}
    for juris in ("US", "EU", "UK"):
        profile = weights.for_jurisdiction(juris)
        adjusted = getattr_scores(dimensions, juris)
        views[juris] = round(sum(adjusted[k] * profile[k] for k in profile), 1)

    top = sorted(dimensions, key=lambda d: d.score * d.weight, reverse=True)
    narrative = (
        f"Composite risk {overall:.1f}/100 ({band.value}) under a weighted, "
        f"citation-backed assessment. The dominant driver is "
        f"{top[0].dimension} ({top[0].score:.0f}/100, weight {top[0].weight:.0%}): "
        f"{top[0].rationale} "
        f"{len(findings)} typology finding(s) were raised. "
        "Scores are decision support, not a determination: a named reviewer must confirm "
        "the outcome and record the rationale."
    )
    if jurisdiction:
        narrative += f" Weighting uses the {jurisdiction.upper()} supervisory profile."

    assessment = RiskAssessment(
        overall=round(overall, 1),
        band=band,
        dimensions=dimensions,
        narrative=narrative,
        confidence=round(clamp(0.55 + 0.02 * len(findings)), 2),
        jurisdiction_views=views,
    )
    if resolve:
        assessment.citations = resolve(list(dict.fromkeys(keys)))
        for dim in dimensions:
            dim.citations = resolve([k for k in keys if _dimension_owns_key(dim.dimension, k)])
    return RiskResult(assessment=assessment, citation_keys=list(dict.fromkeys(keys)))


def getattr_scores(dimensions: Sequence[DimensionScore], jurisdiction: str) -> dict[str, float]:
    """Per-dimension scores, lightly adjusted for jurisdiction-specific sensitivity.

    The adjustments encode documented differences in regime emphasis — for example the EU
    weights geographic risk more heavily because high-risk third-country EDD is mandatory,
    while the US penalises product/channel risk more because the BSA is threshold-driven.
    """
    base = {d.dimension: d.score for d in dimensions}
    if jurisdiction.upper() == "EU":
        base["geographic"] = clamp(base.get("geographic", 0) * 1.12, 0, 100)
    elif jurisdiction.upper() == "US":
        base["product"] = clamp(base.get("product", 0) * 1.08, 0, 100)
        base["behavioral"] = clamp(base.get("behavioral", 0) * 1.05, 0, 100)
    elif jurisdiction.upper() == "UK":
        base["customer"] = clamp(base.get("customer", 0) * 1.10, 0, 100)
    return base


_KEY_OWNERS = {
    "geographic": {"eu-high-risk-third-countries", "fatf-r1-rba", "us-31usc-5318a"},
    "product": {"us-31cfr-1010-311", "us-fincen-cvc-advisory", "fatf-r1-rba"},
    "customer": {"fatf-r10-cdd", "fatf-r12-pep", "us-31cfr-1010-230", "us-ffiec-edd-pep", "uk-mlr-2017-reg27"},
    "behavioral": {"uk-fca-sysc-6-3", "us-31cfr-1020-320", "fatf-r1-rba"},
    "channel": {"fatf-r15-new-tech", "fatf-digital-id", "intl-shadow-fintech-risk"},
}


def _dimension_owns_key(dimension: str, key: str) -> bool:
    return key in _KEY_OWNERS.get(dimension, set())


def volume_summary(ctx: AnalysisContext) -> dict[str, object]:
    amounts = [float(t.amount) for t in ctx.transactions]
    return {
        "transactions": len(ctx.transactions),
        "accounts": len(ctx.accounts_seen),
        "customers": len(ctx.customers),
        "total_value": str(money(sum(Decimal(str(a)) for a in amounts))) if amounts else "0.00",
        "median_value": str(money(median(amounts))) if amounts else "0.00",
        "max_value": str(money(max(amounts))) if amounts else "0.00",
        "first_ts": ctx.transactions[0].timestamp.isoformat() if ctx.transactions else None,
        "last_ts": ctx.transactions[-1].timestamp.isoformat() if ctx.transactions else None,
    }
