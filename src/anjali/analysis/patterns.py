"""Typology detectors.

Design rules that every detector follows:

1. **Deterministic.** Same input, same finding ids, same metrics. An examiner can re-run
   the analysis and get byte-identical output, which is not true of model-based scoring.
2. **Explainable.** Each finding carries the numeric test that fired, the transactions
   behind it, and the reasoning steps in plain language.
3. **Cited.** Detectors reference corpus ``doc_id``s; the engine resolves them to full
   citations. A finding can never be produced without a legal hook.
4. **Conservative.** Thresholds are tunable, and findings state their confidence so a
   weak signal is never dressed up as a conclusion.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal

from anjali.core.models import (
    Account,
    Customer,
    Finding,
    Severity,
    Transaction,
)
from anjali.core.util import (
    clamp,
    median,
    modified_zscore,
    money,
    safe_div,
    stable_id,
)

D = Decimal

# FATF black list + widely-recognised higher-risk jurisdictions. Deliberately small and
# illustrative: production deployments should load the current FATF/EU/US lists, which
# ANJALI tracks as temporal corpus documents rather than hard-coded constants.
HIGH_RISK_COUNTRIES = {
    "IR": "FATF call for action / comprehensive US sanctions",
    "KP": "FATF call for action / comprehensive sanctions",
    "MM": "FATF call for action",
    "SY": "comprehensive sanctions / conflict zone",
    "AF": "conflict zone, weak AML supervision",
    "YE": "conflict zone",
    "SS": "conflict zone",
    "HT": "FATF grey list",
    "RU": "sanctions programmes, limited correspondent access",
    "BY": "sanctions programmes",
    "LB": "FATF grey list (2023-)",
    "VN": "FATF grey list (2023-)",
}

HIGH_RISK_INDUSTRIES = {
    "crypto", "virtual asset", "vasp", "casino", "gambling", "adult entertainment",
    "precious metals", "art dealer", "real estate", "money services business", "msb",
    "shell company", "holding", "arms", "defense", "diamond", "scrap metal",
}

CASH_TYPES = {
    "cash", "cash_deposit", "cash_withdrawal", "currency", "cash_in", "cash_out",
    "atm", "teller", "cash_deposit_atm", "physical_cash",
}

WIRE_TYPES = {"wire", "swift", "funds_transfer", "remittance", "international_transfer", "sepa", "ach"}


@dataclass
class DetectorConfig:
    currency_threshold: D = D("10000")       # US CTR / EU cash CDD trigger
    structuring_band_low: float = 0.80      # "just below threshold" band
    structuring_min_count: int = 2
    structuring_window_days: int = 30
    aggregation_days: int = 1               # business-day aggregation for CTR logic
    travel_rule_threshold: D = D("3000")    # 31 CFR 1010.410(f)
    travel_rule_band_low: float = 0.85
    layering_hours: int = 24
    layering_retention: float = 0.85
    layering_min_hops: int = 2
    velocity_z: float = 3.5
    velocity_window_days: int = 7
    baseline_days: int = 90
    dormant_days: int = 180
    dormant_multiple: float = 3.0
    mule_min_accounts: int = 3
    smurf_min_senders: int = 5
    smurf_window_days: int = 7
    tbml_price_deviation: float = 0.50
    cash_intensity_multiple: float = 2.5
    cycle_max_len: int = 5
    cycle_max_days: int = 45

    def band(self, threshold: D | None = None) -> tuple[D, D]:
        t = threshold or self.currency_threshold
        return money(t * D(str(self.structuring_band_low))), money(t)


@dataclass
class AnalysisContext:
    transactions: list[Transaction]
    customers: dict[str, Customer] = field(default_factory=dict)
    accounts: dict[str, Account] = field(default_factory=dict)
    config: DetectorConfig = field(default_factory=DetectorConfig)

    # derived indexes -------------------------------------------------- #
    def __post_init__(self) -> None:
        self.transactions = sorted(self.transactions, key=lambda t: t.timestamp)
        self.incoming: dict[str, list[Transaction]] = defaultdict(list)
        self.outgoing: dict[str, list[Transaction]] = defaultdict(list)
        self.by_customer: dict[str, list[Transaction]] = defaultdict(list)
        self.account_owner: dict[str, str] = {}
        self.device_accounts: dict[str, set[str]] = defaultdict(set)
        self.ip_accounts: dict[str, set[str]] = defaultdict(set)

        for acct in self.accounts.values():
            self.account_owner.setdefault(acct.account_id, acct.customer_id)
        for cust in self.customers.values():
            for acct in cust.accounts:
                self.account_owner.setdefault(acct, cust.customer_id)

        for txn in self.transactions:
            if txn.to_account:
                self.incoming[txn.to_account].append(txn)
            if txn.from_account:
                self.outgoing[txn.from_account].append(txn)
            for acct in (txn.from_account, txn.to_account):
                if not acct:
                    continue
                owner = self.account_owner.get(acct)
                if owner:
                    self.by_customer[owner].append(txn)
                if txn.device_id:
                    self.device_accounts[txn.device_id].add(acct)
                if txn.ip_address:
                    self.ip_accounts[txn.ip_address].add(acct)

    # helpers ---------------------------------------------------------- #
    @property
    def accounts_seen(self) -> set[str]:
        out: set[str] = set(self.incoming) | set(self.outgoing)
        return out

    def owner_of(self, account: str) -> str | None:
        return self.account_owner.get(account)

    def customer_name(self, account: str | None) -> str | None:
        if not account:
            return None
        owner = self.account_owner.get(account)
        if owner and owner in self.customers:
            return self.customers[owner].name
        return None

    def transactions_for_owner(self, owner: str) -> list[Transaction]:
        if owner in self.by_customer:
            return self.by_customer[owner]
        return [t for t in self.transactions if owner in (t.from_account, t.to_account)]


@dataclass
class Detection:
    """A finding plus the corpus ids that justify it."""

    finding: Finding
    citation_keys: list[str] = field(default_factory=list)


def _mk(
    *,
    typology: str,
    severity: Severity,
    title: str,
    summary: str,
    confidence: float,
    evidence: Iterable[str],
    accounts: Iterable[str] = (),
    metrics: dict[str, object] | None = None,
    explanation: list[str] | None = None,
    actions: list[str] | None = None,
    keys: list[str] | None = None,
    case_salt: str = "",
) -> Detection:
    evidence_list = list(dict.fromkeys(e for e in evidence if e))
    finding = Finding(
        finding_id=stable_id(typology, case_salt, *sorted(evidence_list)[:6], prefix="FND-", length=10),
        typology=typology,
        severity=severity,
        title=title,
        summary=summary,
        confidence=round(clamp(confidence), 3),
        evidence_txn_ids=evidence_list,
        accounts=sorted({a for a in accounts if a}),
        metrics=metrics or {},
        explanation=explanation or [],
        recommended_actions=actions or [],
    )
    return Detection(finding=finding, citation_keys=keys or [])


def _is_cash(txn: Transaction) -> bool:
    """Cash means physical currency. A 'branch' channel is not cash by itself —
    trade-finance and wire business is also booked through branches."""
    kind = (txn.txn_type or "").lower()
    channel = (txn.channel or "").lower()
    return kind in CASH_TYPES or "cash" in kind or channel in {"teller", "atm"}


def _is_wire(txn: Transaction) -> bool:
    kind = (txn.txn_type or "").lower()
    return kind in WIRE_TYPES or "wire" in kind or "transfer" in kind


# --------------------------------------------------------------------------- #
# 1. Structuring / smurfing by one party
# --------------------------------------------------------------------------- #
def detect_structuring(ctx: AnalysisContext) -> list[Detection]:
    cfg = ctx.config
    low, high = cfg.band()
    out: list[Detection] = []

    # Group cash movements by beneficial party (customer where known, else account).
    groups: dict[str, list[Transaction]] = defaultdict(list)
    for txn in ctx.transactions:
        if not _is_cash(txn) or txn.amount < low or txn.amount >= high:
            continue
        party = ctx.owner_of(txn.from_account or "") or ctx.owner_of(txn.to_account or "")
        party = party or (txn.from_account or txn.to_account or "unknown")
        groups[party].append(txn)

    for party, txns in groups.items():
        for direction in ("credit", "debit"):
            bucket = [t for t in txns if t.direction.value == direction]
            if len(bucket) < cfg.structuring_min_count:
                continue
            bucket.sort(key=lambda t: t.timestamp)
            # Candidate windows from every start index, then keep the strongest
            # non-overlapping ones. One pattern should produce one finding: a rolling
            # window would otherwise emit a near-duplicate alert for every extra day,
            # which is exactly how genuine alerts get buried in a backlog.
            candidates: list[list[Transaction]] = []
            for i, start in enumerate(bucket):
                window = [
                    t for t in bucket[i:]
                    if (t.timestamp - start.timestamp) <= timedelta(days=cfg.structuring_window_days)
                ]
                if len(window) >= cfg.structuring_min_count:
                    candidates.append(window)
            candidates.sort(key=lambda w: (len(w), float(sum(t.amount for t in w))), reverse=True)
            windows: list[list[Transaction]] = []
            claimed: set[str] = set()
            for candidate in candidates:
                ids = {t.txn_id for t in candidate}
                if len(ids & claimed) > len(ids) * 0.4:
                    continue
                windows.append(candidate)
                claimed |= ids

            for window in windows:
                total = money(sum(t.amount for t in window))
                if total < high:
                    continue
                branches = {t.branch for t in window if t.branch}
                days = {(t.timestamp.date(), t.branch) for t in window}
                same_day = len({t.timestamp.date() for t in window}) == 1
                count = len(window)
                # Score: how much the pattern looks like deliberate evasion.
                intensity = clamp(float(total / high) / 3.0)           # 0-1
                multiplicity = clamp((count - 1) / 6.0)                 # 0-1
                split_signal = clamp(1.0 - safe_div(float(median([t.amount for t in window])), float(high)))
                score = 0.35 * intensity + 0.35 * multiplicity + 0.30 * split_signal
                strong = (
                    count >= 4
                    or (same_day and count >= 3)
                    or len(branches) >= 2
                    or total >= high * 2
                )
                severity = Severity.CRITICAL if strong and score > 0.55 else (
                    Severity.HIGH if strong or score > 0.5 else Severity.MEDIUM
                )
                name = ctx.customer_name(window[0].to_account or window[0].from_account) or party
                out.append(
                    _mk(
                        typology="structuring",
                        severity=severity,
                        title=f"Structured cash {direction}s just below the reporting threshold",
                        summary=(
                            f"{count} cash {direction}s totalling {total} were made by {name} "
                            f"within {cfg.structuring_window_days} days, each below the "
                            f"{high} reporting threshold but aggregating above it."
                        ),
                        confidence=round(clamp(0.55 + 0.35 * score), 3),
                        evidence=[t.txn_id for t in window],
                        accounts=[a for t in window for a in (t.from_account, t.to_account) if a],
                        metrics={
                            "party": party,
                            "window_from": window[0].timestamp.isoformat(),
                            "window_to": window[-1].timestamp.isoformat(),
                            "transaction_count": count,
                            "total_amount": str(total),
                            "threshold": str(high),
                            "band_low": str(low),
                            "distinct_branches": len(branches),
                            "single_day": same_day,
                            "median_amount": str(money(median([float(t.amount) for t in window]))),
                            "pattern_score": round(score, 3),
                        },
                        explanation=[
                            f"Selected cash transactions with amount in [{low}, {high}) — the "
                            f"'just below threshold' band used for CTR evasion.",
                            f"Grouped by beneficial party {name}; {count} qualifying transactions "
                            f"inside a {cfg.structuring_window_days}-day window.",
                            f"Aggregate {total} exceeds the {high} threshold, so a single "
                            f"transaction would have triggered a CTR and none of these did.",
                            f"Distinct branches used: {len(branches)}; "
                            f"{'all on one day' if same_day else f'spread over {len(days)} day/branch pairs'}"
                            " — consistent with deliberate splitting rather than coincidence.",
                            "Intent cannot be proven from data alone; the pattern supports a "
                            "reasonable suspicion, which is the SAR filing standard.",
                        ],
                        actions=[
                            "Escalate for SAR/STR consideration within the statutory clock.",
                            "Review the customer's stated business and prior CTR history.",
                            "Check related accounts and counterparties for the same pattern.",
                            "Do not inform the customer (tipping-off prohibition).",
                        ],
                        keys=[
                            "us-31cfr-1010-314",
                            "us-31usc-5324",
                            "us-31cfr-1020-320",
                            "us-31cfr-1010-311",
                        ],
                        case_salt=f"{party}-{window[0].timestamp.date()}-{direction}",
                    )
                )
    return out


# --------------------------------------------------------------------------- #
# 2. Smurfing network — many originators, one beneficiary
# --------------------------------------------------------------------------- #
def detect_smurfing(ctx: AnalysisContext) -> list[Detection]:
    cfg = ctx.config
    low, high = cfg.band()
    out: list[Detection] = []
    by_beneficiary: dict[str, list[Transaction]] = defaultdict(list)
    for txn in ctx.transactions:
        if txn.to_account and txn.amount < high:
            by_beneficiary[txn.to_account].append(txn)

    for beneficiary, txns in by_beneficiary.items():
        txns.sort(key=lambda t: t.timestamp)
        for i, start in enumerate(txns):
            window = [
                t for t in txns[i:]
                if (t.timestamp - start.timestamp) <= timedelta(days=cfg.smurf_window_days)
            ]
            senders = {(t.from_account or t.from_name or t.txn_id) for t in window}
            if len(senders) < cfg.smurf_min_senders:
                continue
            total = money(sum(t.amount for t in window))
            if total < high * 2:
                continue
            small = [t for t in window if t.amount < low]
            ratio_small = safe_div(len(small), len(window))
            window_end = start.timestamp + timedelta(days=cfg.smurf_window_days + 7)
            outflow = float(
                sum(
                    t.amount for t in ctx.transactions
                    if t.from_account == beneficiary
                    and start.timestamp <= t.timestamp <= window_end
                )
            )
            passthrough = clamp(safe_div(outflow, float(total)))
            # Many payers into one account is also what a normal business looks like.
            # A smurf/mule account is a conduit: the money must leave again, quickly.
            if passthrough < 0.5:
                continue
            severity = Severity.CRITICAL if len(senders) >= 8 and ratio_small > 0.6 else Severity.HIGH
            name = ctx.customer_name(beneficiary) or beneficiary
            out.append(
                _mk(
                    typology="smurfing",
                    severity=severity,
                    title="Many-to-one fan-in consistent with a mule or smurf account",
                    summary=(
                        f"{len(senders)} distinct senders paid {total} into {name} in "
                        f"{cfg.smurf_window_days} days; {ratio_small:.0%} of the payments were "
                        f"below the reporting threshold, and {passthrough:.0%} of the inflow "
                        "left the account again within a week."
                    ),
                    confidence=round(
                        clamp(0.45 + 0.3 * ratio_small + 0.02 * len(senders) + 0.15 * passthrough), 3
                    ),
                    evidence=[t.txn_id for t in window],
                    accounts=[beneficiary, *(t.from_account for t in window if t.from_account)],
                    metrics={
                        "beneficiary": beneficiary,
                        "distinct_senders": len(senders),
                        "transaction_count": len(window),
                        "total_amount": str(total),
                        "below_band_ratio": round(ratio_small, 3),
                        "passthrough_ratio": round(passthrough, 3),
                        "window_days": cfg.smurf_window_days,
                    },
                    explanation=[
                        f"Fan-in analysis on account {beneficiary}: {len(senders)} distinct "
                        "originators in the window.",
                        f"{len(small)} of {len(window)} payments fall below the "
                        f"{low} 'just under threshold' floor, and the aggregate {total} "
                        "is more than twice the reporting threshold.",
                        "Multiple unrelated senders paying one account in small amounts is the "
                        "canonical smurf/mule collection pattern; legitimate salary or family "
                        f"support does not usually produce this dispersion, and a merchant would "
                        f"retain the funds rather than pass {passthrough:.0%} of them straight on.",
                    ],
                    actions=[
                        "Identify and screen all senders; check for shared device or contact data.",
                        "Assess the beneficiary as a potential money-mule account and consider a hold.",
                        "File a SAR describing the fan-in and the sender population.",
                    ],
                    keys=["us-31cfr-1010-314", "us-31cfr-1020-320", "fatf-r20-str", "intl-shadow-fintech-risk"],
                    case_salt=f"{beneficiary}-{start.timestamp.date()}",
                )
            )
    return out


# --------------------------------------------------------------------------- #
# 3. Layering / rapid pass-through
# --------------------------------------------------------------------------- #
def detect_layering(ctx: AnalysisContext) -> list[Detection]:
    cfg = ctx.config
    out: list[Detection] = []
    for account, inflows in ctx.incoming.items():
        outflows = ctx.outgoing.get(account, [])
        if not inflows or not outflows:
            continue
        passthrough: list[tuple[Transaction, Transaction]] = []
        for inbound in inflows:
            for outbound in outflows:
                delta = outbound.timestamp - inbound.timestamp
                if (
                    timedelta(0) <= delta <= timedelta(hours=cfg.layering_hours)
                    and outbound.amount >= inbound.amount * D(str(cfg.layering_retention))
                ):
                    passthrough.append((inbound, outbound))
        if len(passthrough) < 2:
            continue
        matched_value = money(sum(min(i.amount, o.amount) for i, o in passthrough))
        total_in = money(sum(t.amount for t in inflows))
        retention = safe_div(float(matched_value), float(total_in)) if total_in else 0.0
        hops = len(passthrough)
        severity = Severity.CRITICAL if hops >= 5 or (retention > 0.8 and matched_value > cfg.currency_threshold) else Severity.HIGH
        name = ctx.customer_name(account) or account
        evidence = {t.txn_id for pair in passthrough for t in pair}
        out.append(
            _mk(
                typology="layering",
                severity=severity,
                title="Rapid pass-through — funds in and out within 24 hours",
                summary=(
                    f"Account {name} received and immediately re-sent {matched_value} across "
                    f"{hops} matched in/out pairs, retaining only {retention:.0%} of inflows."
                ),
                confidence=round(clamp(0.5 + 0.05 * hops + 0.2 * retention), 3),
                evidence=evidence,
                accounts=[account, *(i.from_account for i, _ in passthrough if i.from_account)],
                metrics={
                    "account": account,
                    "matched_pairs": hops,
                    "matched_value": str(matched_value),
                    "inflow_total": str(total_in),
                    "retention_ratio": round(retention, 3),
                    "max_hours": cfg.layering_hours,
                },
                explanation=[
                    f"Matched each inflow to an outflow within {cfg.layering_hours} hours where "
                    f"the outflow was at least {cfg.layering_retention:.0%} of the inflow.",
                    f"{hops} such pairs were found, moving {matched_value} through the account "
                    f"while retaining {retention:.0%} of the total inflow.",
                    "This is the layering stage of laundering: value is moved to break the audit "
                    "trail, not to hold a balance. A genuine operating account retains working "
                    "capital rather than passing it straight through.",
                ],
                actions=[
                    "Trace the outbound beneficiaries and build the onward flow graph.",
                    "Check whether the account was opened recently or has unusually low balances.",
                    "Assess for SAR with the full chain, not just the single account.",
                ],
                keys=["eu-amld6-2024-1640", "fatf-r20-str", "us-31cfr-1020-320", "intl-basel-aml"],
                case_salt=f"{account}-{rebox(inflows[0].timestamp)}",
            )
        )
    return out


def rebox(ts) -> str:  # tiny helper keeps finding ids stable per week bucket
    return f"{ts.isocalendar()[0]}-{ts.isocalendar()[1]}"


# --------------------------------------------------------------------------- #
# 4. Round-tripping — cycles in the transaction graph
# --------------------------------------------------------------------------- #
def find_cycles(edges: list[tuple[str, str]], max_len: int = 5) -> list[list[str]]:
    """Enumerate simple cycles up to ``max_len`` nodes (brute force; datasets are small)."""
    adj: dict[str, set[str]] = defaultdict(set)
    for src, dst in edges:
        if src and dst and src != dst:
            adj[src].add(dst)
    cycles: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()

    def dfs(start: str, node: str, path: list[str]) -> None:
        if len(path) > max_len:
            return
        for nxt in adj.get(node, ()):
            if nxt == start and len(path) >= 2:
                key = tuple(sorted(path))
                if key not in seen:
                    seen.add(key)
                    cycles.append([*path, start])
            elif nxt not in path:
                dfs(start, nxt, [*path, nxt])

    for node in adj:
        dfs(node, node, [node])
    return cycles


def detect_round_tripping(ctx: AnalysisContext) -> list[Detection]:
    cfg = ctx.config
    edges: list[tuple[str, str]] = []
    edge_txns: dict[tuple[str, str], list[Transaction]] = defaultdict(list)
    for txn in ctx.transactions:
        if txn.from_account and txn.to_account and txn.from_account != txn.to_account:
            edges.append((txn.from_account, txn.to_account))
            edge_txns[(txn.from_account, txn.to_account)].append(txn)

    out: list[Detection] = []
    for cycle in find_cycles(edges, cfg.cycle_max_len):
        txns: list[Transaction] = []
        for a, b in zip(cycle, cycle[1:]):
            txns.extend(edge_txns.get((a, b), []))
        if len(txns) < len(cycle) - 1:
            continue
        span = max(t.timestamp for t in txns) - min(t.timestamp for t in txns)
        if span > timedelta(days=cfg.cycle_max_days):
            continue
        total = money(sum(t.amount for t in txns))
        values = [float(t.amount) for t in txns]
        consistency = safe_div(min(values), max(values)) if values else 0.0
        severity = Severity.CRITICAL if consistency > 0.8 else Severity.HIGH
        out.append(
            _mk(
                typology="round_tripping",
                severity=severity,
                title="Circular fund flow — money returns to its origin",
                summary=(
                    f"A {len(cycle) - 1}-hop cycle ({' → '.join(cycle)}) moved {total} within "
                    f"{span.days} days, with {consistency:.0%} value consistency between hops."
                ),
                confidence=round(clamp(0.55 + 0.4 * consistency), 3),
                evidence=[t.txn_id for t in txns],
                accounts=cycle,
                metrics={
                    "cycle": cycle,
                    "hops": len(cycle) - 1,
                    "total_amount": str(total),
                    "value_consistency": round(consistency, 3),
                    "span_days": span.days,
                },
                explanation=[
                    "Built a directed graph of account-to-account transfers and searched for "
                    f"simple cycles of at most {cfg.cycle_max_len} nodes.",
                    f"Cycle detected: {' → '.join(cycle)}.",
                    f"Value consistency between hops is {consistency:.0%} and the cycle completed "
                    f"in {span.days} days — funds came back to where they started, net of fees.",
                    "Round-tripping is used to manufacture a paper trail of legitimate-looking "
                    "transactions and to inflate turnover (also relevant to tax and invoice fraud).",
                ],
                actions=[
                    "Identify the beneficial owner of every account in the cycle.",
                    "Compare amounts against invoices or contracts claimed to justify the flows.",
                    "Assess for SAR and consider reporting under trade-based or fraud typologies.",
                ],
                keys=["fatf-tbml", "us-31cfr-1020-320", "eu-amld6-2024-1640"],
                case_salt="-".join(cycle),
            )
        )
    return out


# --------------------------------------------------------------------------- #
# 5. Velocity anomaly
# --------------------------------------------------------------------------- #
def detect_velocity(ctx: AnalysisContext) -> list[Detection]:
    cfg = ctx.config
    out: list[Detection] = []
    account_events: dict[str, list[Transaction]] = defaultdict(list)
    for txn in ctx.transactions:
        for acct in (txn.from_account, txn.to_account):
            if acct:
                account_events[acct].append(txn)

    for account, events in account_events.items():
        events.sort(key=lambda t: t.timestamp)
        if len(events) < 8:
            continue
        daily: dict[str, int] = Counter(t.timestamp.date().isoformat() for t in events)
        days = sorted(daily)
        if len(days) < 10:
            continue
        counts = [daily[d] for d in days]
        baseline = counts[:-1] if len(counts) > 10 else counts
        latest = counts[-1]
        z = modified_zscore(float(latest), [float(c) for c in baseline])
        if z < cfg.velocity_z:
            continue
        latest_date = days[-1]
        latest_txns = [t for t in events if t.timestamp.date().isoformat() == latest_date]
        total = money(sum(t.amount for t in latest_txns))
        severity = Severity.HIGH if z > 6 else Severity.MEDIUM
        name = ctx.customer_name(account) or account
        out.append(
            _mk(
                typology="velocity_anomaly",
                severity=severity,
                title="Transaction velocity far outside the account's own baseline",
                summary=(
                    f"{name} processed {latest} transactions on {latest_date} against a median "
                    f"of {median([float(c) for c in baseline]):.0f} per active day "
                    f"(robust z-score {z:.1f})."
                ),
                confidence=round(clamp(0.45 + 0.06 * abs(z)), 3),
                evidence=[t.txn_id for t in latest_txns],
                accounts=[account],
                metrics={
                    "account": account,
                    "date": latest_date,
                    "count_today": latest,
                    "baseline_median": median([float(c) for c in baseline]),
                    "modified_zscore": round(z, 3),
                    "amount_today": str(total),
                },
                explanation=[
                    "Computed daily transaction counts for the account and used the "
                    "Iglewicz–Hoaglin modified z-score (median/MAD) so that past spikes do not "
                    "inflate the baseline the way a standard deviation would.",
                    f"Latest day {latest_date}: {latest} transactions, baseline median "
                    f"{median([float(c) for c in baseline]):.0f}, z = {z:.1f} "
                    f"(threshold {cfg.velocity_z}).",
                    "A sudden burst of activity on an established account is a recognised "
                    "indicator of account takeover or of the account being rented for layering.",
                ],
                actions=[
                    "Verify customer-initiated activity with the customer through a known channel.",
                    "Check device and IP changes around the burst for account-takeover indicators.",
                    "Continue monitoring; escalate if the burst coincides with high-risk geography.",
                ],
                keys=["fatf-r10-cdd", "us-31cfr-1020-320", "uk-fca-sysc-6-3"],
                case_salt=f"{account}-{latest_date}",
            )
        )
    return out


# --------------------------------------------------------------------------- #
# 6. Dormant account reactivation
# --------------------------------------------------------------------------- #
def detect_dormant_reactivation(ctx: AnalysisContext) -> list[Detection]:
    cfg = ctx.config
    out: list[Detection] = []
    account_events: dict[str, list[Transaction]] = defaultdict(list)
    for txn in ctx.transactions:
        for acct in (txn.from_account, txn.to_account):
            if acct:
                account_events[acct].append(txn)

    for account, events in account_events.items():
        events.sort(key=lambda t: t.timestamp)
        if len(events) < 3:
            continue
        gaps = [
            (events[i + 1].timestamp - events[i].timestamp, i)
            for i in range(len(events) - 1)
        ]
        biggest, idx = max(gaps, key=lambda g: g[0])
        if biggest.days < cfg.dormant_days:
            continue
        before = events[: idx + 1]
        after = events[idx + 1 :]
        prior_median = median([float(t.amount) for t in before]) or 1.0
        after_median = median([float(t.amount) for t in after])
        if after_median < prior_median * cfg.dormant_multiple:
            continue
        severity = Severity.HIGH if after_median > prior_median * 10 else Severity.MEDIUM
        name = ctx.customer_name(account) or account
        out.append(
            _mk(
                typology="dormant_reactivation",
                severity=severity,
                title="Dormant account reactivated with materially larger transactions",
                summary=(
                    f"{name} was inactive for {biggest.days} days, then resumed with a median "
                    f"transaction of {money(after_median)} versus {money(prior_median)} before "
                    "the dormancy."
                ),
                confidence=0.6,
                evidence=[t.txn_id for t in after[:12]],
                accounts=[account],
                metrics={
                    "account": account,
                    "dormant_days": biggest.days,
                    "reactivated_at": events[idx + 1].timestamp.isoformat(),
                    "prior_median": str(money(prior_median)),
                    "post_median": str(money(after_median)),
                    "multiple": round(safe_div(after_median, prior_median), 2),
                },
                explanation=[
                    f"Longest observed inactivity gap on the account: {biggest.days} days "
                    f"(threshold {cfg.dormant_days}).",
                    f"Median transaction value after reactivation is {money(after_median)} versus "
                    f"{money(prior_median)} before — a {safe_div(after_median, prior_median):.1f}x increase.",
                    "Dormant accounts are attractive to launderers because the account has a clean "
                    "history and existing KYC; a change of control or sale of the account is common.",
                ],
                actions=[
                    "Re-perform CDD: confirm the customer still controls the account.",
                    "Check device, IP and contact changes at the point of reactivation.",
                    "Consider a SAR if the new activity cannot be explained by the customer.",
                ],
                keys=["fatf-r10-cdd", "uk-mlr-2017-reg27", "us-31cfr-1020-320"],
                case_salt=f"{account}-{events[idx + 1].timestamp.date()}",
            )
        )
    return out


# --------------------------------------------------------------------------- #
# 7. High-risk geography
# --------------------------------------------------------------------------- #
def detect_high_risk_geography(ctx: AnalysisContext) -> list[Detection]:
    out: list[Detection] = []
    hits: dict[str, list[Transaction]] = defaultdict(list)
    for txn in ctx.transactions:
        for code in (txn.country_from, txn.country_to):
            if code and code.upper() in HIGH_RISK_COUNTRIES:
                hits[code.upper()].append(txn)
    for code, txns in hits.items():
        total = money(sum(t.amount for t in txns))
        share = safe_div(float(total), float(sum(t.amount for t in ctx.transactions) or 1))
        severity = Severity.CRITICAL if share > 0.25 else Severity.HIGH
        out.append(
            _mk(
                typology="high_risk_geography",
                severity=severity,
                title=f"Funds movement involving high-risk jurisdiction {code}",
                summary=(
                    f"{len(txns)} transactions totalling {total} ({share:.1%} of case volume) "
                    f"involve {code} — {HIGH_RISK_COUNTRIES[code]}."
                ),
                confidence=0.8,
                evidence=[t.txn_id for t in txns],
                accounts=[a for t in txns for a in (t.from_account, t.to_account) if a],
                metrics={
                    "country": code,
                    "reason": HIGH_RISK_COUNTRIES[code],
                    "transaction_count": len(txns),
                    "total_amount": str(total),
                    "share_of_volume": round(share, 3),
                },
                explanation=[
                    f"Flagged counterparty countries against the FATF call-for-action and "
                    f"grey lists plus comprehensive sanctions programmes; {code} is listed.",
                    f"{len(txns)} transactions involving {code} total {total}.",
                    "Geographic risk does not establish wrongdoing; it sets the due-diligence "
                    "standard. EDD is mandatory, and the institution must be able to explain the "
                    "business rationale for the corridor.",
                ],
                actions=[
                    "Apply EDD: establish source of funds and the commercial rationale for the corridor.",
                    "Screen all counterparties in the corridor against sanctions lists.",
                    "Document whether the corridor is consistent with the customer's declared business.",
                ],
                keys=["eu-high-risk-third-countries", "fatf-r1-rba", "us-31usc-5318a"],
                case_salt=code,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# 8. Mule / fraud network via shared access artefacts
# --------------------------------------------------------------------------- #
def detect_mule_network(ctx: AnalysisContext) -> list[Detection]:
    cfg = ctx.config
    out: list[Detection] = []
    clusters: list[tuple[str, str, set[str]]] = []
    for device, accts in ctx.device_accounts.items():
        if len(accts) >= cfg.mule_min_accounts:
            clusters.append(("device", device, accts))
    for ip, accts in ctx.ip_accounts.items():
        if len(accts) >= cfg.mule_min_accounts:
            clusters.append(("ip", ip, accts))

    seen: set[frozenset[str]] = set()
    for kind, key, accts in clusters:
        # Without a customer master we cannot tell our accounts from counterparties, so we
        # use every account. With one, only our own accounts count toward the cluster —
        # otherwise a single customer's device plus its payees looks like a mule ring.
        cluster_accounts = {a for a in accts if ctx.owner_of(a)} if ctx.customers else set(accts)
        if len(cluster_accounts) < cfg.mule_min_accounts:
            continue
        signature = frozenset(cluster_accounts)
        if signature in seen:
            continue
        seen.add(signature)
        accts = cluster_accounts
        txns = [
            t for t in ctx.transactions
            if t.to_account in accts or t.from_account in accts
        ]
        if len(txns) < cfg.mule_min_accounts * 2:
            continue
        owners = {ctx.owner_of(a) for a in accts if ctx.owner_of(a)}
        senders = {t.from_account for t in txns if t.from_account and t.from_account not in accts}
        severity = Severity.CRITICAL if len(accts) >= 5 else Severity.HIGH
        out.append(
            _mk(
                typology="mule_network",
                severity=severity,
                title=f"Accounts sharing a {kind} identifier — suspected mule cluster",
                summary=(
                    f"{len(accts)} accounts ({len(owners)} customers) share {kind} '{key}' and "
                    f"participate in {len(txns)} transactions with {len(senders)} external senders."
                ),
                confidence=round(clamp(0.5 + 0.08 * len(accts)), 3),
                evidence=[t.txn_id for t in txns],
                accounts=sorted(accts),
                metrics={
                    "link_type": kind,
                    "link_value": key,
                    "account_count": len(accts),
                    "customer_count": len(owners),
                    "transaction_count": len(txns),
                    "external_senders": len(senders),
                },
                explanation=[
                    f"Indexed accounts by device fingerprint and IP address; {len(accts)} accounts "
                    f"share the same {kind}.",
                    "Independent customers do not normally share a device or IP. Shared access "
                    "artefacts across unrelated accounts are the strongest single indicator of a "
                    "mule network or a single actor operating multiple identities.",
                    f"{len(senders)} distinct external senders fund the cluster, consistent with "
                    "recruited mule accounts receiving victim payments.",
                ],
                actions=[
                    "Identify the beneficial owner/controller behind the shared artefact.",
                    "Freeze or restrict the cluster pending review to prevent further victim loss.",
                    "File a SAR; consider referral to law enforcement given fraud victim impact.",
                ],
                keys=["intl-shadow-fintech-risk", "fatf-r10-cdd", "us-fincen-cvc-advisory"],
                case_salt=f"{kind}-{key}",
            )
        )
    return out


# --------------------------------------------------------------------------- #
# 9. Trade-based money laundering
# --------------------------------------------------------------------------- #
def detect_tbml(ctx: AnalysisContext) -> list[Detection]:
    cfg = ctx.config
    out: list[Detection] = []
    grouped: dict[tuple[str, str, str], list[tuple[Transaction, float]]] = defaultdict(list)
    for txn in ctx.transactions:
        if not txn.unit_price or not txn.benchmark_price:
            continue
        try:
            unit = float(txn.unit_price)
            bench = float(txn.benchmark_price)
        except (TypeError, ValueError):
            continue
        if bench <= 0:
            continue
        deviation = (unit - bench) / bench
        if abs(deviation) < cfg.tbml_price_deviation:
            continue
        direction = "over-invoiced" if deviation > 0 else "under-invoiced"
        grouped[(txn.goods_description or "goods", txn.hs_code or "n/a", direction)].append((txn, deviation))

    for (goods, hs_code, direction), entries in grouped.items():
        txn, deviation = max(entries, key=lambda e: abs(e[1]))
        severity = Severity.CRITICAL if abs(deviation) > 1.5 else Severity.HIGH
        invoice_count = len(entries)
        out.append(
            _mk(
                typology="tbml",
                severity=severity,
                title=f"Trade invoice {direction} against market benchmark",
                summary=(
                    f"Declared unit price {txn.unit_price} for '{goods}' is {deviation:+.0%} versus "
                    f"the benchmark {txn.benchmark_price} (HS {hs_code}) across {invoice_count} "
                    f"invoice(s); a recognised TBML indicator."
                ),
                confidence=round(clamp(0.5 + min(0.45, abs(deviation) / 2)), 3),
                evidence=[t.txn_id for t, _ in entries],
                accounts=sorted({a for t, _ in entries for a in (t.from_account, t.to_account) if a}),
                metrics={
                    "goods": goods,
                    "hs_code": hs_code,
                    "declared_unit_price": str(txn.unit_price),
                    "benchmark_price": str(txn.benchmark_price),
                    "deviation": round(deviation, 4),
                    "invoice_count": invoice_count,
                    "quantity": str(txn.quantity) if txn.quantity else None,
                    "route": txn.route,
                    "vessel": txn.vessel,
                },
                explanation=[
                    f"Compared the declared unit price against an independent benchmark: "
                    f"{txn.unit_price} vs {txn.benchmark_price}.",
                    f"Deviation of {deviation:+.0%} exceeds the {cfg.tbml_price_deviation:.0%} "
                    f"threshold; the invoice is {direction}.",
                    "Over-invoicing moves value out of the importing country; under-invoicing "
                    "moves value in and can also evade duties. Both are core TBML techniques.",
                ],
                actions=[
                    "Obtain the underlying commercial documents and compare with the invoice.",
                    "Verify the goods and route; screen the vessel and the counterparties.",
                    "Assess whether the price difference has a commercial explanation before filing.",
                ],
                keys=["fatf-tbml", "intl-wolfsberg-trade-principles", "us-31cfr-1020-320"],
                case_salt=f"{goods}-{hs_code}-{direction}",
            )
        )
    return out


# --------------------------------------------------------------------------- #
# 10. Travel-rule / recordkeeping threshold avoidance on wires
# --------------------------------------------------------------------------- #
def detect_wire_threshold_avoidance(ctx: AnalysisContext) -> list[Detection]:
    cfg = ctx.config
    threshold = cfg.travel_rule_threshold
    low = money(threshold * D(str(cfg.travel_rule_band_low)))
    out: list[Detection] = []
    groups: dict[str, list[Transaction]] = defaultdict(list)
    for txn in ctx.transactions:
        if _is_wire(txn) and low <= txn.amount < threshold:
            party = txn.from_account or txn.to_account or "unknown"
            groups[party].append(txn)
    for party, txns in groups.items():
        if len(txns) < 3:
            continue
        txns.sort(key=lambda t: t.timestamp)
        span = txns[-1].timestamp - txns[0].timestamp
        if span > timedelta(days=cfg.structuring_window_days):
            continue
        total = money(sum(t.amount for t in txns))
        severity = Severity.MEDIUM if len(txns) < 5 else Severity.HIGH
        out.append(
            _mk(
                typology="threshold_avoidance",
                severity=severity,
                title="Wire amounts clustered just below the travel-rule threshold",
                summary=(
                    f"{len(txns)} transfers between {low} and {threshold} from {party} in "
                    f"{span.days or 1} days totalling {total} — possible recordkeeping evasion."
                ),
                confidence=0.55,
                evidence=[t.txn_id for t in txns],
                accounts=[party],
                metrics={
                    "party": party,
                    "transaction_count": len(txns),
                    "threshold": str(threshold),
                    "band_low": str(low),
                    "total_amount": str(total),
                    "span_days": span.days,
                },
                explanation=[
                    f"Selected wire transfers in [{low}, {threshold}) — just below the "
                    f"{threshold} travel-rule / recordkeeping threshold in 31 CFR 1010.410.",
                    f"{len(txns)} such transfers by the same party within "
                    f"{cfg.structuring_window_days} days.",
                    "Sub-threshold clustering on wires is weaker evidence than cash structuring "
                    "(payment splitting for convenience is common), hence MEDIUM confidence; it "
                    "matters most when combined with other typologies.",
                ],
                actions=[
                    "Review whether splitting has a commercial rationale.",
                    "Confirm travel-rule data is present on each transfer.",
                    "Correlate with cash structuring and geography findings.",
                ],
                keys=["us-31cfr-1010-410-f", "fatf-r16-travel", "eu-tfr-2023-1113"],
                case_salt=f"{party}-{txns[0].timestamp.date()}",
            )
        )
    return out


# --------------------------------------------------------------------------- #
# 11. Cash intensity versus peer group
# --------------------------------------------------------------------------- #
def detect_cash_intensity(ctx: AnalysisContext) -> list[Detection]:
    cfg = ctx.config
    out: list[Detection] = []
    if not ctx.customers:
        return out
    by_customer: dict[str, list[Transaction]] = defaultdict(list)
    for txn in ctx.transactions:
        for acct in (txn.from_account, txn.to_account):
            owner = ctx.owner_of(acct or "")
            if owner:
                by_customer[owner].append(txn)

    ratios: dict[str, float] = {}
    for cid, txns in by_customer.items():
        total = float(sum(t.amount for t in txns)) or 1.0
        cash = float(sum(t.amount for t in txns if _is_cash(t)))
        ratios[cid] = cash / total

    for cid, ratio in ratios.items():
        cust = ctx.customers.get(cid)
        if not cust:
            continue
        peers = [
            r for other, r in ratios.items()
            if other != cid and ctx.customers.get(other)
            and ctx.customers[other].customer_type == cust.customer_type
        ]
        if len(peers) < 2:
            continue
        peer_median = median(peers)
        txns = by_customer[cid]
        cash_txns = [t for t in txns if _is_cash(t)]
        cash_total = float(sum(t.amount for t in cash_txns))
        # A peer median of zero is not a baseline — it means nobody in the cohort uses
        # cash, so "100% versus 0%" says nothing about this customer. Cash-intensive
        # businesses would be flagged on every review. Require a measurable peer
        # behaviour, a material absolute amount, and a real gap.
        if peer_median <= 0.01:
            continue
        if cash_total < 20_000 or len(cash_txns) < 6:
            continue
        if ratio - peer_median < 0.30:
            continue
        # A cash business that declares cash as its source of funds and stays inside its
        # expected turnover is behaving as onboarded — that is CDD working, not an alert.
        declared_cash = "cash" in (cust.source_of_funds or "").lower()
        expected = float(cust.expected_monthly_volume or 0)
        observed_total = float(sum(t.amount for t in txns))
        if declared_cash and expected > 0 and observed_total <= expected * 1.5:
            continue
        if ratio < max(0.25, peer_median * cfg.cash_intensity_multiple):
            continue
        severity = Severity.HIGH if ratio > 0.8 else Severity.MEDIUM
        out.append(
            _mk(
                typology="cash_intensity",
                severity=severity,
                title="Cash intensity materially above the customer's peer group",
                summary=(
                    f"{cust.name} settles {ratio:.0%} of value in cash versus a peer median of "
                    f"{peer_median:.0%} for {cust.customer_type} customers."
                ),
                confidence=0.6,
                evidence=[t.txn_id for t in cash_txns],
                accounts=cust.accounts,
                metrics={
                    "customer_id": cid,
                    "cash_ratio": round(ratio, 3),
                    "peer_median": round(peer_median, 3),
                    "peer_count": len(peers),
                    "peer_group": cust.customer_type,
                    "cash_total": round(cash_total, 2),
                    "cash_txn_count": len(cash_txns),
                },
                explanation=[
                    "Computed the share of transaction value settled in cash for each customer.",
                    f"Peer group = {cust.customer_type} customers in this case ({len(peers)} peers).",
                    f"This customer's cash share is {ratio:.0%} versus a peer median of "
                    f"{peer_median:.0%} — above the {cfg.cash_intensity_multiple}x multiple threshold.",
                    "Cash-intensive behaviour that is inconsistent with the declared business is a "
                    "behavioural deviation indicator under the risk-based approach.",
                ],
                actions=[
                    "Reconcile observed cash volumes with the declared business and expected turnover.",
                    "Refresh source-of-funds evidence.",
                    "Consider EDD or exit if the discrepancy is unexplained.",
                ],
                keys=["fatf-r1-rba", "fatf-r10-cdd", "us-31cfr-1010-311"],
                case_salt=cid,
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
DetectorFn = Callable[[AnalysisContext], list[Detection]]

DETECTORS: dict[str, DetectorFn] = {
    "structuring": detect_structuring,
    "smurfing": detect_smurfing,
    "layering": detect_layering,
    "round_tripping": detect_round_tripping,
    "velocity_anomaly": detect_velocity,
    "dormant_reactivation": detect_dormant_reactivation,
    "high_risk_geography": detect_high_risk_geography,
    "mule_network": detect_mule_network,
    "tbml": detect_tbml,
    "threshold_avoidance": detect_wire_threshold_avoidance,
    "cash_intensity": detect_cash_intensity,
}

DETECTOR_DESCRIPTIONS = {
    "structuring": "Cash activity clustered just below the reporting threshold",
    "smurfing": "Many-to-one fan-in into a single account",
    "layering": "Rapid pass-through of funds within 24 hours",
    "round_tripping": "Circular flows returning value to its origin",
    "velocity_anomaly": "Robust z-score burst detection against the account's own baseline",
    "dormant_reactivation": "Dormant account resuming with larger transactions",
    "high_risk_geography": "Counterparty countries on FATF/sanctions risk lists",
    "mule_network": "Accounts sharing device or IP identifiers",
    "tbml": "Invoice price deviation versus a market benchmark",
    "threshold_avoidance": "Wire clusters just below the travel-rule threshold",
    "cash_intensity": "Cash share of value versus the customer peer group",
}
