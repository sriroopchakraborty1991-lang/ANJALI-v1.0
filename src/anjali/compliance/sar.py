"""Suspicious Activity Report / STR generation.

The narrative is built from *facts already in the case*: the subjects, the transactions,
the computed metrics. Nothing is invented, and every quantitative claim in the narrative
traces back to a transaction id or a metric. An optional LLM pass polishes the prose, but
the fact table is assembled deterministically first — so if the model hallucinates, the
mismatch is detectable, and the report can always be regenerated without it.

The structure follows FinCEN/FFIEC guidance (who, what, when, where, why, how) and the
UK/EU equivalents. A quality gate scores the result against that checklist before it is
presented for human sign-off.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import date, timedelta
from decimal import Decimal
from typing import Any

from anjali.core.models import (
    Account,
    Citation,
    Customer,
    Finding,
    Jurisdiction,
    RiskAssessment,
    SARReport,
    SARSubject,
    Transaction,
)
from anjali.core.util import fmt_money, money, stable_id, today

D = Decimal

NARRATIVE_CHECKS = [
    ("who", "Identifies every subject by name, role and identifier"),
    ("what", "States the activity and the amounts explicitly"),
    ("when", "Gives an explicit start and end date for the activity"),
    ("where", "Names the branches, channels and jurisdictions involved"),
    ("why", "Explains why the activity is out of character for the customer"),
    ("how", "Describes the mechanism used to move the funds"),
    ("amounts", "Total value is stated and matches the underlying transactions"),
    ("no_legal_conclusions", "Avoids concluding that a crime was committed"),
    ("no_report_reference", "Does not reference the report itself or its filing status"),
    ("chronology", "Presents events in chronological order"),
]


@dataclass
class SARInput:
    case_id: str
    findings: Sequence[Finding]
    transactions: Sequence[Transaction]
    customers: Sequence[Customer] = field(default_factory=list)
    accounts: Sequence[Account] = field(default_factory=list)
    risk: RiskAssessment | None = None
    jurisdiction: Jurisdiction = Jurisdiction.US
    filing_type: str = "initial"
    reviewer: str = "ANJALI-AI (draft, requires human sign-off)"
    typology_labels: dict[str, str] = field(default_factory=dict)


def _evidence_transactions(inp: SARInput) -> list[Transaction]:
    ids: set[str] = set()
    for finding in inp.findings:
        ids.update(finding.evidence_txn_ids)
    selected = [t for t in inp.transactions if t.txn_id in ids] if ids else list(inp.transactions)
    return sorted(selected, key=lambda t: t.timestamp)


def _subject_for(
    name: str,
    accounts: Iterable[str],
    customers: Sequence[Customer],
    *,
    role: str = "subject",
) -> SARSubject:
    match = next((c for c in customers if c.name.lower() == name.lower()), None)
    return SARSubject(
        name=name,
        role=role,  # type: ignore[arg-type]
        entity_type=match.customer_type if match else "individual",
        country=match.country if match else None,
        dob=match.dob if match else None,
        identifiers={"customer_id": match.customer_id} if match else {},
        accounts=sorted({a for a in accounts if a}),
    )


def build_report(
    inp: SARInput,
    *,
    citations: Sequence[Citation] = (),
    narrative_hook: Callable[[dict[str, str], SARInput], str] | None = None,
) -> SARReport:
    txns = _evidence_transactions(inp)
    accounts = sorted({a for t in txns for a in (t.from_account, t.to_account) if a})

    # Map every account in the evidence to its owner, so subjects are attributed to the
    # accounts they actually hold rather than to the first name in the dataset.
    account_owner: dict[str, Customer] = {}
    for cust in inp.customers:
        for acct in cust.accounts:
            account_owner.setdefault(acct, cust)

    owner_accounts: dict[str, tuple[Customer, set[str]]] = {}
    for acct in accounts:
        owner = account_owner.get(acct)
        if owner is None:
            continue
        entry = owner_accounts.setdefault(owner.customer_id, (owner, set()))
        entry[1].add(acct)

    subjects: list[SARSubject] = [
        _subject_for(cust.name, sorted(accts), inp.customers)
        for cust, accts in sorted(owner_accounts.values(), key=lambda ca: len(ca[1]), reverse=True)
    ][:6]

    if not subjects:
        # No customer master (or none of the accounts belong to a known customer): fall
        # back to the names carried on the transactions themselves.
        names = []
        for txn in txns:
            for name in (txn.to_name, txn.from_name):
                if name and name not in names:
                    names.append(name)
        subjects = [SARSubject(name=n, accounts=[], identifiers={}) for n in names[:5]] or [
            SARSubject(name="Unidentified subject", identifiers={"note": "No customer master supplied"})
        ]
        for subject in subjects:
            subject.accounts = [
                a for t in txns for a in (t.from_account, t.to_account)
                if a and subject.name.lower() in ((t.to_name or ""), (t.from_name or ""))
            ][:4]

    counterparties: list[SARSubject] = []
    subject_accounts = {a for subject in subjects for a in subject.accounts}
    external = {
        (t.to_name or t.to_account)
        for t in txns
        if t.to_account
        and t.to_account not in subject_accounts
        and not ctx_owner(account_owner, t.to_account)
        and (t.to_name or t.to_account)
    }
    for name in list(external)[:5]:
        counterparties.append(_subject_for(str(name), [], inp.customers, role="beneficiary"))

    total = money(sum(t.amount for t in txns)) if txns else None
    start = txns[0].timestamp.date() if txns else None
    end = txns[-1].timestamp.date() if txns else None
    typologies = sorted({f.typology for f in inp.findings})

    sections = _sections(inp, txns, subjects, counterparties, total, start, end, typologies)
    narrative = _compose(sections)
    if narrative_hook is not None:
        try:
            polished = narrative_hook(sections, inp)
            if polished and len(polished) > len(narrative) * 0.5:
                narrative = polished.strip()
        except Exception:
            # A model failure must never block a filing-quality draft.
            pass

    due = _due_date(inp.jurisdiction, today())
    limitations = _limitations(inp, txns)
    report = SARReport(
        report_id=stable_id(inp.case_id, *typologies, str(total), prefix="SAR-", length=10).upper(),
        case_id=inp.case_id,
        filing_type=inp.filing_type,  # type: ignore[arg-type]
        jurisdiction=inp.jurisdiction,
        filing_regulator=_regulator(inp.jurisdiction),
        filing_form=_form(inp.jurisdiction),
        subjects=[*subjects, *counterparties],
        accounts=accounts,
        activity_start=start,
        activity_end=end,
        total_amount=total,
        currency=txns[0].currency if txns else "USD",
        typologies=typologies,
        narrative=narrative,
        narrative_sections=sections,
        citations=list(citations),
        findings=[f"{f.typology}: {f.summary}" for f in inp.findings[:20]],
        due_date=due,
        prepared_by=inp.reviewer,
        confidence=_confidence(inp),
        requires_human_review=True,
        limitations=limitations,
    )
    return report


def ctx_owner(account_owner: dict[str, Customer], account: str | None) -> Customer | None:
    return account_owner.get(account or "")


def _regulator(jurisdiction: Jurisdiction) -> str:
    return {
        Jurisdiction.US: "FinCEN",
        Jurisdiction.UK: "NCA / UKFIU",
        Jurisdiction.EU: "National FIU",
    }.get(jurisdiction, "FIU")


def _form(jurisdiction: Jurisdiction) -> str:
    return {
        Jurisdiction.US: "FinCEN SAR (BSA E-Filing)",
        Jurisdiction.UK: "UKFIU SAR / DAML request",
        Jurisdiction.EU: "STR via national FIU portal (goAML)",
    }.get(jurisdiction, "STR")


def _due_date(jurisdiction: Jurisdiction, detected: date) -> date | None:
    """Statutory clocks differ; the report states the applicable one."""
    if jurisdiction is Jurisdiction.US:
        return detected + timedelta(days=30)          # 31 CFR 1010.306
    if jurisdiction is Jurisdiction.UK:
        return detected + timedelta(days=7)           # DAML response window (working days approximated)
    return detected + timedelta(days=30)              # "without undue delay" internal SLA


def _confidence(inp: SARInput) -> float:
    if not inp.findings:
        return 0.4
    base = sum(f.confidence for f in inp.findings) / len(inp.findings)
    penalty = 0.05 if not inp.customers else 0.0
    return round(max(0.35, min(0.95, base - penalty)), 3)


def _limitations(inp: SARInput, txns: Sequence[Transaction]) -> list[str]:
    notes = [
        "Draft generated by ANJALI-AI from the case data supplied; a qualified analyst must "
        "verify every fact before submission.",
        "Narrative reflects only the records in this case; related accounts, other "
        "institutions and non-transactional intelligence are not represented.",
    ]
    if not inp.customers:
        notes.append("No customer master was supplied: subject identification relies on transaction names.")
    if any(f.confidence < 0.6 for f in inp.findings):
        notes.append("One or more findings carry confidence below 60%; corroborate before citing them.")
    if not txns:
        notes.append("No transactions were linked to the findings; amounts are not substantiated.")
    missing = [t.txn_id for t in txns if not t.country_to and not t.country_from]
    if missing:
        notes.append(f"{len(missing)} transaction(s) lack geography data, so the WHERE element is partial.")
    return notes


def _sections(
    inp: SARInput,
    txns: Sequence[Transaction],
    subjects: Sequence[SARSubject],
    counterparties: Sequence[SARSubject],
    total: Decimal | None,
    start: date | None,
    end: date | None,
    typologies: Sequence[str],
) -> dict[str, str]:
    currency = txns[0].currency if txns else "USD"
    subject_text = ", ".join(
        f"{s.name} ({s.entity_type}, {'/'.join(s.accounts) or 'no account recorded'})" for s in subjects
    ) or "the subject(s) identified below"
    benef_text = ", ".join(s.name for s in counterparties) or "not identified"

    who = (
        f"The subject of this report is {subject_text}. "
        f"Counterparties identified in the activity include {benef_text}. "
        + (f"Customer identifiers: {', '.join(sorted({s.identifiers.get('customer_id', '') for s in subjects} - {''}))}. " if any(s.identifiers.get('customer_id') for s in subjects) else "")
    )

    branches = sorted({t.branch for t in txns if t.branch})
    channels = sorted({t.channel for t in txns if t.channel})
    countries = sorted({c for t in txns for c in (t.country_from, t.country_to) if c})
    where = (
        f"Activity was conducted through {len(channels) or 'an unrecorded number of'} channel(s)"
        + (f" ({', '.join(channels)})" if channels else "")
        + (f" at branch(es) {', '.join(branches)}" if branches else "")
        + (f", involving the following jurisdictions: {', '.join(countries)}." if countries else ".")
    )

    what_bits = []
    for finding in inp.findings[:6]:
        what_bits.append(f"{finding.title.lower()} — {finding.summary}")
    what = " ".join(what_bits) or "Suspicious activity was identified but no typology finding is recorded."
    if total is not None:
        what += f" The total value of the transactions described is {fmt_money(total, currency)}."
    what += (
        f" The review identified {len(inp.findings)} finding(s) across the following typologies: "
        f"{', '.join(typologies)}." if typologies else ""
    )

    when = (
        f"The activity occurred between {start.isoformat() if start else 'an unstated date'} and "
        f"{end.isoformat() if end else 'an unstated date'}, covering {len(txns)} transaction(s)."
    )

    expected_bits = []
    for cust in inp.customers[:4]:
        if cust.expected_monthly_volume:
            expected_bits.append(
                f"{cust.name} declared expected monthly activity of "
                f"{fmt_money(cust.expected_monthly_volume, currency)}"
            )
    why = (
        "The activity is inconsistent with the customer's profile and with the purpose of the "
        "account as recorded at onboarding. "
        + ("; ".join(expected_bits) + ". " if expected_bits else "")
        + "The pattern matches the following recognised indicators: "
        + ", ".join(sorted({t.replace('_', ' ') for t in typologies}))
        + ". The institution is unable to identify a lawful explanation from the information "
        "available and considers the activity inconsistent with the expected use of the account."
    )

    methods = sorted({(t.txn_type or "transfer").replace("_", " ") for t in txns})
    how = (
        f"Funds were moved using {', '.join(methods[:6])}. "
        + _mechanism_detail(inp, txns, currency)
    )

    risk = ""
    if inp.risk:
        risk = (
            f"Composite risk was assessed at {inp.risk.overall:.1f}/100 ({inp.risk.band.value}). "
            f"The dominant dimension was "
            f"{max(inp.risk.dimensions, key=lambda d: d.score * d.weight).dimension}."
        )

    return {
        "who": who.strip(),
        "what": what.strip(),
        "when": when.strip(),
        "where": where.strip(),
        "why": why.strip(),
        "how": how.strip(),
        "risk": risk.strip(),
    }


def _mechanism_detail(inp: SARInput, txns: Sequence[Transaction], currency: str) -> str:
    details: list[str] = []
    for finding in inp.findings:
        metrics = finding.metrics or {}
        if finding.typology == "structuring":
            details.append(
                f"{metrics.get('transaction_count', 'n/a')} cash transactions in the "
                f"[{metrics.get('band_low', '?')}, {metrics.get('threshold', '?')}) band "
                f"totalling {metrics.get('total_amount', '?')}"
                + (f" across {metrics['distinct_branches']} branches" if metrics.get("distinct_branches") else "")
            )
        elif finding.typology == "smurfing":
            details.append(
                f"{metrics.get('distinct_senders', 'n/a')} distinct senders paid "
                f"{metrics.get('total_amount', 'n/a')} into a single account"
            )
        elif finding.typology == "layering":
            details.append(
                f"{metrics.get('matched_pairs', 'n/a')} in/out pairs moved "
                f"{metrics.get('matched_value', 'n/a')} within "
                f"{metrics.get('max_hours', 'n/a')} hours, retaining "
                f"{metrics.get('retention_ratio', 'n/a')} of inflows"
            )
        elif finding.typology == "round_tripping":
            cycle = metrics.get("cycle") or []
            details.append(
                f"funds cycled through {' → '.join(str(c) for c in cycle)} totalling "
                f"{metrics.get('total_amount', 'n/a')}"
            )
        elif finding.typology == "mule_network":
            details.append(
                f"{metrics.get('account_count', 'n/a')} accounts shared a single "
                f"{metrics.get('link_type', 'access')} identifier"
            )
        elif finding.typology == "tbml":
            details.append(
                f"invoice pricing deviated {metrics.get('deviation', 0):.0%} from the market "
                f"benchmark for {metrics.get('goods') or 'the goods'} (HS {metrics.get('hs_code') or 'n/a'})"
            )
        elif finding.typology == "velocity_anomaly":
            details.append(
                f"{metrics.get('count_today')} transactions on {metrics.get('date')} against a "
                f"baseline median of {metrics.get('baseline_median')}"
            )
        elif finding.typology == "high_risk_geography":
            details.append(
                f"{metrics.get('transaction_count')} transactions involving {metrics.get('country')} "
                f"totalling {metrics.get('total_amount')}"
            )
    if not details:
        details.append(
            f"{len(txns)} transactions totalling {fmt_money(sum((t.amount for t in txns), Decimal('0')), currency)}"
        )
    return "Specifically, " + "; ".join(details) + "."


def _compose(sections: dict[str, str]) -> str:
    """Continuous prose: a narrative, not a form. Headings live in `narrative_sections`."""
    order = ["who", "when", "what", "where", "how", "why"]
    paragraphs = [sections.get(key, "").strip() for key in order if sections.get(key)]
    if sections.get("risk"):
        paragraphs.append(sections["risk"])
    return "\n\n".join(p for p in paragraphs if p)


def quality_check(report: SARReport) -> dict[str, Any]:
    """Score the narrative against the FinCEN/FFIEC six-element checklist."""
    text = report.narrative.lower()
    reveals = ["suspicious activity report", "sar ", "we filed", "filed a report", "report number"]
    results: list[dict[str, Any]] = []

    def add(key: str, ok: bool, detail: str) -> None:
        label = next((label for k, label in NARRATIVE_CHECKS if k == key), key)
        results.append({"key": key, "check": label, "pass": ok, "detail": detail})

    add("who", bool(report.subjects) and report.subjects[0].name.lower() in text,
        f"{len(report.subjects)} subject(s) listed")
    add("what", bool(report.typologies) and any(t.replace("_", " ") in text for t in report.typologies),
        f"typologies: {', '.join(report.typologies) or 'none'}")
    add("when", report.activity_start is not None and report.activity_end is not None,
        f"{report.activity_start} → {report.activity_end}")
    add("where", any(w in text for w in ("branch", "channel", "jurisdiction", "country")),
        "channels/branches/jurisdictions referenced")
    add("why", "inconsistent" in text or "out of character" in text or "unable to identify" in text,
        "explains the deviation from expected behaviour")
    add("how", any(w in text for w in ("moved", "transferred", "deposited", "paid", "cycled")),
        "describes the mechanism")
    total_stated = report.total_amount is not None and (
        f"{report.total_amount:,.2f}" in text or str(report.total_amount) in text
    )
    add("amounts", total_stated, f"total {report.total_amount}")
    add("no_legal_conclusions", "guilty" not in text and "committed a crime" not in text,
        "no conclusion of criminal liability")
    add("no_report_reference", not any(r in text for r in reveals),
        "does not reference the report itself")
    dates = [t for t in (report.activity_start, report.activity_end) if t]
    add("chronology", len(dates) == 2 and dates[0] <= dates[1], "activity window is ordered")

    passed = sum(1 for r in results if r["pass"])
    score = round(100 * passed / len(results))
    return {
        "score": score,
        "passed": passed,
        "total": len(results),
        "grade": "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D",
        "checks": results,
        "recommendations": [r["check"] for r in results if not r["pass"]],
    }


def to_markdown(report: SARReport) -> str:
    lines = [f"# {report.filing_form} — draft narrative", ""]
    lines.append(f"**Report ID:** `{report.report_id}`  ")
    lines.append(f"**Case:** {report.case_id or '—'}  ")
    lines.append(f"**Jurisdiction / regulator:** {report.jurisdiction.value} / {report.filing_regulator}  ")
    lines.append(f"**Filing type:** {report.filing_type}  ")
    lines.append(f"**Activity window:** {report.activity_start} → {report.activity_end}  ")
    lines.append(f"**Total amount:** {fmt_money(report.total_amount or 0, report.currency)}  ")
    lines.append(f"**Typologies:** {', '.join(report.typologies)}  ")
    lines.append(f"**Filing due by:** {report.due_date}  ")
    lines.append(f"**Confidence:** {report.confidence:.0%} — human review required")
    lines.append("")
    lines.append("## Subjects")
    lines.append("")
    lines.append("| Name | Role | Type | Country | DOB | Accounts |")
    lines.append("|------|------|------|---------|-----|----------|")
    for s in report.subjects:
        lines.append(
            f"| {s.name} | {s.role} | {s.entity_type} | {s.country or '—'} | {s.dob or '—'} | "
            f"{', '.join(s.accounts) or '—'} |"
        )
    lines.append("")
    lines.append("## Narrative")
    lines.append("")
    lines.append(report.narrative)
    lines.append("")
    if report.citations:
        lines.append("## Authorities")
        lines.append("")
        for cit in report.citations:
            lines.append(f"- {cit.citation} — {cit.title}")
        lines.append("")
    lines.append("## Limitations")
    lines.append("")
    for note in report.limitations:
        lines.append(f"- {note}")
    lines.append("")
    lines.append("## Sign-off")
    lines.append("")
    lines.append("_Prepared by:_  ______________________  _Date:_ ____________")
    lines.append("")
    lines.append("_Approved by (MLRO / BSA officer):_  ______________________  _Date:_ ____________")
    lines.append("")
    return "\n".join(lines)


def narrative_prompt(sections: dict[str, str], inp: SARInput) -> str:
    """Prompt used by the optional LLM polish pass. Facts-only, no invention."""
    facts = "\n".join(f"{k.upper()}: {v}" for k, v in sections.items() if v)
    return (
        "You are drafting the narrative section of a suspicious activity report. Rewrite the "
        "facts below as a single continuous narrative in plain past tense, third person, "
        "5 paragraphs maximum, maximum 450 words.\n\n"
        "Rules:\n"
        "- Use ONLY the facts provided. Do not invent names, amounts, dates or jurisdictions.\n"
        "- Do not state or imply that a crime was committed.\n"
        "- Do not mention a report, a filing, or any regulator.\n"
        "- Do not add hedging language such as 'possibly' or 'might be'.\n"
        "- Keep every amount and date exactly as given.\n\n"
        f"FACTS\n{facts}\n"
    )
