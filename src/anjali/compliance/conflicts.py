"""Cross-jurisdiction conflict resolver.

Multi-jurisdiction compliance programmes fail in a specific, predictable way: two
regulators require incompatible things and nobody notices until an examination. The
classic case is SAR confidentiality — EU and UK law expect a group compliance function to
see suspicious-activity reports across the group; US law forbids telling anyone involved,
including a foreign parent.

This module encodes the conflicts as first-class data, with the provision on each side,
the practical divergence, and a resolution that has been adopted in practice. It is
decision support, not legal advice — every memo says so, and every position links to the
corpus so the reader can go straight to the source.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from anjali.core.models import Severity
from anjali.core.util import truncate

CONFIDENCE_NOTE = (
    "This analysis is decision support for compliance professionals, not legal advice. "
    "Confirm with counsel in each jurisdiction before changing a control."
)


@dataclass
class Position:
    jurisdiction: str
    rule: str
    doc_ids: list[str]
    practical_effect: str


@dataclass
class Conflict:
    id: str
    title: str
    topic: str
    summary: str
    severity: Severity
    positions: list[Position]
    divergence: str
    resolution: list[str]
    tags: list[str] = field(default_factory=list)
    confidence: float = 0.8
    trigger_typologies: list[str] = field(default_factory=list)

    @property
    def jurisdictions(self) -> list[str]:
        return sorted({p.jurisdiction for p in self.positions})


CONFLICTS: list[Conflict] = [
    Conflict(
        id="sar-group-disclosure",
        title="SAR confidentiality vs intra-group disclosure",
        topic="Suspicious activity reporting",
        summary=(
            "US law prohibits disclosing a suspicious activity report to any person involved in "
            "the transaction, with no intra-group carve-out. EU and UK law permit — and in "
            "practice expect — disclosure within the group so that group compliance can manage "
            "the relationship. A US-licensed subsidiary of an EU or UK group cannot satisfy both."
        ),
        severity=Severity.CRITICAL,
        positions=[
            Position(
                jurisdiction="US",
                rule=(
                    "31 USC 5318(g)(2) prohibits a financial institution or any director, "
                    "officer, employee or agent from notifying any person involved in the "
                    "transaction that it was reported. Permitted recipients are FinCEN, law "
                    "enforcement and supervisors; 314(b) sharing applies only to non-affiliated "
                    "registered institutions."
                ),
                doc_ids=["us-31usc-5318g2", "us-31cfr-1010-540"],
                practical_effect=(
                    "Sharing the SAR narrative with a foreign parent is a disclosure violation "
                    "even where the parent is the consolidated supervisor's regulated entity."
                ),
            ),
            Position(
                jurisdiction="UK",
                rule=(
                    "POCA 2002 s333A prohibits prejudicial disclosure, but s333B and the MLRs "
                    "permit disclosure within the same undertaking and to group undertakings for "
                    "the purpose of preventing or detecting money laundering."
                ),
                doc_ids=["uk-poca-s333a", "uk-mlr-2017-reg18-19"],
                practical_effect=(
                    "Group MLRO and group financial-crime functions may lawfully receive the "
                    "report; withholding it may itself breach group policy and the MLR "
                    "risk-management obligation."
                ),
            ),
            Position(
                jurisdiction="EU",
                rule=(
                    "The EU framework permits group-wide information sharing necessary for AML/CFT "
                    "purposes, subject to confidentiality safeguards; AMLD6 and the AMLR restate "
                    "this for the post-2027 regime."
                ),
                doc_ids=["eu-fiu-reports", "eu-amld6-2024-1640"],
                practical_effect=(
                    "Group compliance is expected to have visibility of STRs across the group; "
                    "the EU parent's own supervisor may treat an information barrier as a control "
                    "weakness."
                ),
            ),
        ],
        divergence=(
            "The US regulates the *recipient* of the disclosure (anyone involved), while the EU "
            "and UK regulate the *effect* of the disclosure (prejudicing an investigation) and "
            "carve out the group. The same act is lawful for the EU/UK entity and unlawful for "
            "the US entity."
        ),
        resolution=[
            "Document a jurisdictional split in the group AML policy: define which entity may "
            "share what, with whom, and on what legal basis.",
            "Route group-level SAR visibility through a separately incorporated non-US "
            "compliance function with its own access controls; do not give the US entity's "
            "staff access to non-US SARs.",
            "For non-affiliated institutions, use the 314(b) safe harbour (both parties "
            "registered) rather than informal sharing.",
            "Log every cross-border disclosure decision in the audit trail, including the "
            "legal basis relied on, so the institution can evidence that it did not disclose "
            "impermissibly.",
            "If the group structure makes separation impossible, escalate to counsel for a "
            "formal opinion and consider whether the US licence is the right operating model.",
        ],
        tags=["sar", "confidentiality", "tipping-off", "group", "cross-border"],
        confidence=0.9,
        trigger_typologies=["structuring", "smurfing", "layering"],
    ),
    Conflict(
        id="tipping-off-scope",
        title="Tipping-off: flat prohibition vs permitted disclosures",
        topic="Suspicious activity reporting",
        summary=(
            "The US prohibition on notifying a subject is close to absolute. The UK and EU "
            "regimes prohibit only disclosure likely to prejudice an investigation, and permit "
            "specific disclosures — including to prevent an offence and, in the UK, within the "
            "same undertaking."
        ),
        severity=Severity.HIGH,
        positions=[
            Position(
                jurisdiction="US",
                rule="31 USC 5318(g)(2) — no notification to any person involved in the transaction.",
                doc_ids=["us-31usc-5318g2"],
                practical_effect="Even confirming to a customer that a review 'has been escalated' is risky.",
            ),
            Position(
                jurisdiction="UK",
                rule=(
                    "POCA 2002 s333A offence requires that the disclosure is likely to prejudice "
                    "an investigation; s333B permits disclosures for the purpose of preventing "
                    "an offence and within the same undertaking/group."
                ),
                doc_ids=["uk-poca-s333a"],
                practical_effect=(
                    "A firm may decline a transaction and tell the customer that it is exercising "
                    "its own commercial discretion, provided it does not reveal the report."
                ),
            ),
            Position(
                jurisdiction="EU",
                rule="AMLR/AMLD prohibit disclosure to the customer or third parties; internal and group reporting is required.",
                doc_ids=["eu-fiu-reports", "eu-amld6-2024-1640"],
                practical_effect="Internal escalation is mandatory and must not be delayed by confidentiality concerns.",
            ),
        ],
        divergence=(
            "The US rule targets the act of notification; the UK rule targets the risk of "
            "prejudice. A statement that is harmless in London can be a violation in New York."
        ),
        resolution=[
            "Adopt the strictest standard globally in customer-facing scripts: never confirm, "
            "deny or discuss reporting.",
            "Train front-line staff on the US standard for any customer with a US nexus.",
            "Use a neutral exit rationale ('commercial decision', 'account terms') that is "
            "documented internally and discloses nothing.",
            "Keep internal escalation completely separate from customer communications.",
        ],
        tags=["tipping-off", "disclosure", "sar", "customer-communication"],
        confidence=0.85,
        trigger_typologies=["structuring", "smurfing"],
    ),
    Conflict(
        id="ownership-50-percent-control",
        title="Sanctions ownership: 50% rule vs ownership-and-control test",
        topic="Sanctions",
        summary=(
            "The US treats an entity as blocked when designated persons own 50% or more in "
            "aggregate, with no control prong. The EU and UK apply an ownership-or-control test "
            "that can catch entities below 50% through board or decisive influence, and treats "
            "the 50% figure as a rebuttable presumption."
        ),
        severity=Severity.CRITICAL,
        positions=[
            Position(
                jurisdiction="US",
                rule="OFAC 50 Percent Rule: aggregate direct and indirect ownership of 50% or more by one or more blocked persons blocks the entity by operation of law.",
                doc_ids=["us-ofac-50-percent-rule", "us-31cfr-501-603"],
                practical_effect="A 60%-owned unnamed subsidiary is blocked; no control analysis is needed or permitted.",
            ),
            Position(
                jurisdiction="EU",
                rule="EU guidance and CJEU case law: ownership above 50% raises a rebuttable presumption; control below 50% can suffice.",
                doc_ids=["eu-sanctions-ownership-control"],
                practical_effect="A 45%-owned entity with board control may be caught; a 55%-owned entity may argue the presumption is rebutted.",
            ),
            Position(
                jurisdiction="UK",
                rule="OFSI: 'owned or controlled' includes >50% shares/votes, board appointment rights, or otherwise controlling the entity.",
                doc_ids=["uk-oFSI-sanctions"],
                practical_effect="Similar to the EU but with UK-specific guidance and no aggregation rule identical to the US.",
            ),
        ],
        divergence=(
            "Below 50% the EU/UK tests are broader; above 50% the US test is stricter because it "
            "is automatic and aggregates holdings. Neither test is a subset of the other."
        ),
        resolution=[
            "Apply the union of the tests: block where any jurisdiction's test is met.",
            "Record which test drove the decision and the ownership evidence relied on.",
            "Maintain an ownership graph with effective-dated percentages so a change in "
            "holding is reflected without re-running onboarding.",
            "For a 40–50% holding, document the control analysis (board rights, voting "
            "agreements, financing) rather than relying on the percentage alone.",
            "Where the US test blocks and a customer disputes it, do not unblock pending legal "
            "advice — OFAC liability is strict and blocking is reversible; a prohibited "
            "transfer is not.",
        ],
        tags=["sanctions", "ownership", "control", "50-percent", "blocking"],
        confidence=0.9,
        trigger_typologies=["high_risk_geography"],
    ),
    Conflict(
        id="travel-rule-thresholds",
        title="Travel rule: three different thresholds and scopes",
        topic="Payments",
        summary=(
            "The FATF baseline is USD/EUR 1,000. The US applies $3,000 to covered transmittals. "
            "The EU applies zero threshold to CASP-to-CASP crypto transfers from 30 December "
            "2024 and requires self-hosted-wallet verification above €1,000. One global constant "
            "cannot satisfy all three."
        ),
        severity=Severity.HIGH,
        positions=[
            Position(
                jurisdiction="FATF",
                rule="Recommendation 16: USD/EUR 1,000 threshold for cross-border transfers; information must travel with the payment.",
                doc_ids=["fatf-r16-travel"],
                practical_effect="The floor below which a scheme may simplify; not a ceiling.",
            ),
            Position(
                jurisdiction="US",
                rule="31 CFR 1010.410(f): $3,000 for transmittals of funds, extended to CVC transmittals by money transmitters.",
                doc_ids=["us-31cfr-1010-410-f", "us-31cfr-1010-410-e"],
                practical_effect="A $2,500 CVC transfer needs records but not transmitted originator data under the US rule.",
            ),
            Position(
                jurisdiction="EU",
                rule="Regulation (EU) 2023/1113: no de-minimis threshold for CASP-to-CASP transfers; verify self-hosted-wallet control above €1,000.",
                doc_ids=["eu-tfr-2023-1113"],
                practical_effect="The same $2,500 CVC transfer requires full originator/beneficiary data if either leg is in the EU.",
            ),
        ],
        divergence=(
            "Threshold, currency and scope all differ: the EU covers crypto without a threshold "
            "for CASPs, the US uses a dollar figure on transmittals, and FATF sets the "
            "international baseline."
        ),
        resolution=[
            "Implement the rule as a per-corridor policy object with effective dates, not a "
            "global constant.",
            "Apply the strictest applicable threshold to each payment based on the "
            "jurisdictions of the ordering, intermediary and beneficiary institutions.",
            "Record which regime required the data so a supervisor can see the basis.",
            "Currency-convert at the transaction date, and store the rate used.",
        ],
        tags=["travel-rule", "crypto", "payments", "threshold", "cross-border"],
        confidence=0.85,
        trigger_typologies=["threshold_avoidance"],
    ),
    Conflict(
        id="retention-vs-gdpr",
        title="Five-year AML retention vs GDPR storage limitation",
        topic="Data protection",
        summary=(
            "BSA, MLR and AMLD require retention of CDD and transaction records for five years. "
            "GDPR Article 5(1)(e) requires that personal data not be kept longer than necessary. "
            "The tension is resolved by legal obligation, not by shortening retention."
        ),
        severity=Severity.HIGH,
        positions=[
            Position(
                jurisdiction="US",
                rule="31 CFR 1010.430: five years; account-opening records five years after closure.",
                doc_ids=["us-31cfr-1010-430"],
                practical_effect="Deleting on a shorter privacy schedule is a BSA violation.",
            ),
            Position(
                jurisdiction="EU",
                rule="AMLD/AMLR: five years after the end of the relationship or transaction; GDPR Art 5(1)(e), 6(1)(c), 17(3)(b).",
                doc_ids=["eu-amlr-2024-1624", "eu-gdpr-art5", "eu-gdpr-art17"],
                practical_effect="Retention is lawful for the mandated period and unlawful beyond it absent another basis.",
            ),
            Position(
                jurisdiction="UK",
                rule="MLR 2017 reg. 40: five years after the relationship ends; UK GDPR legal-obligation basis.",
                doc_ids=["uk-mlr-2017-reg40"],
                practical_effect="ICO/FCA expect deletion at expiry, with legal-hold logic for investigations.",
            ),
        ],
        divergence=(
            "The conflict is temporal, not substantive: both regimes accept legal obligation as "
            "the basis, but privacy schedules and AML schedules are set by different teams and "
            "rarely reconciled."
        ),
        resolution=[
            "Maintain one retention schedule, owned jointly by financial crime and privacy.",
            "Tag each record class with its statutory retention period and legal basis.",
            "Enforce deletion in code at expiry, with a documented legal-hold override.",
            "Answer erasure requests with a partial response: delete non-mandatory data, retain "
            "the AML record, and record the assessment.",
            "Do not use consent as the basis for AML processing — it is revocable and therefore "
            "incompatible with a statutory duty.",
        ],
        tags=["gdpr", "retention", "records", "privacy"],
        confidence=0.9,
        trigger_typologies=[],
    ),
    Conflict(
        id="dsar-vs-sar-confidentiality",
        title="Data subject access vs SAR confidentiality",
        topic="Data protection",
        summary=(
            "A customer who is the subject of a suspicious activity report may request access to "
            "their data. The US has no such right and prohibits disclosure of the report. The EU "
            "and UK grant access rights but provide AML-specific restrictions. Answering naively "
            "either breaches the SAR prohibition or the access right."
        ),
        severity=Severity.HIGH,
        positions=[
            Position(
                jurisdiction="US",
                rule="No general data-subject access right; 31 USC 5318(g)(2) prohibits confirming a SAR.",
                doc_ids=["us-31usc-5318g2"],
                practical_effect="Respond to the request as an ordinary customer enquiry without confirming any filing.",
            ),
            Position(
                jurisdiction="EU",
                rule="GDPR Art 15 access right, subject to member-state restrictions under Art 23 for criminal-offence prevention.",
                doc_ids=["eu-gdpr-art15-23"],
                practical_effect="A partial response is required, with the restriction documented.",
            ),
            Position(
                jurisdiction="UK",
                rule="UK GDPR Art 15 with the DPA 2018 Sch 2 para 16 exemption for AML/regulatory functions.",
                doc_ids=["eu-gdpr-art15-23", "uk-mlr-2017-reg40"],
                practical_effect="The exemption is applied and documented; a blanket refusal is not acceptable.",
            ),
        ],
        divergence=(
            "The US protects the report absolutely; the EU and UK protect it through a "
            "proportionate restriction, which requires a documented assessment rather than a "
            "refusal."
        ),
        resolution=[
            "Route DSARs involving a SAR subject to a specialist team, never to front-line staff.",
            "Provide the transaction data that is not restricted; withhold the report and the "
            "fact of it, citing the restriction.",
            "Record the restriction assessment, the provisions relied on, and the reviewer.",
            "Ensure the DSAR response cannot be correlated with the SAR timeline by the customer.",
        ],
        tags=["gdpr", "dsar", "sar", "confidentiality"],
        confidence=0.85,
        trigger_typologies=["structuring", "smurfing"],
    ),
    Conflict(
        id="filing-deadlines",
        title="SAR filing deadlines and consent clocks",
        topic="Suspicious activity reporting",
        summary=(
            "The US imposes a hard 30-day clock from initial detection. The UK has no statutory "
            "filing deadline but requires internal disclosure 'as soon as practicable' and runs a "
            "seven-working-day consent (DAML) clock. The EU requires reporting 'without undue "
            "delay'. A single global SLA will be wrong somewhere."
        ),
        severity=Severity.HIGH,
        positions=[
            Position(
                jurisdiction="US",
                rule="31 CFR 1010.306 / 1020.320: 30 calendar days from initial detection, 60 where no suspect, continuing SARs every 120 days.",
                doc_ids=["us-31cfr-1010-306", "us-31cfr-1020-320", "us-sar-continuing"],
                practical_effect="Long internal review cycles are treated as late filing.",
            ),
            Position(
                jurisdiction="UK",
                rule="POCA s330: internal disclosure as soon as practicable; UKFIU DAML response within 7 working days, extendable by up to 31 calendar days.",
                doc_ids=["uk-sars-nca", "uk-poca-s330", "uk-ta-2000-s21a"],
                practical_effect="The consent clock, not the filing clock, drives operational urgency.",
            ),
            Position(
                jurisdiction="EU",
                rule="AMLR: report to the FIU without undue delay; no fixed statutory period.",
                doc_ids=["eu-fiu-reports", "eu-amlr-2024-1624"],
                practical_effect="'Without undue delay' is assessed against the institution's own documented process.",
            ),
        ],
        divergence=(
            "The US measures from detection, the UK from the point the consent is needed, and "
            "the EU by reference to reasonableness. Systems that track one clock miss the others."
        ),
        resolution=[
            "Start the clock at alert acknowledgement and record the timestamp immutably.",
            "Tag each alert with the jurisdictions whose clocks apply.",
            "Track the DAML seven-working-day response window separately from the SAR filing clock.",
            "Report the 120-day continuing-activity review as a scheduled control, not a reminder.",
        ],
        tags=["deadline", "sar", "daml", "filing"],
        confidence=0.85,
        trigger_typologies=["structuring", "smurfing", "layering"],
    ),
    Conflict(
        id="pep-domestic-scope",
        title="PEP scope: foreign-only vs including domestic PEPs",
        topic="Customer due diligence",
        summary=(
            "The US BSA's mandatory PEP provisions focus on senior foreign political figures. "
            "FATF, the EU and the UK require domestic PEPs to be identified and risk-managed "
            "too. A single PEP list with a single mandatory-EDD rule is either over- or "
            "under-inclusive depending on the jurisdiction."
        ),
        severity=Severity.MEDIUM,
        positions=[
            Position(
                jurisdiction="US",
                rule="31 CFR 1010.620 and FFIEC guidance: mandatory EDD for senior foreign political figures; domestic PEPs are risk-based, not mandatory.",
                doc_ids=["us-ffiec-edd-pep"],
                practical_effect="A domestic PEP does not automatically require EDD or senior-management approval.",
            ),
            Position(
                jurisdiction="EU",
                rule="AMLD5: domestic PEPs are PEPs; member states may apply lower-risk measures under specified conditions, but identification is required.",
                doc_ids=["eu-amld5-2018-843", "fatf-r12-pep"],
                practical_effect="Domestic PEPs must be identified, screened and risk-managed.",
            ),
            Position(
                jurisdiction="UK",
                rule="MLR 2017 reg. 35: PEPs include domestic PEPs; EDD with senior-management approval is required.",
                doc_ids=["uk-mlr-2017-reg28"],
                practical_effect="Senior management approval is mandatory, not risk-based discretion.",
            ),
        ],
        divergence=(
            "Mandatory EDD attaches to foreign PEPs everywhere, but to domestic PEPs only in "
            "the EU/UK. Applying the US rule globally under-controls; applying the EU rule "
            "globally over-controls US-only relationships."
        ),
        resolution=[
            "Classify PEPs as foreign, domestic or international-organisation, and store the "
            "classification with the source and date.",
            "Drive the EDD requirement from the classification and the jurisdictions in scope, "
            "not from a single boolean.",
            "Re-screen on a schedule and when a customer takes public office.",
            "Record senior-management approval where required, with the approver's identity.",
        ],
        tags=["pep", "cdd", "edd", "jurisdiction"],
        confidence=0.85,
        trigger_typologies=["cash_intensity"],
    ),
    Conflict(
        id="secondary-sanctions-blocking",
        title="US secondary sanctions vs the EU Blocking Statute",
        topic="Sanctions",
        summary=(
            "US secondary sanctions can reach non-US persons for conduct outside the US. The EU "
            "Blocking Statute prohibits EU operators from complying with specified US measures "
            "and permits compliance only with an authorisation. Following the US instruction can "
            "breach EU law, and vice versa."
        ),
        severity=Severity.CRITICAL,
        positions=[
            Position(
                jurisdiction="US",
                rule="IEEPA 50 USC 1705 plus programme regulations: causing a violation and secondary sanctions exposure for non-US persons.",
                doc_ids=["us-ieepa-1705", "us-ofac-compliance-framework"],
                practical_effect="A non-US bank can be cut off from USD clearing for facilitating a designated trade.",
            ),
            Position(
                jurisdiction="EU",
                rule="Regulation (EC) 2271/96: EU operators must not comply with listed extraterritorial measures and may seek an authorisation to comply.",
                doc_ids=["eu-blocking-statute-2271-96"],
                practical_effect="Complying without authorisation is itself a breach, and a refusal to perform can create contractual damages exposure.",
            ),
        ],
        divergence=(
            "The two regimes impose directly opposite obligations on the same entity. There is "
            "no structuring solution that removes the conflict — only documented risk allocation "
            "and, where available, an authorisation."
        ),
        resolution=[
            "Identify every relationship or transaction where both regimes bite before it "
            "becomes urgent.",
            "Escalate to legal; consider an authorisation application under the Blocking "
            "Statute where damage would be serious.",
            "Document the dual exposure and the decision, with the legal advice relied on.",
            "Consider structural separation of EU and US operations so each entity follows its "
            "own regime.",
            "Never let a correspondent's compliance instruction be applied automatically to an "
            "EU entity without a legal review.",
        ],
        tags=["sanctions", "extraterritorial", "blocking-statute", "secondary-sanctions"],
        confidence=0.8,
        trigger_typologies=["high_risk_geography"],
    ),
    Conflict(
        id="automated-decisions",
        title="Automated risk decisions: EU/UK explainability vs US flexibility",
        topic="AI and model governance",
        summary=(
            "GDPR Article 22 and the EU AI Act impose human-oversight, transparency and "
            "documentation duties on automated decisions affecting individuals. The US has no "
            "equivalent general rule, but adverse-action and fair-lending regimes impose their "
            "own explanation duties. A model that satisfies one may not satisfy the other."
        ),
        severity=Severity.HIGH,
        positions=[
            Position(
                jurisdiction="EU",
                rule="GDPR Art 22 (solely automated decisions), AI Act high-risk obligations for creditworthiness systems, DORA for model/third-party risk.",
                doc_ids=["eu-gdpr-art22", "eu-ai-act-2024-1689", "eu-dora-2022-2554"],
                practical_effect="Factor-level explanation and human intervention are mandatory, with logs retained.",
            ),
            Position(
                jurisdiction="US",
                rule="BSA/OFAC do not prescribe model explainability, but supervisory expectations (SR 11-7, OCC 2011-12) require model risk management and documentation.",
                doc_ids=["us-bsa-program-requirements", "us-ofac-compliance-framework"],
                practical_effect="Documentation is expected for examination even where no statute mandates it.",
            ),
            Position(
                jurisdiction="UK",
                rule="FCA SYSC 6.3 and Consumer Duty expectations on explainability and fair treatment; ICO guidance on automated decision-making.",
                doc_ids=["uk-fca-sysc-6-3"],
                practical_effect="Firms must show that automated outcomes are understood and can be challenged.",
            ),
        ],
        divergence=(
            "The EU creates an individual right to explanation and human intervention; the US "
            "creates supervisory expectations about documentation. The EU standard is the "
            "stricter one and is the one to build to."
        ),
        resolution=[
            "Keep threshold and scoring logic deterministic and inspectable; use the LLM for "
            "narrative and retrieval, never for the numeric decision.",
            "Record factor contributions for every score and every alert disposition.",
            "Require a named human reviewer before any customer-affecting action.",
            "Retain the model/rule version and the input digest with each decision.",
        ],
        tags=["ai", "explainability", "gdpr", "model-risk", "automation"],
        confidence=0.8,
        trigger_typologies=[],
    ),
]


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
def all_conflicts() -> list[Conflict]:
    return list(CONFLICTS)


def get(conflict_id: str) -> Conflict | None:
    for conflict in CONFLICTS:
        if conflict.id == conflict_id:
            return conflict
    # allow fuzzy id / title / tag matching
    needle = conflict_id.strip().lower()
    for conflict in CONFLICTS:
        if needle in conflict.id or needle in conflict.title.lower() or needle in conflict.tags:
            return conflict
    return None


def find(
    query: str | None = None,
    *,
    jurisdictions: Sequence[str] | None = None,
    tags: Sequence[str] | None = None,
) -> list[Conflict]:
    results = list(CONFLICTS)
    if jurisdictions:
        wanted = {j.upper() for j in jurisdictions}
        results = [c for c in results if wanted & set(c.jurisdictions)]
    if tags:
        wanted_tags = {t.lower() for t in tags}
        results = [c for c in results if wanted_tags & {t.lower() for t in c.tags}]
    if query:
        needle = query.lower()
        results = [
            c for c in results
            if needle in c.title.lower()
            or needle in c.summary.lower()
            or needle in c.topic.lower()
            or needle in c.divergence.lower()
            or any(needle in t for t in c.tags)
            or needle in c.id
        ]
    return results


def relevant_to_findings(findings: Sequence, jurisdictions: Sequence[str] | None = None) -> list[Conflict]:
    """Which conflicts does this case actually raise?"""
    typologies = {getattr(f, "typology", "") for f in findings}
    out: list[Conflict] = []
    for conflict in CONFLICTS:
        if not (conflict.trigger_typologies and typologies & set(conflict.trigger_typologies)):
            continue
        if jurisdictions and not {j.upper() for j in jurisdictions} & set(conflict.jurisdictions):
            continue
        out.append(conflict)
    return out


def severity_rank(conflict: Conflict) -> int:
    return conflict.severity.rank


def memo(conflict: Conflict, kb=None, *, as_of=None) -> str:
    """Render a conflict memo in markdown, with resolved citations."""
    from anjali.kb.resolve import resolve as resolve_keys

    lines: list[str] = []
    lines.append(f"# Conflict memo — {conflict.title}")
    lines.append("")
    lines.append(f"**Conflict ID:** `{conflict.id}`  ")
    lines.append(f"**Topic:** {conflict.topic}  ")
    lines.append(f"**Severity:** {conflict.severity.value}  ")
    lines.append(f"**Jurisdictions:** {', '.join(conflict.jurisdictions)}  ")
    lines.append(f"**Confidence:** {conflict.confidence:.0%}")
    lines.append("")
    lines.append("## What the regimes require")
    lines.append("")
    lines.append(conflict.summary)
    lines.append("")
    for position in conflict.positions:
        lines.append(f"### {position.jurisdiction}")
        lines.append("")
        lines.append(position.rule)
        lines.append("")
        citations = []
        if kb is not None:
            citations = resolve_keys(kb, position.doc_ids, as_of=as_of)
        if citations:
            lines.append("**Authority**")
            lines.append("")
            for cit in citations:
                stale = " *(no longer in force at the as-of date)*" if cit.stale else ""
                future = " *(not yet in force at the as-of date)*" if cit.future else ""
                link = f" — <{cit.source_url}>" if cit.source_url else ""
                lines.append(f"- {cit.citation} — {cit.title}{link}{stale}{future}")
            lines.append("")
        else:
            lines.append(f"**Authority keys:** {', '.join(position.doc_ids)}")
            lines.append("")
        lines.append(f"**Practical effect:** {position.practical_effect}")
        lines.append("")
    lines.append("## Where the regimes diverge")
    lines.append("")
    lines.append(conflict.divergence)
    lines.append("")
    lines.append("## Recommended resolution")
    lines.append("")
    for i, step in enumerate(conflict.resolution, 1):
        lines.append(f"{i}. {step}")
    lines.append("")
    lines.append("## Control position to record")
    lines.append("")
    lines.append(
        "Apply the strictest requirement applicable to each entity, document the legal basis "
        "per jurisdiction, and record the decision in the audit trail so the institution can "
        "show that the divergence was identified and managed deliberately."
    )
    lines.append("")
    lines.append(f"> {CONFIDENCE_NOTE}")
    lines.append("")
    return "\n".join(lines)


def matrix() -> list[dict[str, str]]:
    return [
        {
            "id": c.id,
            "topic": c.topic,
            "jurisdictions": ", ".join(c.jurisdictions),
            "severity": c.severity.value,
            "summary": truncate(c.summary, 160),
        }
        for c in CONFLICTS
    ]


def coverage_by_topic() -> dict[str, int]:
    counts: dict[str, int] = {}
    for conflict in CONFLICTS:
        counts[conflict.topic] = counts.get(conflict.topic, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))
