"""Domain ontology for financial-crime retrieval.

Generic embeddings blur acronyms that carry the entire meaning of a compliance
question: "STR" vs "SAR", "CVC" vs "crypto", "UBO" vs "beneficial owner", "MLR" vs
"Money Laundering Regulations". A curated synonym graph fixes this deterministically,
without a model and without a network call — and, unlike a learned expansion, it can be
reviewed and signed off by a compliance officer.

Expansion is *weighted*: the literal query terms keep full weight, synonyms enter at
:data:`SYNONYM_WEIGHT` so they can rescue recall without hijacking precision.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

SYNONYM_WEIGHT = 0.5

# Groups of interchangeable / closely-related concepts. Every member maps to the group.
_GROUPS: list[tuple[str, ...]] = [
    ("structuring", "smurfing", "structur", "evasion", "splitting", "belowthreshold"),
    ("sar", "str", "suspiciousactivityreport", "suspicioustransactionreport", "disclosure", "ukfiu"),
    ("ctr", "currencytransactionreport", "currencytransaction", "form112"),
    ("cdd", "kyc", "customerdue diligence", "customerdue diligence", "customeridentification", "cip"),
    ("edd", "enhanceddue diligence", "enhancedduediligence", "highriskreview"),
    ("pep", "politicallyexposed", "seniorforeignpoliticalfigure", "domesticpep"),
    ("sanctions", "ofac", "sdn", "assetfreeze", "freezing", "targetedfinancialsanctions", "tfs", "ofsi"),
    ("tippingoff", "tipping", "confidentiality", "nondisclosure", "prohibitionondisclosure"),
    ("beneficialowner", "ubo", "beneficialownership", "ownership", "controlperson"),
    ("travelrule", "wiretransfer", "fundstransfer", "originator", "beneficiaryinformation", "r16"),
    ("crypto", "cvc", "virtualcurrency", "virtualasset", "vasp", "casp", "digitalasset", "wallet"),
    ("mule", "moneymule", "muleaccount", "smurfaccount", "recruitedaccount"),
    ("layering", "passthrough", "rapidmovement", "placement", "integration", "roundtripping"),
    ("tbml", "tradebasedmoneylaundering", "tradebased", "overinvoicing", "underinvoicing",
     "tradefinance", "letterofcredit", "carousel"),
    ("aml", "antimoneylaundering", "mltf", "financialcrime", "moneylaundering", "cft"),
    ("amld5", "amld6", "amlr", "amld", "antimoneylaunderingdirective", "2024/1640", "2018/843"),
    ("gdpr", "dataprotection", "personaldata", "datasubject", "dsar", "privacy"),
    ("retention", "recordkeeping", "fiveyears", "storagelimitation", "records"),
    ("poca", "proceedsofcrime", "failuredisclose", "failuredisclosure"),
    ("mlr", "moneylaunderingregulations", "mlr2017"),
    ("fatf", "recommendation", "fortyrecommendations", "rba"),
    ("risk", "riskbasedapproach", "riskassessment", "riskscore", "riskrating"),
    ("velocity", "rapid", "burst", "frequency", "anomaly", "anomalous"),
    ("threshold", "limit", "deminimis", "reportingthreshold"),
    ("correspondent", "nostro", "vostro", "nested", "payablethrough", "respondent"),
    ("conflict", "divergence", "inconsistency", "jurisdictional", "extraterritorial"),
    ("sar-confidentiality", "5318g2", "tipping", "confidential"),
    ("cta", "boi", "corporatetransparency", "reportingcompany"),
    ("psd2", "strongcustomerauthentication", "sca", "paymentservices"),
    ("aiact", "highriskai", "automateddecision", "explainability", "humanoversight"),
    ("deadline", "timing", "days", "calendar", "clock", "duedate"),
    ("penalty", "penalties", "fine", "enforcement", "liability", "strictliability"),
]

# Jurisdiction cues used to bias (not filter) retrieval.
JURISDICTION_CUES: dict[str, tuple[str, ...]] = {
    "US": ("us", "usa", "unitedstates", "fincen", "ofac", "bsa", "cfr", "patriot", "federal", "occ", "federalreserve"),
    "EU": ("eu", "europeanunion", "amld", "amlr", "gdpr", "eba", "esma", "amla", "european", "memberstate"),
    "UK": ("uk", "britain", "british", "fca", "poca", "ofsi", "ukfiu", "nca", "mlr", "england", "scotland"),
    "FATF": ("fatf", "recommendation", "mutualevaluation", "grey list", "greylist", "blacklist"),
}

JURISDICTION_BOOST = 1.18


def _norm(term: str) -> str:
    return re.sub(r"[^a-z0-9/]", "", term.lower())


_INDEX: dict[str, set[str]] = defaultdict(set)
_GROUP_OF: dict[str, int] = {}
for _gi, _group in enumerate(_GROUPS):
    for _member in _group:
        key = _norm(_member)
        _GROUP_OF[key] = _gi
        for other in _group:
            if _norm(other) != key:
                _INDEX[key].add(_norm(other))


@dataclass(frozen=True)
class ExpandedTerm:
    term: str
    weight: float
    source: str  # "literal" | "synonym"


def expand(tokens: list[str]) -> list[ExpandedTerm]:
    """Return literal terms at weight 1.0 plus ontology neighbours at 0.5."""
    out: dict[str, ExpandedTerm] = {}
    for tok in tokens:
        key = _norm(tok)
        if not key:
            continue
        out.setdefault(key, ExpandedTerm(tok, 1.0, "literal"))
        for syn in _INDEX.get(key, ()):
            out.setdefault(syn, ExpandedTerm(syn, SYNONYM_WEIGHT, "synonym"))
    return list(out.values())


def detect_jurisdictions(query: str) -> list[str]:
    """Soft jurisdiction hints from the question text."""
    cleaned = re.sub(r"[^a-z0-9 ]", " ", query.lower())
    padded = f" {cleaned} "
    found: list[str] = []
    for juris, cues in JURISDICTION_CUES.items():
        for cue in cues:
            cue_clean = cue.replace(" ", "")
            if f" {cue_clean} " in padded or f" {cue_clean}s " in padded:
                found.append(juris)
                break
    return found


def _stem(term: str) -> str:
    """Tiny suffix stripper so 'sharing' matches the tag 'group-sharing'."""
    t = term.lower()
    for suffix in ("ations", "ation", "ings", "ing", "ies", "ied", "es", "ed", "s"):
        if len(t) > len(suffix) + 3 and t.endswith(suffix):
            return t[: -len(suffix)]
    return t


def tag_overlap(query_tokens: list[str], tags: list[str]) -> int:
    q = {_stem(t) for t in query_tokens if len(t) > 2}
    t = {_stem(part) for tag in tags for part in re.split(r"[-_ ]", tag)}
    return len(q & t)
