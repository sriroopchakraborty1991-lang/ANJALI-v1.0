"""Core domain models for ANJALI-AI.

Every model is serialisable to JSON and designed to be *auditable*: anything the
agent asserts must be traceable to a citation, a transaction id, or a computation
that can be re-run. No model here performs I/O.
"""

from __future__ import annotations

import enum
import hashlib
import json
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Jurisdiction(str, enum.Enum):
    US = "US"
    EU = "EU"
    UK = "UK"
    FATF = "FATF"
    INTL = "INTL"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]


class RiskBand(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def from_score(cls, score: float) -> RiskBand:
        if score >= 80:
            return cls.CRITICAL
        if score >= 60:
            return cls.HIGH
        if score >= 35:
            return cls.MEDIUM
        return cls.LOW


class Direction(str, enum.Enum):
    DEBIT = "debit"
    CREDIT = "credit"


class DocStatus(str, enum.Enum):
    IN_FORCE = "in_force"
    AMENDED = "amended"
    SUPERSEDED = "superseded"
    REPEALED = "repealed"
    PROPOSED = "proposed"

    @property
    def is_current(self) -> bool:
        return self in (DocStatus.IN_FORCE, DocStatus.AMENDED)


class MatchTier(str, enum.Enum):
    CLEAR = "CLEAR"
    WEAK = "WEAK"
    POTENTIAL = "POTENTIAL"
    STRONG = "STRONG"
    EXACT = "EXACT"

    @property
    def requires_review(self) -> bool:
        return self in (self.POTENTIAL, self.STRONG, self.EXACT)


# --------------------------------------------------------------------------- #
# Base
# --------------------------------------------------------------------------- #
class AnjaliModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        ser_json_timedelta="float",
        json_encoders={Decimal: lambda v: str(v), datetime: lambda v: v.isoformat()},
    )

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.model_dump_json())

    def digest(self) -> str:
        """Stable content hash — used for the audit chain and dedup."""
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(payload.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Knowledge base
# --------------------------------------------------------------------------- #
class RegulatoryDocument(AnjaliModel):
    """A single provision / guidance item in the regulatory corpus."""

    doc_id: str
    citation: str = Field(description='Human citation, e.g. "31 CFR § 1010.314"')
    title: str
    jurisdiction: Jurisdiction
    regulator: str
    doc_type: Literal[
        "statute", "regulation", "directive", "guidance", "recommendation", "advisory", "standard"
    ] = "regulation"
    status: DocStatus = DocStatus.IN_FORCE
    effective_from: date
    effective_to: date | None = None
    amended_by: list[str] = Field(default_factory=list)
    supersedes: list[str] = Field(default_factory=list)
    source_url: str | None = None
    tags: list[str] = Field(default_factory=list)
    text: str
    obligations: list[str] = Field(default_factory=list)
    penalties: str | None = None
    confidence_note: str | None = None

    @field_validator("effective_from", "effective_to", mode="before")
    @classmethod
    def _coerce_date(cls, v: Any) -> Any:
        if isinstance(v, str):
            return date.fromisoformat(v)
        return v

    @field_validator("tags", "obligations", "amended_by", "supersedes", mode="before")
    @classmethod
    def _coerce_str_list(cls, v: Any) -> Any:
        if v is None:
            return []
        if isinstance(v, str):
            # Delimited strings arrive from CSV columns ("ACC-1;ACC-2") and YAML tags.
            parts = v.replace(";", "|").replace(",", "|").split("|")
            cleaned = [part.strip() for part in parts if part.strip()]
            return cleaned or [v]
        if isinstance(v, (int, float)):
            return [str(v)]
        return [str(item) for item in v]


    def is_current(self, as_of: date | None = None) -> bool:
        as_of = as_of or date.today()
        if self.status in (DocStatus.REPEALED, DocStatus.SUPERSEDED, DocStatus.PROPOSED):
            return False
        if self.effective_from > as_of:
            return False
        return not (self.effective_to and self.effective_to < as_of)


class Chunk(AnjaliModel):
    """A retrievable slice of a regulatory document."""

    chunk_id: str
    doc_id: str
    citation: str
    title: str
    jurisdiction: Jurisdiction
    regulator: str
    doc_type: str
    status: DocStatus
    effective_from: date
    effective_to: date | None = None
    source_url: str | None = None
    tags: list[str] = Field(default_factory=list)
    section: str | None = None
    text: str
    ordinal: int = 0


class Citation(AnjaliModel):
    """A verified pointer to a retrieved provision, attached to an assertion."""

    doc_id: str
    citation: str
    title: str
    jurisdiction: Jurisdiction
    regulator: str = ""
    source_url: str | None = None
    effective_from: date | None = None
    snippet: str = ""
    score: float = 0.0
    verified: bool = True
    stale: bool = False
    future: bool = False


# --------------------------------------------------------------------------- #
# Transactions & customers
# --------------------------------------------------------------------------- #
class Transaction(AnjaliModel):
    txn_id: str
    timestamp: datetime
    amount: Decimal
    currency: str = "USD"
    direction: Direction = Direction.DEBIT
    txn_type: str = "wire"
    from_account: str | None = None
    to_account: str | None = None
    from_name: str | None = None
    to_name: str | None = None
    channel: str | None = None
    country_from: str | None = None
    country_to: str | None = None
    branch: str | None = None
    device_id: str | None = None
    ip_address: str | None = None
    description: str | None = None
    reference: str | None = None
    status: str = "posted"
    # Trade-finance attributes (optional) — enable the TBML detector.
    goods_description: str | None = None
    hs_code: str | None = None
    quantity: Decimal | None = None
    unit_price: Decimal | None = None
    benchmark_price: Decimal | None = None
    vessel: str | None = None
    route: str | None = None

    @field_validator("currency")
    @classmethod
    def _upper_currency(cls, v: Any) -> Any:
        return str(v).strip().upper() if v else "USD"

    @field_validator("timestamp", mode="before")
    @classmethod
    def _coerce_ts(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = v.strip().replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(v)
            except ValueError:
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M"):
                    try:
                        dt = datetime.strptime(v, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    raise ValueError(f"Unrecognised timestamp: {v!r}") from None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        return v

    @field_validator("quantity", "unit_price", "benchmark_price", mode="before")
    @classmethod
    def _coerce_optional_decimal(cls, v: Any) -> Any:
        if v is None or v == "":
            return None
        if isinstance(v, str):
            return Decimal(v.replace(",", "").replace("$", "").strip())
        if isinstance(v, float):
            return Decimal(str(v))
        return v

    @field_validator("amount", mode="before")
    @classmethod
    def _coerce_amount(cls, v: Any) -> Any:
        if isinstance(v, str):
            return Decimal(v.replace(",", "").replace("$", "").strip())
        if isinstance(v, float):
            return Decimal(str(v))
        return v

    @property
    def ts(self) -> datetime:
        return self.timestamp

    @property
    def month_key(self) -> str:
        return self.timestamp.strftime("%Y-%m")

    @property
    def parties(self) -> set[str]:
        out: set[str] = set()
        for v in (self.from_account, self.to_account, self.from_name, self.to_name):
            if v:
                out.add(v)
        return out


class BeneficialOwner(AnjaliModel):
    name: str
    ownership_pct: float = 0.0
    country: str | None = None
    dob: str | None = None
    sanctions_id: str | None = None


class Customer(AnjaliModel):
    customer_id: str
    name: str
    customer_type: Literal["individual", "business"] = "individual"
    country: str = "US"
    residency: str | None = None
    dob: str | None = None
    occupation: str | None = None
    industry: str | None = None
    naics: str | None = None
    pep: bool = False
    risk_rating: str | None = None
    onboarded_at: date | None = None
    expected_monthly_volume: Decimal | None = None
    expected_txn_count: int | None = None
    source_of_funds: str | None = None
    accounts: list[str] = Field(default_factory=list)
    beneficial_owners: list[BeneficialOwner] = Field(default_factory=list)
    kyc_verified_at: date | None = None
    edd_completed: bool = False
    notes: str | None = None

    @field_validator("accounts", "beneficial_owners", mode="before")
    @classmethod
    def _split_accounts(cls, v: Any) -> Any:
        if isinstance(v, str):
            parts = v.replace(";", "|").replace(",", "|").split("|")
            return [part.strip() for part in parts if part.strip()]
        return v

    @field_validator("country", mode="before")
    @classmethod
    def _upper_country(cls, v: Any) -> Any:
        return str(v).strip().upper() if v else v


class Account(AnjaliModel):
    account_id: str
    customer_id: str
    account_type: str = "checking"
    currency: str = "USD"
    country: str = "US"
    opened_at: date | None = None
    status: str = "open"


# --------------------------------------------------------------------------- #
# Findings, risk, screening
# --------------------------------------------------------------------------- #
class Finding(AnjaliModel):
    """A deterministic detection result with an explanation trace."""

    finding_id: str
    typology: str
    severity: Severity
    title: str
    summary: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.7)
    evidence_txn_ids: list[str] = Field(default_factory=list)
    accounts: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    explanation: list[str] = Field(default_factory=list)
    regulatory_refs: list[Citation] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    jurisdiction_notes: dict[str, str] = Field(default_factory=dict)


class DimensionScore(AnjaliModel):
    dimension: str
    score: float = Field(ge=0.0, le=100.0)
    weight: float
    rationale: str
    drivers: list[str] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)


class RiskAssessment(AnjaliModel):
    overall: float = Field(ge=0.0, le=100.0)
    band: RiskBand
    methodology: str = "FATF risk-based approach; weighted multi-dimensional composite"
    dimensions: list[DimensionScore] = Field(default_factory=list)
    narrative: str = ""
    citations: list[Citation] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.75)
    jurisdiction_views: dict[str, float] = Field(default_factory=dict)


class SanctionsMatch(AnjaliModel):
    query_name: str
    matched_name: str
    list_name: str
    list_id: str | None = None
    score: float = Field(ge=0.0, le=1.0)
    tier: MatchTier
    algorithm: str = "jaro_winkler+token_set"
    attributes: dict[str, Any] = Field(default_factory=dict)
    corroboration: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)

    @property
    def alert_banner(self) -> str:
        return "[SANCTIONS ALERT]" if self.tier.requires_review else ""


class ScreeningResult(AnjaliModel):
    query: str
    matches: list[SanctionsMatch] = Field(default_factory=list)
    lists_checked: list[str] = Field(default_factory=list)
    threshold: float = 0.85
    disposition: MatchTier = MatchTier.CLEAR
    citations: list[Citation] = Field(default_factory=list)
    ownership_hits: list[dict[str, Any]] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
class SARSubject(AnjaliModel):
    name: str
    role: Literal["subject", "beneficiary", "counterparty", "account_holder"] = "subject"
    entity_type: str = "individual"
    country: str | None = None
    dob: str | None = None
    identifiers: dict[str, str] = Field(default_factory=dict)
    accounts: list[str] = Field(default_factory=list)


class SARReport(AnjaliModel):
    report_id: str
    case_id: str | None = None
    filing_type: Literal["initial", "continuing", "corrected"] = "initial"
    jurisdiction: Jurisdiction = Jurisdiction.US
    filing_regulator: str = "FinCEN"
    filing_form: str = "FinCEN SAR (BSA E-Filing)"
    subjects: list[SARSubject] = Field(default_factory=list)
    accounts: list[str] = Field(default_factory=list)
    activity_start: date | None = None
    activity_end: date | None = None
    total_amount: Decimal | None = None
    currency: str = "USD"
    typologies: list[str] = Field(default_factory=list)
    narrative: str = ""
    narrative_sections: dict[str, str] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    due_date: date | None = None
    prepared_by: str = "ANJALI-AI"
    confidence: float = Field(ge=0.0, le=1.0, default=0.7)
    requires_human_review: bool = True
    limitations: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Recording layer
# --------------------------------------------------------------------------- #
class AuditRecord(AnjaliModel):
    seq: int
    timestamp: datetime
    actor: str
    action: str
    subject: str | None = None
    payload_digest: str
    prev_hash: str
    hash: str
    details: dict[str, Any] = Field(default_factory=dict)


class AgentStep(AnjaliModel):
    step: int
    kind: Literal["thought", "tool_call", "tool_result", "answer", "guardrail"]
    content: str = ""
    tool: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    observation: str | None = None
    citations: list[Citation] = Field(default_factory=list)
    duration_ms: int | None = None


class AgentResult(AnjaliModel):
    question: str
    answer: str
    steps: list[AgentStep] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    risk_level: Severity | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.6)
    provider: str = ""
    model: str = ""
    offline: bool = False
    tokens_estimate: int = 0
    audit_ref: str | None = None
