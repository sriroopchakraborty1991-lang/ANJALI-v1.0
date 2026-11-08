"""The agent's toolbelt.

Each tool is a thin, auditable wrapper over a deterministic function. The model chooses
*which* tool to call and in what order; it never computes a threshold, a score or a match
itself. That separation is what makes the output defensible: the numbers come from code
that can be unit-tested, and the model contributes language and orchestration.

Every call is recorded in the audit trail with its arguments and a digest of its result.
"""

from __future__ import annotations

import ast
import json
import operator
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from anjali.analysis.engine import AnalysisResult, analyze, build_context
from anjali.analysis.patterns import AnalysisContext
from anjali.compliance.conflicts import all_conflicts
from anjali.compliance.conflicts import find as find_conflicts
from anjali.core.errors import AnjaliError
from anjali.core.models import Citation
from anjali.graph.entity_graph import EntityGraph, link_analysis
from anjali.kb.resolve import resolve as resolve_citations
from anjali.providers.base import ToolSpec

MAX_TOOL_OUTPUT = 6000


@dataclass
class ToolResult:
    payload: Any
    citations: list[Citation] = field(default_factory=list)
    summary: str = ""
    error: str | None = None

    def for_model(self, *, max_chars: int = MAX_TOOL_OUTPUT) -> str:
        if self.error:
            return json.dumps({"error": self.error, "note": "report this to the analyst; do not guess"})
        text = self.payload if isinstance(self.payload, str) else json.dumps(self.payload, default=str, ensure_ascii=False)
        if len(text) > max_chars:
            text = text[:max_chars] + "\n…[truncated]"
        return text


@dataclass
class AgentContext:
    settings: Any
    kb: Any
    db: Any
    screener: Any = None
    audit: Any = None
    analysis: AnalysisResult | None = None
    analysis_ctx: AnalysisContext | None = None
    graph: EntityGraph | None = None
    as_of: date | None = None
    jurisdictions: list[str] = field(default_factory=lambda: ["US", "EU", "UK", "FATF"])
    case_id: str | None = None

    def ensure_analysis(self) -> AnalysisResult | None:
        if self.analysis is not None:
            return self.analysis
        from anjali.analysis.ingest import fetch_accounts, fetch_customers, fetch_transactions

        txns = fetch_transactions(self.db)
        if not txns:
            return None
        ctx = build_context(txns, fetch_customers(self.db), fetch_accounts(self.db))
        self.analysis_ctx = ctx
        self.analysis = analyze(
            ctx, kb=self.kb, as_of=self.as_of, case_id=self.case_id, db=self.db
        )
        return self.analysis

    def ensure_graph(self) -> EntityGraph | None:
        if self.graph is not None:
            return self.graph
        if self.analysis_ctx is None:
            self.ensure_analysis()
        if self.analysis_ctx is None:
            return None
        self.graph = EntityGraph.from_context(self.analysis_ctx)
        return self.graph


# --------------------------------------------------------------------------- #
# Safe arithmetic for threshold questions
# --------------------------------------------------------------------------- #
_BIN_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.Mod: operator.mod, ast.Pow: operator.pow,
    ast.FloorDiv: operator.floordiv,
}
_UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _eval_node(node: ast.AST) -> float:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        return _BIN_OPS[type(node.op)](_eval_node(node.left), _eval_node(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_eval_node(node.operand))
    raise ValueError("unsupported expression")


def safe_calculate(expression: str) -> dict[str, Any]:
    """Threshold arithmetic with no names, calls or attribute access."""
    if len(expression) > 200:
        raise ValueError("expression too long")
    tree = ast.parse(expression.replace(",", ""), mode="eval")
    return {"expression": expression, "result": round(_eval_node(tree.body), 6)}


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #
def _tool_search_regulations(ctx: AgentContext, query: str, jurisdictions: list[str] | None = None,
                             top_k: int = 8, include_superseded: bool = False) -> ToolResult:
    hits = ctx.kb.search(
        query,
        top_k=int(top_k),
        jurisdictions=jurisdictions or None,
        as_of=ctx.as_of,
        include_superseded=include_superseded,
    )
    citations = []
    payload = []
    for hit in hits:
        cit = hit.to_citation()
        citations.append(cit)
        payload.append(
            {
                "citation": cit.citation,
                "title": cit.title,
                "jurisdiction": cit.jurisdiction.value,
                "doc_id": cit.doc_id,
                "effective_from": cit.effective_from.isoformat() if cit.effective_from else None,
                "stale": cit.stale,
                "not_yet_in_force": cit.future,
                "score": cit.score,
                "snippet": cit.snippet,
            }
        )
    return ToolResult(
        payload={"query": query, "results": payload, "count": len(payload)},
        citations=citations,
        summary=f"{len(payload)} provisions retrieved for '{query}'",
    )


def _tool_get_provision(ctx: AgentContext, citation: str) -> ToolResult:
    doc = ctx.kb.get_document(citation)
    if doc is None:
        matches = ctx.kb.find_by_citation(citation)
        doc = matches[0] if matches else None
    if doc is None:
        return ToolResult(payload={}, error=f"No provision in the corpus matches '{citation}'.")
    citations = resolve_citations(ctx.kb, [doc["doc_id"]], as_of=ctx.as_of)
    return ToolResult(
        payload={
            "citation": doc["citation"],
            "title": doc["title"],
            "jurisdiction": doc["jurisdiction"],
            "regulator": doc["regulator"],
            "status": doc["status"],
            "effective_from": doc["effective_from"],
            "effective_to": doc["effective_to"],
            "obligations": json.loads(doc.get("obligations") or "[]"),
            "penalties": doc.get("penalties"),
            "source_url": doc.get("source_url"),
            "text": doc["text"],
        },
        citations=citations,
        summary=f"Retrieved {doc['citation']}",
    )


def _tool_analyze(ctx: AgentContext, typologies: list[str] | None = None, max_findings: int = 15) -> ToolResult:
    result = ctx.ensure_analysis()
    if result is None:
        return ToolResult(payload={}, error="No transaction data loaded in this workspace.")
    findings = result.findings
    if typologies:
        findings = [f for f in findings if f.typology in typologies]
    citations: list[Citation] = []
    rows = []
    for finding in findings[: int(max_findings)]:
        citations.extend(finding.regulatory_refs)
        rows.append(
            {
                "finding_id": finding.finding_id,
                "typology": finding.typology,
                "severity": finding.severity.value,
                "summary": finding.summary,
                "confidence": finding.confidence,
                "transactions": finding.evidence_txn_ids[:8],
                "metrics": finding.metrics,
                "explanation": finding.explanation,
                "citations": [c.citation for c in finding.regulatory_refs],
            }
        )
    return ToolResult(
        payload={
            "summary": result.summary,
            "risk": result.risk.model_dump(mode="json"),
            "findings": rows,
            "detectors_skipped": result.detectors_skipped,
        },
        citations=citations,
        summary=f"{len(findings)} findings; risk {result.risk.overall} ({result.risk.band.value})",
    )


def _tool_assess_risk(ctx: AgentContext, jurisdiction: str | None = None) -> ToolResult:
    result = ctx.ensure_analysis()
    if result is None:
        return ToolResult(payload={}, error="No transaction data loaded in this workspace.")
    if jurisdiction:
        from anjali.analysis.risk import assess

        refreshed = assess(ctx.analysis_ctx, result.findings, jurisdiction=jurisdiction,
                           resolve=lambda keys: resolve_citations(ctx.kb, keys, as_of=ctx.as_of))
        assessment = refreshed.assessment
    else:
        assessment = result.risk
    return ToolResult(
        payload=assessment.model_dump(mode="json"),
        citations=list(assessment.citations),
        summary=f"Risk {assessment.overall}/100 ({assessment.band.value})",
    )


def _tool_screen_sanctions(ctx: AgentContext, name: str, dob: str | None = None,
                           country: str | None = None) -> ToolResult:
    if ctx.screener is None:
        from anjali.analysis.sanctions import SanctionsScreener

        ctx.screener = SanctionsScreener(ctx.db)
    result = ctx.screener.screen(name, dob=dob, country=country)
    citations = resolve_citations(ctx.kb, [
        "us-31cfr-501-603", "us-ofac-50-percent-rule", "fatf-r6-7-sanctions",
    ], as_of=ctx.as_of)
    top = result.matches[0] if result.matches else None
    return ToolResult(
        payload={
            "query": name,
            "disposition": result.disposition.value,
            "requires_review": result.disposition.requires_review,
            "matches": [m.model_dump(mode="json") for m in result.matches],
            "lists_checked": result.lists_checked,
            "list_version": getattr(ctx.screener, "version", "unknown"),
            "banner": "[SANCTIONS ALERT]" if result.disposition.requires_review else "",
        },
        citations=citations,
        summary=(
            f"{result.disposition.value} — top score {top.score:.2f} on {top.list_name}"
            if top else "CLEAR — no match at or above threshold"
        ),
    )


def _tool_find_conflicts(ctx: AgentContext, topic: str | None = None,
                         jurisdictions: list[str] | None = None) -> ToolResult:
    conflicts = find_conflicts(topic, jurisdictions=jurisdictions) if (topic or jurisdictions) else all_conflicts()
    citations: list[Citation] = []
    payload = []
    for conflict in conflicts:
        for position in conflict.positions:
            citations.extend(resolve_citations(ctx.kb, position.doc_ids, as_of=ctx.as_of))
        payload.append(
            {
                "id": conflict.id,
                "title": conflict.title,
                "severity": conflict.severity.value,
                "jurisdictions": conflict.jurisdictions,
                "summary": conflict.summary,
                "divergence": conflict.divergence,
                "resolution": conflict.resolution,
                "authorities": [d for p in conflict.positions for d in p.doc_ids],
            }
        )
    payload = _dedupe_citation_refs(payload)
    return ToolResult(
        payload={"count": len(payload), "conflicts": payload},
        citations=_dedupe_citations(citations),
        summary=f"{len(payload)} cross-jurisdiction conflict(s)",
    )


def _tool_trace_connections(ctx: AgentContext, subject: str, target: str | None = None) -> ToolResult:
    graph = ctx.ensure_graph()
    if graph is None:
        return ToolResult(payload={}, error="No transaction data loaded; the graph is empty.")
    return ToolResult(
        payload=link_analysis(graph, subject, target),
        summary=f"Link analysis for {subject}" + (f" → {target}" if target else ""),
    )


def _tool_case_summary(ctx: AgentContext) -> ToolResult:
    result = ctx.ensure_analysis()
    if result is None:
        data = {
            "transactions": ctx.db.scalar("SELECT COUNT(*) FROM transactions") or 0,
            "customers": ctx.db.scalar("SELECT COUNT(*) FROM customers") or 0,
            "note": "No transactions in this workspace. Load a case with `anjali data load`.",
        }
        return ToolResult(payload=data, summary="Workspace inventory")
    return ToolResult(
        payload={**result.summary, "case_id": result.case_id, "corpus_digest": result.corpus_digest},
        citations=[],
        summary=f"Case {result.case_id}: {result.summary.get('transactions')} transactions",
    )


def _tool_calculate(ctx: AgentContext, expression: str) -> ToolResult:
    try:
        return ToolResult(payload=safe_calculate(expression), summary=f"{expression} = …")
    except Exception as exc:
        return ToolResult(payload={}, error=f"Cannot evaluate '{expression}': {exc}")


def _tool_timeline(ctx: AgentContext, limit: int = 20) -> ToolResult:
    result = ctx.ensure_analysis()
    if result is None or ctx.analysis_ctx is None:
        return ToolResult(payload={}, error="No transaction data loaded.")
    events = []
    for finding in result.findings[:20]:
        for txn_id in finding.evidence_txn_ids[:2]:
            txn = next((t for t in ctx.analysis_ctx.transactions if t.txn_id == txn_id), None)
            if txn:
                events.append(
                    {
                        "timestamp": txn.timestamp.isoformat(),
                        "event": f"{finding.typology}: {txn.txn_type} {txn.amount}",
                        "finding_id": finding.finding_id,
                        "severity": finding.severity.value,
                    }
                )
    events.sort(key=lambda e: e["timestamp"])
    return ToolResult(payload={"events": events[: int(limit)]}, summary=f"{len(events)} timeline events")


def _dedupe_citations(citations: Sequence[Citation]) -> list[Citation]:
    seen: dict[str, Citation] = {}
    for cit in citations:
        seen.setdefault(f"{cit.doc_id}:{cit.citation}", cit)
    return list(seen.values())


def _dedupe_citation_refs(payload: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return payload


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    fn: Callable[..., ToolResult]

    def spec(self) -> ToolSpec:
        return ToolSpec(name=self.name, description=self.description, parameters=self.parameters)


def _obj(properties: dict[str, Any], required: Sequence[str] = ()) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": list(required)}


TOOLS: dict[str, Tool] = {
    "search_regulations": Tool(
        name="search_regulations",
        description=(
            "Hybrid search over the regulatory corpus (US BSA/OFAC, EU AMLD/AMLR/GDPR/AI Act, "
            "UK MLR/POCA/FCA, FATF recommendations, international standards). Returns provisions "
            "in force on the analysis date. Always call this before making a regulatory claim."
        ),
        parameters=_obj(
            {
                "query": {"type": "string", "description": "Natural-language or citation-style query."},
                "jurisdictions": {
                    "type": "array", "items": {"type": "string", "enum": ["US", "EU", "UK", "FATF", "INTL"]},
                    "description": "Optional jurisdiction filter.",
                },
                "top_k": {"type": "integer", "minimum": 1, "maximum": 20, "default": 8},
                "include_superseded": {
                    "type": "boolean", "default": False,
                    "description": "Include provisions no longer in force, flagged as stale.",
                },
            },
            ["query"],
        ),
        fn=_tool_search_regulations,
    ),
    "get_provision": Tool(
        name="get_provision",
        description="Fetch the full text of a single provision by citation or doc_id (e.g. '31 CFR § 1010.314').",
        parameters=_obj({"citation": {"type": "string"}}, ["citation"]),
        fn=_tool_get_provision,
    ),
    "analyze_transactions": Tool(
        name="analyze_transactions",
        description=(
            "Run the deterministic typology detectors over the loaded case and return findings "
            "with metrics, explanation steps and citations. Optionally filter to specific typologies."
        ),
        parameters=_obj(
            {
                "typologies": {"type": "array", "items": {"type": "string"}},
                "max_findings": {"type": "integer", "minimum": 1, "maximum": 40, "default": 15},
            }
        ),
        fn=_tool_analyze,
    ),
    "assess_risk": Tool(
        name="assess_risk",
        description="Return the explainable composite risk assessment (5 dimensions, citations, jurisdiction views).",
        parameters=_obj({"jurisdiction": {"type": "string", "enum": ["US", "EU", "UK"]}}),
        fn=_tool_assess_risk,
    ),
    "screen_sanctions": Tool(
        name="screen_sanctions",
        description="Fuzzy sanctions screening against loaded lists, with corroboration and match tiers.",
        parameters=_obj(
            {
                "name": {"type": "string"},
                "dob": {"type": "string", "description": "ISO date of birth, if known."},
                "country": {"type": "string", "description": "ISO-2 country code."},
            },
            ["name"],
        ),
        fn=_tool_screen_sanctions,
    ),
    "find_conflicts": Tool(
        name="find_conflicts",
        description="Cross-jurisdiction conflicts (US vs EU vs UK) with authorities and a recommended resolution.",
        parameters=_obj(
            {
                "topic": {"type": "string", "description": "Free-text topic, e.g. 'sar disclosure' or 'sanctions ownership'."},
                "jurisdictions": {"type": "array", "items": {"type": "string"}},
            }
        ),
        fn=_tool_find_conflicts,
    ),
    "trace_connections": Tool(
        name="trace_connections",
        description="Knowledge-graph link analysis: ego network for a subject and the shortest path to a target.",
        parameters=_obj(
            {"subject": {"type": "string"}, "target": {"type": "string"}}, ["subject"]
        ),
        fn=_tool_trace_connections,
    ),
    "case_summary": Tool(
        name="case_summary",
        description="Volume, severity and risk summary of the loaded case, plus corpus digest.",
        parameters=_obj({}),
        fn=_tool_case_summary,
    ),
    "timeline": Tool(
        name="timeline",
        description="Chronological events derived from findings and their evidence transactions.",
        parameters=_obj({"limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}}),
        fn=_tool_timeline,
    ),
    "calculate": Tool(
        name="calculate",
        description="Safe arithmetic for threshold maths (e.g. '0.8 * 10000'). No variables or functions.",
        parameters=_obj({"expression": {"type": "string"}}, ["expression"]),
        fn=_tool_calculate,
    ),
}


def tool_specs() -> list[ToolSpec]:
    return [tool.spec() for tool in TOOLS.values()]


def call_tool(ctx: AgentContext, name: str, arguments: dict[str, Any]) -> ToolResult:
    tool = TOOLS.get(name)
    if tool is None:
        return ToolResult(payload={}, error=f"Unknown tool '{name}'. Available: {', '.join(TOOLS)}")
    try:
        return tool.fn(ctx, **arguments)
    except TypeError as exc:
        return ToolResult(payload={}, error=f"Bad arguments for {name}: {exc}")
    except AnjaliError as exc:
        return ToolResult(payload={}, error=f"{name} failed: {exc.message}")
    except Exception as exc:  # pragma: no cover - defensive
        return ToolResult(payload={}, error=f"{name} failed: {type(exc).__name__}: {exc}")
