"""Agent orchestration.

Two execution paths, one output contract:

* **LLM path** — a bounded ReAct loop. The model selects tools, ANJALI executes them
  deterministically, results are fed back, and the loop terminates on a final answer or at
  ``max_steps``. Tool calls are audited individually.
* **Offline path** — no model, no network. A fixed pipeline (retrieve → analyse → resol-
  conf licts) assembles a citation-backed answer from the same tools. It is slower-witted
  than an LLM but never invents a provision, which is the correct trade-off in an
  air-gapped environment.

Both paths enforce the citation guardrail: an answer with regulatory claims but no
authority is flagged rather than presented as complete.
"""

from __future__ import annotations

import contextlib
import re
import time
from datetime import date
from typing import Any

from anjali.agent.prompts import build_system_prompt
from anjali.agent.tools import AgentContext, ToolResult, call_tool, tool_specs
from anjali.core.models import AgentResult, AgentStep, Citation, Severity
from anjali.core.util import truncate
from anjali.providers.base import LLMProvider, Message, estimate_tokens

CASE_KEYWORDS = {
    "analyse", "analyze", "analysis", "review", "investigate", "case", "dataset", "our data",
    "transactions", "patterns", "what stands out", "findings", "risk score",
    "structuring", "layering", "smurfing", "mule", "velocity", "dormant", "round-trip",
}
CONFLICT_KEYWORDS = {
    "eu", "uk", "us", "cross-border", "cross border", "jurisdiction", "jurisdictions",
    "conflict", "diverge", "parent", "group", "both", "america", "europe", "britain",
}
SANCTIONS_KEYWORDS = {"sanction", "sanctions", "ofac", "sdn", "screening", "screen", "designated", "blocked"}

CITATION_PATTERN = re.compile(
    r"(31\s+C?F?R|31\s+USC|\bAMLD\d?\b|\bAML[RD]\b|\bGDPR\b|\bPOCA\b|\bMLR\b|"
    r"Recommendation\s+\d+|Article\s+\d+|s\.\s?\d+|§\s?[\d.]+|\bFATF\b|\bPSD2\b|\bAI Act\b)",
    re.IGNORECASE,
)


def _looks_like_case_question(question: str) -> bool:
    text = question.lower()
    return any(k in text for k in CASE_KEYWORDS)


def _mentions_conflicts(question: str) -> bool:
    text = question.lower()
    return any(k in text for k in CONFLICT_KEYWORDS)


def _has_case(ctx: AgentContext) -> bool:
    try:
        return bool(ctx.db.scalar("SELECT COUNT(*) FROM transactions"))
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Offline pipeline
# --------------------------------------------------------------------------- #
def run_offline(question: str, ctx: AgentContext, *, audit: Any = None) -> AgentResult:
    steps: list[AgentStep] = []
    citations: dict[str, Citation] = {}
    started = time.perf_counter()

    def record(kind: str, content: str, *, tool: str | None = None, obs: str | None = None,
               t0: float | None = None) -> None:
        steps.append(
            AgentStep(
                step=len(steps) + 1,
                kind=kind,  # type: ignore[arg-type]
                content=content,
                tool=tool,
                observation=obs,
                duration_ms=int((time.perf_counter() - (t0 or started)) * 1000),
            )
        )

    record("thought", "Offline mode: retrieving provisions in force before answering.")

    t0 = time.perf_counter()
    search = call_tool(ctx, "search_regulations", {"query": question, "top_k": 7})
    citations.update({c.doc_id: c for c in search.citations})
    record("tool_call", "search_regulations", tool="search_regulations", t0=t0,
           obs=search.summary)

    analysis = None
    if _has_case(ctx) and _looks_like_case_question(question):
        t0 = time.perf_counter()
        analysis_result = call_tool(ctx, "analyze_transactions", {"max_findings": 12})
        citations.update({c.doc_id: c for c in analysis_result.citations})
        record("tool_call", "analyze_transactions", tool="analyze_transactions", t0=t0,
               obs=analysis_result.summary)
        analysis = analysis_result

    conflicts_result = None
    if _mentions_conflicts(question) or analysis is not None:
        t0 = time.perf_counter()
        topic = question if _mentions_conflicts(question) else "sar disclosure"
        conflicts_result = call_tool(ctx, "find_conflicts", {"topic": topic})
        citations.update({c.doc_id: c for c in conflicts_result.citations})
        record("tool_call", "find_conflicts", tool="find_conflicts", t0=t0,
               obs=conflicts_result.summary)

    sanctions_result = None
    lowered = question.lower()
    if any(k in lowered for k in SANCTIONS_KEYWORDS) and _has_case(ctx):
        t0 = time.perf_counter()
        from anjali.analysis.ingest import fetch_customers

        for customer in fetch_customers(ctx.db)[:3]:
            result = call_tool(
                ctx, "screen_sanctions",
                {"name": customer.name, "dob": customer.dob, "country": customer.country},
            )
            citations.update({c.doc_id: c for c in result.citations})
            record("tool_call", f"screen_sanctions({customer.name})", tool="screen_sanctions",
                   t0=t0, obs=result.summary)
            sanctions_result = result

    answer = _compose_offline(question, search, analysis, conflicts_result, sanctions_result, ctx)
    severity = _infer_severity(answer, analysis)
    if severity is None:
        # The output contract requires a stated risk level on every answer. An advisory
        # question has no case risk, and saying so is more honest than inventing one.
        severity = Severity.LOW
        answer = (
            answer.rstrip()
            + "\n\n**Risk level:** LOW — this is an advisory question; no case-specific "
            "customer or transaction risk was assessed. Load a case (`anjali analyze`) to get "
            "a scored assessment."
        )
    record("answer", answer)

    result = AgentResult(
        question=question,
        answer=answer,
        steps=steps,
        citations=_top_citations(citations),
        risk_level=severity,
        confidence=0.62 if analysis is not None else 0.66,
        provider="offline",
        model="anjali-offline-analyst",
        offline=True,
        tokens_estimate=estimate_tokens(answer),
    )
    if audit is not None:
        result.audit_ref = audit.append(
            "agent.answer.offline",
            subject=truncate(question, 120),
            details={
                "steps": [{"kind": s.kind, "tool": s.tool, "observation": s.observation} for s in steps],
                "citations": [c.citation for c in result.citations],
                "confidence": result.confidence,
            },
        ).hash
    return result


def _compose_offline(
    question: str,
    search: ToolResult,
    analysis: ToolResult | None,
    conflicts: ToolResult | None,
    sanctions: ToolResult | None,
    ctx: AgentContext,
) -> str:
    as_of = (ctx.as_of or date.today()).isoformat()
    out: list[str] = []
    out.append(f"**Offline synthesis — provisions in force as of {as_of}.**")
    out.append("")

    provisions = (search.payload or {}).get("results", []) if isinstance(search.payload, dict) else []
    if provisions:
        out.append("**Applicable authority**")
        out.append("")
        for i, item in enumerate(provisions[:6], 1):
            flag = ""
            if item.get("stale"):
                flag = " _(no longer in force at the analysis date — historical only)_"
            elif item.get("not_yet_in_force"):
                flag = " _(not yet in force at the analysis date)_"
            out.append(f"{i}. **{item['citation']}** — {item['title']} [{item['jurisdiction']}]{flag}")
            if item.get("snippet"):
                out.append(f"   > {item['snippet']}")
        out.append("")
    else:
        out.append(
            "No provision in the corpus matched this question. I will not answer a regulatory "
            "question from memory — refine the query or extend the corpus with "
            "`anjali kb add <file>`."
        )
        out.append("")

    if sanctions is not None and isinstance(sanctions.payload, dict):
        payload = sanctions.payload
        if payload.get("banner"):
            out.append(f"**{payload['banner']}** Screening hit requiring review.")
            out.append("")
            for match in payload.get("matches", [])[:3]:
                out.append(
                    f"- {match['matched_name']} — {match['list_name']} "
                    f"({match['tier']}, score {match['score']:.2f})"
                )
            out.append(
                "  Blocking obligations are strict-liability and time-bound. Escalate to the "
                "sanctions team immediately; do not release funds pending review."
            )
            out.append("")
        else:
            out.append(f"No sanctions match at or above threshold for the screened subjects "
                       f"(list version `{payload.get('list_version')}`).")
            out.append("")

    if analysis is not None and isinstance(analysis.payload, dict):
        payload = analysis.payload
        risk = payload.get("risk") or {}
        summary = payload.get("summary") or {}
        out.append(
            f"**Case assessment** — risk {risk.get('overall')}/100 ({risk.get('band')}), "
            f"{summary.get('findings_total', 0)} findings across "
            f"{len(summary.get('by_typology') or {})} typologies."
        )
        out.append("")
        for finding in payload.get("findings", [])[:6]:
            cites = ", ".join(finding.get("citations") or []) or "uncited"
            out.append(
                f"- **{finding['severity']}** · {finding['typology']} — {finding['summary']} "
                f"_(confidence {finding['confidence']:.0%}; {cites})_"
            )
        out.append("")
        if payload.get("detectors_skipped"):
            out.append(f"Detectors skipped: {'; '.join(payload['detectors_skipped'])}")
            out.append("")

    if conflicts is not None and isinstance(conflicts.payload, dict):
        items = conflicts.payload.get("conflicts", [])
        if items:
            out.append("**Cross-jurisdiction divergences**")
            out.append("")
            for item in items[:4]:
                out.append(f"- **{item['title']}** ({item['severity']}) — {item['divergence']}")
                out.append(f"  Resolution: {item['resolution'][0]}")
            out.append("")

    if analysis is not None:
        # Only a case produces a scored risk level. For an advisory question the caller
        # appends the single "advisory" line, so the answer never carries two verdicts.
        out.append(
            "**Risk level:** " + _severity_word(analysis)
            + " — based on the findings and the authority above; a named reviewer must confirm."
        )
    out.append("")
    out.append(
        "**Confidence: 62%.** This is deterministic synthesis (no language model was called). "
        "The retrieval and the detectors are reproducible; the interpretation is not "
        "context-aware. Provider-backed mode gives a richer reading of the same evidence."
    )
    out.append("")
    out.append(
        "_ANJALI drafts and advises; it does not file, block, exit or clear. Human sign-off is "
        "required before any customer-affecting action._"
    )
    return "\n".join(out)


def _severity_word(analysis: ToolResult | None) -> str:
    if analysis is None or not isinstance(analysis.payload, dict):
        return "NOT ASSESSED (no case data)"
    risk = analysis.payload.get("risk") or {}
    band = str(risk.get("band") or "MEDIUM")
    return band


def _infer_severity(answer: str, analysis: ToolResult | None) -> Severity | None:
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if f"**{severity}**" in answer:
            return Severity(severity)
        if re.search(rf"risk level[^\n]{{0,20}}{severity}", answer, re.IGNORECASE):
            return Severity(severity)
    if isinstance(analysis.payload if analysis else None, dict):
        band = (analysis.payload.get("risk") or {}).get("band")  # type: ignore[union-attr]
        if band:
            return Severity(str(band))
    return None


def _top_citations(citations: dict[str, Citation], limit: int = 12) -> list[Citation]:
    ordered = sorted(citations.values(), key=lambda c: (-c.score, c.citation))
    return ordered[:limit]


# --------------------------------------------------------------------------- #
# LLM loop
# --------------------------------------------------------------------------- #
def run_llm(
    question: str,
    ctx: AgentContext,
    provider: LLMProvider,
    *,
    max_steps: int = 8,
    temperature: float | None = None,
    audit: Any = None,
    verbose: Any = None,
) -> AgentResult:
    steps: list[AgentStep] = []
    citations: dict[str, Citation] = {}

    corpus_stats = None
    with contextlib.suppress(Exception):
        corpus_stats = ctx.kb.stats()
    case_summary = None
    if _has_case(ctx):
        try:
            summary_result = call_tool(ctx, "case_summary", {})
            case_summary = summary_result.payload if isinstance(summary_result.payload, dict) else None
        except Exception:
            case_summary = None

    system = build_system_prompt(
        as_of=ctx.as_of,
        jurisdictions=ctx.jurisdictions,
        corpus_stats=corpus_stats,
        case_summary=case_summary,
    )
    messages: list[Message] = [Message(role="user", content=question)]
    final_text = ""
    tool_calls_made = 0

    for step_index in range(1, max_steps + 1):
        t0 = time.perf_counter()
        response = provider.complete(
            messages, tool_specs(), system=system, temperature=temperature
        )
        duration = int((time.perf_counter() - t0) * 1000)

        if response.text:
            steps.append(
                AgentStep(step=len(steps) + 1, kind="thought", content=truncate(response.text, 1200),
                          duration_ms=duration)
            )
            if verbose:
                verbose("thought", response.text)

        if not response.tool_calls:
            final_text = response.text
            break

        messages.append(
            Message(role="assistant", content=response.text, tool_calls=response.tool_calls)
        )
        for tc in response.tool_calls:
            tool_calls_made += 1
            call_started = time.perf_counter()
            result = call_tool(ctx, tc.name, tc.arguments)
            for cit in result.citations:
                citations.setdefault(f"{cit.doc_id}:{cit.citation}", cit)
            steps.append(
                AgentStep(
                    step=len(steps) + 1,
                    kind="tool_call",
                    tool=tc.name,
                    arguments=tc.arguments,
                    observation=truncate(result.summary or result.error or "", 400),
                    duration_ms=int((time.perf_counter() - call_started) * 1000),
                )
            )
            if verbose:
                verbose("tool", f"{tc.name}({tc.arguments}) → {result.summary or result.error}")
            if audit is not None:
                audit.append(
                    "agent.tool_call",
                    subject=tc.name,
                    details={
                        "arguments": tc.arguments,
                        "summary": result.summary,
                        "error": result.error,
                        "citations": [c.citation for c in result.citations],
                    },
                )
            messages.append(
                Message(
                    role="tool",
                    tool_call_id=tc.id,
                    name=tc.name,
                    content=result.for_model(),
                )
            )
        if step_index == max_steps:
            messages.append(
                Message(
                    role="user",
                    content=(
                        "Step budget reached. Produce your final answer now using only the "
                        "evidence already gathered, with citations. State any gaps explicitly."
                    ),
                )
            )
            response = provider.complete(messages, [], system=system, temperature=temperature)
            final_text = response.text
            break

    if not final_text.strip():
        final_text = (
            "The agent did not produce a final answer within the step budget. "
            "The evidence gathered is listed in the trace; re-run with `--max-steps` higher or "
            "ask a narrower question."
        )

    final_text, guardrail_note = _citation_guardrail(question, final_text, citations, ctx)
    if guardrail_note:
        steps.append(AgentStep(step=len(steps) + 1, kind="guardrail", content=guardrail_note))

    severity = _severity_from_text(final_text)

    result = AgentResult(
        question=question,
        answer=final_text,
        steps=steps,
        citations=_top_citations(citations),
        risk_level=severity,
        confidence=0.8 if citations else 0.5,
        provider=provider.name,
        model=provider.model,
        offline=False,
        tokens_estimate=estimate_tokens(final_text),
    )
    if audit is not None:
        result.audit_ref = audit.append(
            "agent.answer",
            subject=truncate(question, 120),
            details={
                "provider": provider.name,
                "model": provider.model,
                "tool_calls": tool_calls_made,
                "citations": [c.citation for c in result.citations],
                "answer_digest_input": final_text[:200],
                "guardrail": guardrail_note,
            },
        ).hash
    return result


def _severity_from_text(text: str) -> Severity | None:
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if re.search(rf"\b{severity}\b", text):
            return Severity(severity)
    return None


def _citation_guardrail(
    question: str,
    answer: str,
    citations: dict[str, Citation],
    ctx: AgentContext,
) -> tuple[str, str | None]:
    """A prompt is a request. This is the control.

    If the answer makes a regulatory claim without authority, the answer is amended rather
    than silently shipped: the analyst sees the gap and the retrieved provisions.
    """
    claims_regulation = bool(CITATION_PATTERN.search(question)) or any(
        word in question.lower()
        for word in ("must", "require", "allowed", "lawful", "permitted", "threshold", "deadline", "penalty")
    )
    cites_in_answer = bool(CITATION_PATTERN.search(answer))
    if not claims_regulation:
        return answer, None
    if cites_in_answer and citations:
        return answer, None

    note = "[CITATION GUARDRAIL] The answer did not carry an explicit regulatory citation."
    appendix = ["", "---", "**Authorities retrieved for this question (auto-attached):**"]
    if citations:
        for cit in _top_citations(citations, 6):
            appendix.append(f"- {cit.citation} — {cit.title}")
    else:
        fallback = call_tool(ctx, "search_regulations", {"query": question, "top_k": 4})
        if fallback.citations:
            for cit in fallback.citations:
                citations.setdefault(f"{cit.doc_id}:{cit.citation}", cit)
                appendix.append(f"- {cit.citation} — {cit.title}")
        else:
            appendix.append("- No provision in the corpus supports this answer. Treat it as unverified.")
    appendix.append("")
    appendix.append(
        "_Uncited regulatory statements must be verified before use. Run `anjali kb search \"…\"` "
        "to inspect the underlying provisions._"
    )
    return answer + "\n".join(appendix), note


def run(
    question: str,
    ctx: AgentContext,
    provider: LLMProvider | None = None,
    *,
    max_steps: int = 8,
    audit: Any = None,
    verbose: Any = None,
) -> AgentResult:
    if provider is None or provider.is_offline:
        return run_offline(question, ctx, audit=audit)
    return run_llm(question, ctx, provider, max_steps=max_steps, audit=audit, verbose=verbose)
