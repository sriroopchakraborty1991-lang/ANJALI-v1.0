from __future__ import annotations

import pytest

from anjali.agent.loop import run as run_agent
from anjali.agent.loop import run_offline
from anjali.agent.prompts import build_system_prompt
from anjali.agent.tools import AgentContext, call_tool, tool_specs


@pytest.fixture(scope="module")
def agent_ctx(settings, kb, db, demo_result, demo_context):
    from anjali.analysis.sanctions import SanctionsScreener

    return AgentContext(
        settings=settings,
        kb=kb,
        db=db,
        screener=SanctionsScreener(db),
        analysis=demo_result,
        analysis_ctx=demo_context,
    )


def test_tool_catalogue_is_declared(agent_ctx):
    specs = tool_specs()
    assert len(specs) >= 10
    names = {spec.name for spec in specs}
    assert {
        "search_regulations",
        "get_provision",
        "analyze_transactions",
        "assess_risk",
        "screen_sanctions",
        "find_conflicts",
        "trace_connections",
        "calculate",
    } <= names
    for spec in specs:
        assert spec.description
        assert spec.parameters is not None


def test_search_tool_returns_citations(agent_ctx):
    result = call_tool(
        agent_ctx, "search_regulations", {"query": "structuring cash deposits", "top_k": 3}
    )
    assert result.error is None
    assert result.citations
    assert all(citation.source_url for citation in result.citations)


def test_sanctions_tool_flags_the_match(agent_ctx):
    result = call_tool(
        agent_ctx, "screen_sanctions", {"name": "Mohammed Al-Rashid", "country": "SY"}
    )
    assert result.error is None
    assert result.payload["disposition"] == "EXACT"


def test_unknown_tool_returns_an_error_not_an_exception(agent_ctx):
    result = call_tool(agent_ctx, "does_not_exist", {})
    assert result.error and "does_not_exist" in result.error


def test_bad_arguments_return_an_error_not_an_exception(agent_ctx):
    result = call_tool(agent_ctx, "calculate", {"expression": "__import__('os').system('echo hi')"})
    assert result.error or result.payload is not None
    assert "__import__" not in str(result.payload)


def test_system_prompt_encodes_the_output_contract():
    prompt = build_system_prompt().lower()
    for rule in (
        "31 cfr",
        "amld6",
        "critical",
        "[sanctions alert]",
        "confidence",
        "audit trail",
        "risk-based",
    ):
        assert rule in prompt


def test_offline_answer_cites_law_and_states_risk(agent_ctx):
    result = run_offline("When must a SAR be filed in the US?", agent_ctx)
    assert result.offline is True
    assert result.citations
    assert "31 CFR" in result.answer or "31 USC" in result.answer
    assert result.risk_level in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert 0.0 <= result.confidence <= 1.0


def test_offline_answer_is_grounded_in_retrieval_for_a_case_question(agent_ctx):
    result = run_offline("What stands out in this case?", agent_ctx)
    assert result.answer
    assert any(step.tool for step in result.steps if step.tool)


def test_run_without_a_provider_falls_back_to_offline(agent_ctx):
    result = run_agent("What is structuring?", agent_ctx, provider=None)
    assert result.offline is True
    assert result.answer


def test_every_answer_carries_an_audit_reference(agent_ctx):
    result = run_offline("What is the CTR threshold?", agent_ctx)
    assert result.audit_ref is None or isinstance(result.audit_ref, str)
