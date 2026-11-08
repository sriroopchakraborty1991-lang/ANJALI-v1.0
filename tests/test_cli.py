"""End-to-end tests through the actual command line.

These are the tests that would have caught the JSON corruption, the missing risk floor and
the subject-attribution bug, so they assert on observable output rather than internals.
"""

from __future__ import annotations

import json

from anjali.cli.main import app


def invoke(runner, args, **kwargs):
    return runner.invoke(app, args, **kwargs)


def machine(result) -> dict:
    """Parse machine output. Progress and checklists go to stderr, which may be merged."""
    raw = getattr(result, "stdout", "") or result.output
    return json.loads(raw)


def test_version_flag(runner):
    result = invoke(runner, ["--version"])
    assert result.exit_code == 0
    assert "ANJALI-AI" in result.output


def test_bare_invocation_prints_guidance(runner, workspace):
    result = invoke(runner, [])
    assert result.exit_code == 0
    assert "anjali" in result.output.lower()


def test_init_on_a_fresh_home(runner, tmp_path):
    home = tmp_path / "fresh"
    result = invoke(runner, ["--home", str(home), "--quiet", "init"])
    assert result.exit_code == 0, result.output
    assert (home / "anjali.db").exists()
    assert (home / "config.json").exists()


def test_doctor_passes_on_a_healthy_workspace(runner, workspace):
    result = invoke(runner, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "All checks passed" in result.output


def test_analyze_json_is_machine_readable(runner, workspace):
    result = invoke(runner, ["analyze", "--dataset", "demo", "--json"])
    assert result.exit_code == 0, result.output
    payload = machine(result)
    assert payload["risk"]["band"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert len(payload["findings"]) >= 8
    for finding in payload["findings"]:
        assert finding["regulatory_refs"]


def test_analyze_gate_fails_the_build_on_critical_findings(runner, workspace):
    result = invoke(runner, ["analyze", "--dataset", "demo", "--fail-on", "critical"])
    assert result.exit_code == 1


def test_analyze_gate_passes_when_threshold_is_not_met(runner, workspace):
    result = invoke(runner, ["analyze", "--dataset", "demo", "--fail-on", "impossible"])
    assert result.exit_code in {0, 2}


def test_analyze_lists_its_detectors(runner, workspace):
    result = invoke(runner, ["analyze", "--detectors"])
    assert result.exit_code == 0
    assert "structuring" in result.output


def test_screen_flags_a_listed_name_with_json(runner, workspace):
    result = invoke(runner, ["screen", "Mohammed Al-Rashid", "--country", "SY", "--json"])
    assert result.exit_code == 0, result.output
    payload = machine(result)
    assert payload["results"][0]["disposition"] == "EXACT"
    assert payload["results"][0]["matches"][0]["tier"] == "EXACT"
    assert payload["list_version"]


def test_screen_marks_a_clear_name(runner, workspace):
    result = invoke(runner, ["screen", "Priya Sharma", "--country", "US", "--json"])
    payload = machine(result)
    first = payload["results"][0]
    assert first["disposition"] in {"CLEAR", "NONE"}
    assert first["matches"] == [] or first["matches"][0]["tier"] in {"WEAK", "POTENTIAL"}


def test_kb_search_is_cited(runner, workspace):
    result = invoke(runner, ["kb", "search", "structuring cash deposits", "-k", "3", "--json"])
    assert result.exit_code == 0, result.output
    payload = machine(result)
    assert payload["results"]
    assert payload["results"][0]["citation"]


def test_kb_verify_accepts_a_known_citation(runner, workspace):
    result = invoke(runner, ["kb", "verify", "31 CFR § 1010.311", "--json"])
    assert result.exit_code == 0, result.output
    assert machine(result)["found"] is True


def test_kb_verify_rejects_an_unknown_citation(runner, workspace):
    result = invoke(runner, ["kb", "verify", "31 CFR § 9999.999", "--json"])
    assert result.exit_code != 0


def test_conflicts_list_covers_the_library(runner, workspace):
    result = invoke(runner, ["conflicts", "list", "--json"])
    assert result.exit_code == 0, result.output
    payload = machine(result)
    assert len(payload["conflicts"]) >= 10
    assert payload["topics"]


def test_conflicts_show_names_both_sides(runner, workspace):
    result = invoke(runner, ["conflicts", "show", "sar-group-disclosure"])
    assert result.exit_code == 0
    lowered = result.output.lower()
    assert "us" in lowered and "eu" in lowered and "uk" in lowered


def test_sar_json_is_parseable_and_scored(runner, workspace):
    result = invoke(runner, ["sar", "--dataset", "demo", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = machine(result)
    assert payload["quality"]["score"] >= 80
    assert payload["subjects"]


def test_sar_writes_markdown_to_disk(runner, workspace, tmp_path):
    destination = tmp_path / "out" / "sar.md"
    result = invoke(runner, ["--quiet", "sar", "--dataset", "demo", "-o", str(destination)])
    assert result.exit_code == 0, result.output
    assert destination.exists()
    assert "Prepared by" in destination.read_text(encoding="utf-8")


def test_ctr_worksheet_finds_the_reportable_deposit(runner, workspace):
    result = invoke(runner, ["ctr", "--dataset", "demo", "--json"])
    assert result.exit_code == 0, result.output
    payload = machine(result)
    assert payload["count"] == 1
    assert payload["filings"][0]["account"] == "ACC-9001"


def test_simulate_passes_its_own_control_gate(runner, workspace):
    result = invoke(runner, ["simulate", "--fail-under", "0.9", "--json"])
    assert result.exit_code == 0, result.output
    payload = machine(result)
    assert payload["overall"]["recall"] >= 0.9


def test_simulate_gate_can_fail(runner, workspace):
    result = invoke(runner, ["simulate", "--seed", "7", "--fail-under", "1.01"])
    assert result.exit_code != 0


def test_audit_chain_verifies_after_commands(runner, workspace):
    result = invoke(runner, ["audit", "verify", "--json"])
    assert result.exit_code == 0, result.output
    assert machine(result)["valid"] is True


def test_audit_log_is_exportable(runner, workspace, tmp_path):
    destination = tmp_path / "audit.md"
    result = invoke(runner, ["--quiet", "audit", "export", "-o", str(destination)])
    assert result.exit_code == 0, result.output
    assert destination.exists()


def test_ask_offline_answers_with_citations(runner, workspace):
    result = invoke(runner, ["ask", "What is the CTR threshold?", "--offline"])
    assert result.exit_code == 0, result.output
    assert "31 CFR" in result.output
    assert "Risk level" in result.output or "risk" in result.output.lower()


def test_as_of_limits_retrieval_to_provisions_in_force(runner, workspace):
    result = invoke(
        runner,
        ["--as-of", "2015-01-01", "kb", "search", "beneficial ownership", "--json"],
    )
    assert result.exit_code == 0, result.output
    payload = machine(result)
    assert all("EU 2024" not in row["citation"] for row in payload["results"])


def test_provider_status_reports_offline_without_a_key(runner, workspace):
    result = invoke(runner, ["providers"])
    assert result.exit_code == 0
    assert "offline" in result.output.lower()


def test_config_show_never_leaks_a_key(runner, workspace, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-secret-value")
    result = invoke(runner, ["config", "show"])
    assert result.exit_code == 0
    assert "sk-test-secret-value" not in result.output


def test_dataset_listing_includes_the_demo_case(runner, workspace):
    result = invoke(runner, ["data", "list", "--json"])
    payload = machine(result)
    assert "demo" in json.dumps(payload).lower()


def test_conflicts_relevant_is_machine_readable(runner, workspace):
    result = invoke(runner, ["conflicts", "relevant", "--json"])
    assert result.exit_code == 0, result.output
    payload = machine(result)
    assert payload["conflicts"]
    assert {"id", "severity", "resolution"} <= set(payload["conflicts"][0])


def test_investigate_exports_graph_formats(runner, workspace, tmp_path):
    destination = tmp_path / "graph.mmd"
    result = invoke(runner, ["--quiet", "investigate", "--format", "mermaid", "-o", str(destination)])
    assert result.exit_code == 0, result.output
    assert destination.exists()
    assert "graph" in destination.read_text(encoding="utf-8").lower()


def test_ask_states_exactly_one_risk_level(runner, workspace):
    result = invoke(runner, ["ask", "Can we share a SAR with our EU parent?", "--offline"])
    assert result.exit_code == 0, result.output
    assert result.output.count("Risk level") == 1
