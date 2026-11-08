from __future__ import annotations

from anjali.sim.adversary import SCENARIOS, build_case, evaluate_case, run, to_markdown


def test_every_typology_has_a_scenario():
    covered = {typology for typology, _ in SCENARIOS.values()}
    assert len(SCENARIOS) >= 11
    assert {
        "structuring",
        "smurfing",
        "layering",
        "round_tripping",
        "mule_network",
        "tbml",
        "velocity_anomaly",
        "dormant_reactivation",
        "high_risk_geography",
        "threshold_avoidance",
        "cash_intensity",
    } == covered


def test_full_run_detects_every_injected_scenario():
    result = run(seed=7)
    assert result.overall["recall"] == 1.0
    assert result.overall["missed"] == []


def test_benign_traffic_does_not_produce_findings():
    """Cafés, landlords and parity invoicing must not be reported as suspicious."""
    result = run(seed=7)
    assert result.overall["false_positives"] == 0
    for case in result.cases:
        assert case["false_positives"] == [], case["case"]


def test_runs_are_reproducible_for_a_seed():
    first = run(seed=11, scenarios=["structuring-classic"])
    second = run(seed=11, scenarios=["structuring-classic"])
    assert first.overall == second.overall


def test_a_weakened_configuration_shows_up_as_a_control_gap():
    """The simulator must be able to fail — otherwise it measures nothing."""
    from anjali.analysis.patterns import DetectorConfig

    strict = DetectorConfig(structuring_min_count=99)
    result = run(seed=7, scenarios=["structuring-classic"], config=strict)
    assert result.overall["detected"] < result.overall["injected"]
    assert result.overall["missed"]
    assert result.overall["verdict"]


def test_case_builder_is_deterministic_and_labelled():
    case = build_case("mule-cluster", seed=3)
    assert case.ground_truth
    assert all(truth.txn_ids for truth in case.ground_truth)
    again = build_case("mule-cluster", seed=3)
    assert [t.txn_id for t in case.transactions][:5] == [t.txn_id for t in again.transactions][:5]


def test_evaluate_case_reports_evidence_overlap():
    report = evaluate_case(build_case("tbml-overinvoicing", seed=7))
    assert report["rows"][0]["detected"] is True
    assert report["rows"][0]["overlap_txns"] >= 1


def test_markdown_report_states_the_limitation():
    text = to_markdown(run(seed=7, scenarios=["round-tripping"]))
    assert "Recall" in text
    assert "Synthetic data only" in text
