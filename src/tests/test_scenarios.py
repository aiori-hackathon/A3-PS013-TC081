from __future__ import annotations

import json
from pathlib import Path

from incident_timeline.scenarios import SCENARIOS, create_demo_cases


def test_three_synthetic_scenarios_reconstruct_expected_timelines(tmp_path: Path) -> None:
    results = create_demo_cases(tmp_path / "demos")
    assert len(SCENARIOS) == 3
    assert len(results) == 3
    assert all(result["passed"] for result in results)
    assert all(result["integrity_ok"] for result in results)
    assert all(result["gap_count"] == 0 for result in results)

    for result in results:
        folder = tmp_path / "demos" / result["scenario_id"]
        expected = json.loads((folder / "expected.json").read_text(encoding="utf-8"))
        actual = json.loads((folder / "run-result.json").read_text(encoding="utf-8"))
        assert actual["event_count"] == expected["event_count"]
        assert actual["actual_action_counts"] == expected["action_counts"]
        assert actual["actual_timeline"] == expected["expected_timeline"]
        assert (folder / "case" / "normalised" / "events.jsonl").is_file()
        assert (folder / "inputs").is_dir()


def test_synthetic_scenario_logs_are_reproducible(tmp_path: Path) -> None:
    root_a = tmp_path / "first"
    root_b = tmp_path / "second"
    create_demo_cases(root_a)
    create_demo_cases(root_b)
    for scenario_id in SCENARIOS:
        a = root_a / scenario_id
        b = root_b / scenario_id
        assert json.loads((a / "expected.json").read_text()) == json.loads((b / "expected.json").read_text())
        for name in SCENARIOS[scenario_id]["logs"]:
            assert (a / "inputs" / name).read_bytes() == (b / "inputs" / name).read_bytes()


def test_demo_generation_can_be_rerun_into_the_same_output_folder(tmp_path: Path) -> None:
    output = tmp_path / "demos"
    first = create_demo_cases(output)
    second = create_demo_cases(output)
    assert all(result["passed"] for result in first)
    assert all(result["passed"] for result in second)
    for result in second:
        case_meta = json.loads((Path(result["case_path"]) / "case.json").read_text(encoding="utf-8"))
        assert len(case_meta["sources"]) == len(SCENARIOS[result["scenario_id"]]["logs"])


def test_demo_generation_can_run_one_selected_scenario(tmp_path: Path) -> None:
    selected = "02-web-exploit-to-server-access"
    results = create_demo_cases(tmp_path / "single-demo", scenario_ids=[selected])
    assert len(results) == 1
    result = results[0]
    assert result["scenario_id"] == selected
    assert result["passed"] is True
    assert result["source_count"] == 2
    assert result["input_files"] == ["access.log", "auth.log"]
    assert result["checks"]["expected_timeline"]["passed"] is True
    assert result["checks"]["evidence_integrity"]["passed"] is True
    manifest = json.loads((tmp_path / "single-demo" / "manifest.json").read_text(encoding="utf-8"))
    assert [scenario["scenario_id"] for scenario in manifest["scenarios"]] == [selected]


def test_demo_generation_rejects_unknown_or_empty_scenario_selection(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(ValueError, match="unknown scenario_id"):
        create_demo_cases(tmp_path / "unknown", scenario_ids=["not-a-real-scenario"])
    with pytest.raises(ValueError, match="at least one scenario_id"):
        create_demo_cases(tmp_path / "empty", scenario_ids=[])
