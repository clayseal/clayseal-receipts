from __future__ import annotations

import sys
from pathlib import Path

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.adapters.registry import iter_cases  # noqa: E402
from harness.red_team_metrics import summarize_red_team  # noqa: E402
from harness.runner import run_benchmarks  # noqa: E402


def test_red_team_cases_tagged_by_surface():
    cases = list(iter_cases("red_team"))
    assert len(cases) >= 10
    for case in cases:
        assert case.metadata.get("attack_surface"), case.case_id
        assert case.metadata.get("defense_layer"), case.case_id


def test_red_team_metrics_structure():
    report = run_benchmarks(
        suites=["red_team"],
        export_receipts=False,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_red_team_metrics",
    )
    summary = next(s for s in report.suites if s.suite == "red_team")
    metrics = summary.red_team_metrics
    assert metrics is not None
    assert metrics["counts"]["controls"] >= 8
    assert metrics["rates"]["control_pass_rate"] == 1.0
    assert metrics["rates"]["schema_enforcement_rate"] == 1.0
    assert metrics["rates"]["tool_block_rate"] == 1.0
    assert metrics["by_attack_surface"]["fraud_schema"]["active"] >= 4
    assert metrics["documented_gaps"]["open_count"] >= 3
    assert len(metrics["attack_matrix"]) == summary.total

    summarized = summarize_red_team(report.cases)
    assert summarized["counts"]["regressions"] == 0
