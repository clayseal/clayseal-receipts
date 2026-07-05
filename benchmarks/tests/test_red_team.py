from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.adapters.registry import iter_cases  # noqa: E402
from harness.runner import run_benchmarks  # noqa: E402


def test_red_team_cases_exist():
    cases = list(iter_cases("red_team"))
    assert len(cases) >= 10
    categories = {case.metadata.get("red_team_category") for case in cases}
    assert "control" in categories
    assert "baseline" in categories
    assert "blind_spot" in categories


def test_red_team_suite_runs():
    report = run_benchmarks(
        suites=["red_team"],
        export_receipts=True,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_red_team",
    )
    summary = next(s for s in report.suites if s.suite == "red_team")
    assert summary.total >= 10
    assert summary.control_pass_rate == 1.0
    assert summary.baseline_pass_rate == 1.0
    controls = [c for c in report.cases if c.metadata.get("red_team_category") == "control"]
    assert all(c.ok for c in controls)
    assert summary.red_team_metrics is not None
    assert summary.red_team_metrics["rates"]["mitigation_regression_rate"] == 0.0
