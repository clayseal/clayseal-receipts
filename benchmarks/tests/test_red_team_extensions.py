from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.adapters.registry import iter_cases  # noqa: E402
from harness.config import AdapterOptions  # noqa: E402
from harness.fraud_metrics import decision_label_mismatch  # noqa: E402
from harness.runner import run_benchmarks  # noqa: E402


def test_decision_label_mismatch():
    assert decision_label_mismatch("approve", 1) is True
    assert decision_label_mismatch("deny", 1) is False
    assert decision_label_mismatch("approve", 0) is False
    assert decision_label_mismatch("deny", 0) is True


@pytest.mark.skipif(
    not (BENCHMARKS_ROOT / "corpus" / "ulb_creditcard" / "creditcard.csv").is_file(),
    reason="ULB corpus not downloaded",
)
def test_ulb_summary_includes_label_mismatch_rate():
    report = run_benchmarks(
        suites=["ulb_fraud"],
        limit=50,
        export_receipts=False,
        adapter_options=AdapterOptions(limit=50, ulb_sample="stratified"),
        results_dir=BENCHMARKS_ROOT / "results" / "_test_label_mismatch",
    )
    summary = report.suites[0]
    assert summary.label_mismatch_rate is not None
    assert 0.0 <= summary.label_mismatch_rate <= 1.0
    mismatches = [case.metadata.get("label_mismatch") for case in report.cases]
    assert all(value is not None for value in mismatches)


@pytest.mark.skipif(
    not (BENCHMARKS_ROOT / "corpus" / "mcp_agent_trajectory_benchmark").is_dir(),
    reason="ATIF corpus not downloaded",
)
def test_atif_tight_mode_blocks_extra_tools():
    opts = AdapterOptions(limit=3, policy_mode="tight")
    cases = list(iter_cases("atif_mcp", limit=3, options=opts))
    assert cases
    assert all(case.metadata.get("policy_mode") == "tight" for case in cases)
    report = run_benchmarks(
        suites=["atif_mcp"],
        limit=3,
        export_receipts=False,
        adapter_options=opts,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_atif_tight",
    )
    summary = report.suites[0]
    assert summary.total > 0
    blocked = [case.metadata.get("tool_calls_blocked", 0) for case in report.cases]
    assert any(count > 0 for count in blocked)


@pytest.mark.skipif(
    not (BENCHMARKS_ROOT / "corpus" / "tau2_bench").is_dir(),
    reason="tau2 corpus not downloaded",
)
def test_tau2_tight_mode_blocks_extra_actions():
    opts = AdapterOptions(limit=20, tau2_domains=["mock", "airline"], policy_mode="tight")
    report = run_benchmarks(
        suites=["tau2_policy"],
        limit=20,
        export_receipts=False,
        adapter_options=opts,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_tau2_tight",
    )
    summary = report.suites[0]
    assert summary.total > 0
    multi_tool = [
        case
        for case in report.cases
        if (case.metadata.get("action_tool_count") or 0) > 1
    ]
    if multi_tool:
        assert any(case.metadata.get("blocked", 0) > 0 for case in multi_tool)


def test_red_team_identity_blind_spot_without_identity():
    report = run_benchmarks(
        suites=["red_team"],
        export_receipts=False,
        with_identity=False,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_rt_no_identity",
    )
    case = next(c for c in report.cases if c.case_id == "blind_spot_no_spiffe_without_identity")
    assert case.ok
    assert case.metadata.get("observed") == "no_spiffe_in_bundle"


def test_red_team_spiffe_baseline_with_identity():
    report = run_benchmarks(
        suites=["red_team"],
        export_receipts=False,
        with_identity=True,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_rt_with_identity",
    )
    case = next(c for c in report.cases if c.case_id == "baseline_spiffe_with_identity")
    assert case.ok
    assert case.metadata.get("observed") == "spiffe_in_bundle"
    assert case.metadata.get("spiffe_id", "").startswith("spiffe://")
