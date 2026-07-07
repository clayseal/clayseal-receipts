from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.prove_compare import build_prove_comparison, run_prove_comparison  # noqa: E402
from harness.runner import run_benchmarks  # noqa: E402
from harness.types import SuiteSummary  # noqa: E402


@pytest.fixture(autouse=True)
def _allow_stub(monkeypatch):
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_STUB", "1")


@pytest.mark.requires_ulb
@pytest.mark.requires_prover
def test_prove_mode_ulb_limit_10():
    report = run_benchmarks(
        suites=["ulb_fraud"],
        limit=10,
        mode="prove",
        export_receipts=True,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_prove_10",
    )
    summary = report.suites[0]
    assert summary.passed == 10
    assert summary.prove_metrics is not None
    assert summary.prove_metrics["counts"]["cases"] == 10
    assert summary.prove_metrics["proof_bytes"]["avg"] > 8000
    assert summary.prove_metrics["latency_ms"]["p95"] >= summary.prove_metrics["latency_ms"]["p50"]
    assert summary.verify_valid_rate == 1.0


def test_prove_comparison_structure(tmp_path):
    baseline = SuiteSummary(
        suite="ulb_fraud",
        total=5,
        passed=5,
        failed=0,
        skipped=0,
        avg_latency_ms=1.5,
        p50_latency_ms=1.2,
        p95_latency_ms=2.0,
        verify_valid_rate=0.0,
    )
    prove = SuiteSummary(
        suite="ulb_fraud",
        total=5,
        passed=5,
        failed=0,
        skipped=0,
        avg_latency_ms=500.0,
        p50_latency_ms=480.0,
        p95_latency_ms=600.0,
        verify_valid_rate=1.0,
        prove_metrics={
            "proof_bytes": {"avg": 9000, "min": 9000, "max": 9100},
        },
    )
    comparison = build_prove_comparison(suite="ulb_fraud", limit=5, baseline=baseline, prove=prove)
    assert comparison["comparison"]["latency_slowdown_avg"] == pytest.approx(500 / 1.5, rel=0.01)
    assert comparison["comparison"]["verify_valid_delta"] == 1.0


@pytest.mark.requires_ulb
@pytest.mark.skipif(
    os.environ.get("EV201_FULL") != "1",
    reason="Set EV201_FULL=1 to run N=100 prove comparison (~60s)",
)
def test_prove_comparison_n100():
    comparison, baseline_report, prove_report = run_prove_comparison(
        suite="ulb_fraud",
        limit=100,
        results_dir=BENCHMARKS_ROOT / "results",
    )
    assert comparison["bounded_auto"]["passed"] == 100
    assert comparison["prove"]["passed"] == 100
    assert comparison["prove"]["verify_valid_rate"] == 1.0
    assert comparison["comparison"]["latency_slowdown_avg"] > 100
    assert baseline_report.suites[0].avg_latency_ms < prove_report.suites[0].avg_latency_ms
