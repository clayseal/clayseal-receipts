from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.adapters.registry import iter_cases  # noqa: E402
from harness.config import AdapterOptions  # noqa: E402
from harness.runner import _percentile, run_benchmarks  # noqa: E402


def test_percentile_interpolation():
    assert _percentile([1.0, 2.0, 3.0, 4.0], 50) == 2.5
    assert _percentile([5.0], 95) == 5.0


@pytest.mark.skipif(
    not (BENCHMARKS_ROOT / "corpus" / "ulb_creditcard" / "creditcard.csv").is_file(),
    reason="ULB corpus not downloaded",
)
def test_ulb_stratified_includes_fraud_rows():
    opts = AdapterOptions(limit=100, ulb_sample="stratified")
    cases = list(iter_cases("ulb_fraud", limit=100, options=opts))
    assert len(cases) == 100
    fraud = sum(1 for case in cases if case.metadata.get("class") == 1)
    assert fraud >= 10


@pytest.mark.skipif(
    not (BENCHMARKS_ROOT / "corpus" / "tau2_bench").is_dir(),
    reason="tau2 corpus not downloaded",
)
def test_tau2_multi_domain_cases():
    opts = AdapterOptions(tau2_domains=["mock", "airline", "retail"])
    cases = list(iter_cases("tau2_policy", limit=500, options=opts))
    domains = {case.metadata.get("domain") for case in cases}
    assert "mock" in domains
    assert "airline" in domains or "retail" in domains
    assert len(cases) > 8


@pytest.mark.requires_bfcl
def test_summary_includes_latency_percentiles():
    report = run_benchmarks(
        suites=["bfcl_caps"],
        limit=5,
        export_receipts=False,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_percentiles",
    )
    summary = report.suites[0].to_dict()
    assert summary["p50_latency_ms"] is not None
    assert summary["p95_latency_ms"] is not None
    assert summary["audit_chain_ok_rate"] == 1.0
