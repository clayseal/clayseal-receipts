from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.runner import run_benchmarks  # noqa: E402


@pytest.mark.requires_ulb_atif
def test_identity_at_scale_ulb_and_atif():
    report = run_benchmarks(
        suites=["ulb_fraud", "atif_mcp"],
        limit=20,
        export_receipts=True,
        with_identity=True,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_identity_at_scale",
    )
    by_suite = {suite.suite: suite for suite in report.suites}
    assert by_suite["ulb_fraud"].passed == by_suite["ulb_fraud"].total
    assert by_suite["atif_mcp"].passed == by_suite["atif_mcp"].total

    for name in ("ulb_fraud", "atif_mcp"):
        metrics = by_suite[name].identity_metrics
        assert metrics is not None
        rates = metrics["rates"]
        assert rates["spiffe_in_authority_rate"] == 1.0
        assert rates["identity_section_rate"] == 1.0
        assert rates["identity_verify_ok_rate"] == 1.0
        assert rates["live_validate_ok_rate"] == 1.0


@pytest.mark.requires_ulb
@pytest.mark.requires_prover
def test_prove_mode_ulb_smoke():
    report = run_benchmarks(
        suites=["ulb_fraud"],
        limit=5,
        mode="prove",
        export_receipts=True,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_prove_smoke",
    )
    summary = report.suites[0]
    assert summary.passed == summary.total
    assert summary.prove_metrics is not None
    assert summary.prove_metrics["counts"]["cases"] == 5
    assert summary.prove_metrics["proof_bytes"]["avg"] > 0
