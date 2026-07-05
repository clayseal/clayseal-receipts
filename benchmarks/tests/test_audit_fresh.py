from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.runner import run_benchmarks  # noqa: E402


@pytest.mark.requires_ulb
def test_fresh_audit_db_ulb_200_completes_quickly():
    """Fresh audit DB per case keeps verify_chain O(1) — 200 cases should finish fast."""
    started = time.perf_counter()
    report = run_benchmarks(
        suites=["ulb_fraud"],
        limit=200,
        export_receipts=False,
        shared_audit_db=False,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_fresh_audit_200",
    )
    elapsed = time.perf_counter() - started
    summary = report.suites[0]
    assert summary.passed == 200
    assert summary.audit_chain_ok_rate == 1.0
    assert elapsed < 30.0, f"200-case ULB run took {elapsed:.1f}s (expected <30s with fresh audit DB)"


@pytest.mark.requires_ulb
def test_shared_audit_db_still_supported():
    report = run_benchmarks(
        suites=["ulb_fraud"],
        limit=20,
        export_receipts=False,
        shared_audit_db=True,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_shared_audit_20",
    )
    assert report.suites[0].passed == 20
    assert report.suites[0].audit_chain_ok_rate == 1.0
