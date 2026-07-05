from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.adapters.registry import iter_cases  # noqa: E402
from harness.runner import run_benchmarks  # noqa: E402
from harness.synthetic_scenarios import load_scenarios  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_scenario_cache():
    load_scenarios.cache_clear()
    yield
    load_scenarios.cache_clear()


def test_synthetic_scenario_catalog():
    scenarios = load_scenarios()
    assert len(scenarios) >= 28
    ids = {item["id"] for item in scenarios}
    assert "revoke_blocks_validate" in ids
    assert "tenant_cannot_validate_foreign_token" in ids


def test_synthetic_revocation_smoke():
    cases = list(iter_cases("synthetic_revocation", limit=5))
    assert len(cases) == 5
    assert cases[0].execute is not None


def test_synthetic_tenant_smoke():
    cases = list(iter_cases("synthetic_tenant", limit=5))
    assert len(cases) == 5
    assert cases[0].execute is not None


def test_synthetic_core_suites_run():
    report = run_benchmarks(
        suites=["synthetic_revocation", "synthetic_tenant"],
        limit=10,
        export_receipts=False,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_synthetic_identity",
    )
    by_suite = {suite.suite: suite for suite in report.suites}
    assert by_suite["synthetic_revocation"].passed == by_suite["synthetic_revocation"].total
    assert by_suite["synthetic_tenant"].passed == by_suite["synthetic_tenant"].total
