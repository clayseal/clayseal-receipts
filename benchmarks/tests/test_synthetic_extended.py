from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.adapters.registry import iter_cases  # noqa: E402
from harness.runner import run_benchmarks  # noqa: E402
from harness.synthetic_scenarios import load_scenarios  # noqa: E402
from harness.synthetic_scale import (  # noqa: E402
    REIDENTIFY_SCALE,
    REVOKE_BLOCK_SCALE,
    TENANT_CROSS_SCALE,
)


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
    assert "l1_pop_bearer_rejected" in ids
    assert "assurance_tee_mock_verify_valid" in ids


def test_synthetic_revocation_cases():
    cases = list(iter_cases("synthetic_revocation"))
    expected = 8 + REVOKE_BLOCK_SCALE + REIDENTIFY_SCALE
    assert len(cases) == expected
    assert {c.metadata.get("ev") for c in cases if not c.metadata.get("scaled")} == {"EV-103"}


def test_synthetic_tenant_cases():
    cases = list(iter_cases("synthetic_tenant"))
    expected = 8 + TENANT_CROSS_SCALE
    assert len(cases) == expected
    assert {c.metadata.get("ev") for c in cases if not c.metadata.get("scaled")} == {"EV-102"}


def test_synthetic_l1_cases():
    cases = list(iter_cases("synthetic_l1"))
    assert len(cases) == 7


def test_synthetic_assurance_cases():
    cases = list(iter_cases("synthetic_assurance"))
    assert len(cases) == 5


def test_all_synthetic_suites_run():
    suites = [
        "synthetic_revocation",
        "synthetic_tenant",
        "synthetic_l1",
        "synthetic_assurance",
    ]
    report = run_benchmarks(
        suites=suites,
        limit=None,
        export_receipts=False,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_synthetic_extended",
    )
    by_suite = {suite.suite: suite for suite in report.suites}
    for name in suites:
        summary = by_suite[name]
        assert summary.passed == summary.total, f"{name} failures: {summary.failed}"
        assert summary.control_pass_rate == 1.0
        assert summary.baseline_pass_rate == 1.0
        if summary.blind_spot_open_rate is not None:
            assert summary.blind_spot_open_rate == 1.0

    assert sum(suite.total for suite in report.suites) >= 125
