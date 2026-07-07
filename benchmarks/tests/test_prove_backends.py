from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.ev202 import run_backend_smoke  # noqa: E402


@pytest.fixture(autouse=True)
def _allow_stub(monkeypatch):
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_STUB", "1")


@pytest.mark.requires_ulb
@pytest.mark.requires_prover
@pytest.mark.parametrize("backend", ["ezkl", "risc0", "sp1"])
def test_prove_backend_smoke(backend: str):
    report = run_backend_smoke(backend=backend, limit=3)
    summary = report.suites[0]
    assert summary.passed == 3
    assert summary.prove_metrics is not None
    assert summary.verify_valid_rate == 1.0
    backends = {case.metadata.get("inference_backend") for case in report.cases}
    assert backends == {backend}


@pytest.mark.requires_ulb
@pytest.mark.requires_prover
@pytest.mark.skipif(
    os.environ.get("EV202_FULL") != "1",
    reason="Set EV202_FULL=1 to run full backend matrix",
)
def test_ev202_matrix():
    from harness.ev202 import run_ev202_matrix

    matrix = run_ev202_matrix(
        limit=5,
        results_dir=BENCHMARKS_ROOT / "results",
    )
    ok = [row for row in matrix["backends"] if row.get("status") == "ok"]
    assert len(ok) == 3
