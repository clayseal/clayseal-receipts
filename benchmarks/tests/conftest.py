"""Shared paths and corpus skip markers for benchmarks/tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

ULB_CSV = BENCHMARKS_ROOT / "corpus" / "ulb_creditcard" / "creditcard.csv"
BFCL_JSON = (
    BENCHMARKS_ROOT
    / "corpus"
    / "gorilla"
    / "berkeley-function-call-leaderboard"
    / "bfcl_eval"
    / "data"
    / "BFCL_v4_simple_python.json"
)
ATIF_DIR = BENCHMARKS_ROOT / "corpus" / "mcp_agent_trajectory_benchmark"

HAS_ULB = ULB_CSV.is_file()
HAS_BFCL = BFCL_JSON.is_file()


def _has_prover_cli() -> bool:
    try:
        from agentauth.receipts.prover import locate_cli

        return locate_cli().available
    except Exception:  # noqa: BLE001 - skip if the prover cannot be inspected
        return False


HAS_PROVER = _has_prover_cli()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "requires_ulb: needs ULB fraud corpus")
    config.addinivalue_line("markers", "requires_bfcl: needs BFCL corpus")
    config.addinivalue_line("markers", "requires_ulb_bfcl: needs ULB and BFCL corpora")
    config.addinivalue_line("markers", "requires_ulb_atif: needs ULB and ATIF corpora")
    config.addinivalue_line("markers", "requires_prover: needs agent-receipts prover CLI")


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("requires_ulb") and not HAS_ULB:
        pytest.skip("ULB corpus not downloaded")
    if item.get_closest_marker("requires_bfcl") and not HAS_BFCL:
        pytest.skip("BFCL corpus not downloaded")
    if item.get_closest_marker("requires_ulb_bfcl") and not (HAS_ULB and HAS_BFCL):
        pytest.skip("ULB and BFCL corpora not downloaded")
    if item.get_closest_marker("requires_ulb_atif") and not (HAS_ULB and ATIF_DIR.is_dir()):
        pytest.skip("ULB and/or ATIF corpus not downloaded")
    if item.get_closest_marker("requires_prover") and not HAS_PROVER:
        pytest.skip("agent-receipts prover CLI not built")
