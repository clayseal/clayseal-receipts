from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.adapters.registry import iter_cases  # noqa: E402
from harness.corpus_paths import ARL_FRAUD_ROOT, resolve_csv  # noqa: E402


def test_arl_fraud_root_exists():
    if not ARL_FRAUD_ROOT.is_dir():
        pytest.skip("adaptive-reliability-layer fraud data not present")
    assert (ARL_FRAUD_ROOT / "ieee_cis_full.csv").is_file()


def test_resolve_ieee_cis_from_arl():
    path = resolve_csv(
        env_var="AGENTAUTH_CORPUS_IEEE_CIS",
        corpus_relative=Path("ieee_cis/ieee_cis_full.csv"),
        arl_filename="ieee_cis_full.csv",
    )
    if path is None:
        pytest.skip("IEEE-CIS CSV not found")
    assert path.is_file()
    assert path.name in {"ieee_cis_full.csv"}


@pytest.mark.parametrize(
    "suite",
    ["ieee_cis_fraud", "paysim_fraud", "elliptic_fraud", "baf_fraud"],
)
def test_arl_fraud_suites_yield_cases(suite: str):
    cases = list(iter_cases(suite, limit=5))  # type: ignore[arg-type]
    if not cases:
        pytest.skip(f"no corpus for {suite}")
    assert cases[0].execute is not None
    assert "source_csv" in cases[0].metadata
