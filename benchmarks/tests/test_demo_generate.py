from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = BENCHMARKS_ROOT / "demo"
sys.path.insert(0, str(BENCHMARKS_ROOT))
sys.path.insert(0, str(DEMO_ROOT))

from generate import generate_all  # noqa: E402
from harness.paths import CORPUS, ensure_import_paths  # noqa: E402


@pytest.fixture(autouse=True)
def _allow_stub(monkeypatch):
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_STUB", "1")


@pytest.mark.skipif(
    not (CORPUS / "ulb_creditcard" / "creditcard.csv").is_file(),
    reason="ULB corpus not downloaded",
)
def test_generate_d08_assurance_ladder(tmp_path):
    ensure_import_paths()
    manifest = generate_all(tmp_path, only=["D-08"])
    assert "D-08" in manifest["sets"]
    comparison = tmp_path / "D-08_assurance_ladder" / "comparison.json"
    assert comparison.is_file()
    modes = {row["mode"] for row in manifest["sets"]["D-08"]["modes"]}
    assert modes == {"shadow", "bounded_auto", "prove"}
