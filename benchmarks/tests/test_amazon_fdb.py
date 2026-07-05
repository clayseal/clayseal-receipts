from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.adapters.registry import iter_cases  # noqa: E402
from harness.fdb_corpus import (  # noqa: E402
    FDB_VERSIONED,
    FDB_VERSIONED_DATASETS,
    available_fdb_keys,
    load_versioned_test_rows,
)


def test_fdb_ipblock_versioned_zip_present():
    zip_path = FDB_VERSIONED / "ipblock/20220607.zip"
    if not zip_path.is_file():
        pytest.skip("Amazon FDB ipblock bundle not present (run scripts/download_benchmark_corpora.sh)")
    assert "ipblock" in available_fdb_keys()


def test_fdb_ipblock_loads_test_rows():
    if "ipblock" not in available_fdb_keys():
        pytest.skip("Amazon FDB ipblock bundle not present")
    rows = load_versioned_test_rows(
        next(spec for spec in FDB_VERSIONED_DATASETS if spec.key == "ipblock")
    )
    assert len(rows) > 40_000
    assert rows[0][2] in {0, 1}


def test_amazon_fdb_suite_yields_cases():
    cases = list(iter_cases("amazon_fdb", limit=5))  # type: ignore[arg-type]
    if not cases:
        pytest.skip("Amazon FDB corpus not present")
    assert cases[0].suite == "amazon_fdb"
    assert cases[0].metadata.get("fdb_key") == "ipblock"
    assert cases[0].execute is not None
