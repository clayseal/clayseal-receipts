from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.config import AdapterOptions  # noqa: E402
from harness.provenance import collect_run_provenance  # noqa: E402


def test_collect_run_provenance_marks_synthetic_suite():
    records = collect_run_provenance(
        ["red_team"],
        options=AdapterOptions(),
        cases_by_suite={"red_team": []},
    )
    assert len(records) == 1
    record = records[0]
    assert record.suite == "red_team"
    assert record.source_kind == "synthetic"
    assert record.assets[0].kind == "synthetic"
    assert record.assets[0].digest_status == "missing"


def test_collect_run_provenance_resolves_external_csv(tmp_path, monkeypatch):
    csv_path = tmp_path / "ieee.csv"
    csv_path.write_text("label,feature_0\n0,0.0\n")
    monkeypatch.setenv("AGENTAUTH_CORPUS_IEEE_CIS", str(csv_path))

    records = collect_run_provenance(
        ["ieee_cis_fraud"],
        options=AdapterOptions(),
        cases_by_suite={"ieee_cis_fraud": []},
    )

    assert len(records) == 1
    asset = records[0].assets[0]
    assert asset.exists is True
    assert asset.resolved_path == str(csv_path)
    assert asset.sha256 is not None
    assert asset.digest_status == "computed"


def test_run_report_includes_corpora_section(tmp_path):
    pytest.importorskip("biscuit_auth")
    from harness.runner import run_benchmarks  # noqa: WPS433,E402

    report = run_benchmarks(
        suites=["red_team"],
        limit=1,
        export_receipts=False,
        results_dir=tmp_path / "results",
    )
    payload = report.to_dict()
    assert "corpora" in payload
    assert payload["corpora"]
    assert payload["corpora"][0]["suite"] == "red_team"
