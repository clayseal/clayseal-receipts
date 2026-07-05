from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.adapters.registry import iter_cases  # noqa: E402
from harness.paths import ensure_import_paths  # noqa: E402
from harness.runner import run_benchmarks  # noqa: E402


def test_ulb_adapter_yields_cases_when_corpus_present():
    cases = list(iter_cases("ulb_fraud", limit=1))
    if not cases:
        return
    assert cases[0].suite == "ulb_fraud"
    assert cases[0].execute is not None


@pytest.mark.requires_ulb_bfcl
def test_smoke_run_ulb_and_bfcl():
    ensure_import_paths()
    report = run_benchmarks(
        suites=["ulb_fraud", "bfcl_caps"],
        limit=2,
        mode="bounded_auto",
        export_receipts=True,
    )
    assert report.cases
    for case in report.cases:
        assert case.audit_chain_ok
        assert case.export_ok


@pytest.mark.requires_bfcl
def test_smoke_run_bfcl_with_tamper_analysis(tmp_path):
    ensure_import_paths()
    report = run_benchmarks(
        suites=["bfcl_caps"],
        limit=1,
        mode="bounded_auto",
        export_receipts=True,
        tamper_analysis=True,
        results_dir=tmp_path / "results",
    )
    assert report.cases
    case = report.cases[0]
    assert case.export_ok
    assert case.tamper_total_mutations is not None
    assert case.tamper_total_mutations > 0
    assert case.tamper_detection_rate is not None
    assert case.metadata.get("tamper_report_path")
    summary = report.suites[0]
    assert summary.tamper_total_mutations is not None
    assert summary.tamper_detection_rate is not None
    assert report.overview is not None
    assert report.overview["total_cases"] == 1
    assert report.overview["exported_cases"] == 1
    assert report.tamper_coverage is not None
    assert report.tamper_coverage["cases_analyzed"] == 1
    assert report.tamper_coverage["top_survivors"]
    assert report.tamper_coverage["survivors_by_classification"]
    assert "expected_informational" in report.tamper_coverage["survivors_by_classification"]


@pytest.mark.requires_ulb
@pytest.mark.skipif(
    not (BENCHMARKS_ROOT.parent / "target" / "release" / "agent-receipts").is_file(),
    reason="release CLI not built",
)
def test_smoke_run_ulb_prove_mode_verifies(tmp_path, monkeypatch):
    ensure_import_paths()
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_STUB", "1")
    report = run_benchmarks(
        suites=["ulb_fraud"],
        limit=1,
        mode="prove",
        export_receipts=True,
        tamper_analysis=True,
        results_dir=tmp_path / "results",
    )
    assert report.cases
    case = report.cases[0]
    assert case.export_ok is True
    assert case.verify_valid is True
    assert case.tamper_total_mutations is not None
