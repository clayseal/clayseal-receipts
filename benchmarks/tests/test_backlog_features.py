from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.adapters.registry import iter_cases  # noqa: E402
from harness.adapters.swe_session import shard_count  # noqa: E402
from harness.config import AdapterOptions  # noqa: E402
from harness.runner import run_benchmarks  # noqa: E402


@pytest.mark.skipif(
    not (BENCHMARKS_ROOT / "corpus" / "tau2_bench").is_dir(),
    reason="tau2 corpus not downloaded",
)
def test_tau2_all_domains_including_telecom_and_banking():
    opts = AdapterOptions(
        tau2_domains=["mock", "airline", "retail", "telecom", "banking_knowledge"],
        tau2_telecom_tasks="small",
        limit=200,
    )
    cases = list(iter_cases("tau2_policy", limit=200, options=opts))
    domains = {case.metadata.get("domain") for case in cases}
    assert "mock" in domains
    assert "telecom" in domains or "banking_knowledge" in domains
    assert len(cases) > 8


@pytest.mark.skipif(
    not (BENCHMARKS_ROOT / "corpus" / "swe_agent_trajectories").is_dir(),
    reason="SWE corpus not downloaded",
)
def test_swe_multi_shard_cases():
    count = shard_count()
    if count < 2:
        pytest.skip("need at least 2 SWE shards")
    opts = AdapterOptions(swe_shards=list(range(min(count, 3))), limit=30)
    cases = list(iter_cases("swe_session", limit=30, options=opts))
    assert len(cases) > 0
    assert all(case.metadata.get("shard") is not None for case in cases)
    assert max(case.metadata.get("shard", 0) for case in cases) >= 0


@pytest.mark.requires_ulb
def test_attach_mock_tee_attaches_quote(monkeypatch):
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_STUB", "1")
    report = run_benchmarks(
        suites=["ulb_fraud"],
        limit=1,
        export_receipts=True,
        attach_mock_tee=True,
        results_dir=BENCHMARKS_ROOT / "results" / "_test_mock_tee",
    )
    case = report.cases[0]
    assert case.export_ok is True
    path = case.metadata.get("receipt_path")
    assert path
    bundle = json.loads(Path(path).read_text())
    proof = bundle.get("execution_proof") or {}
    bundle_section = proof.get("bundle") or {}
    assert bundle_section.get("tee_quote") is not None
    assert case.verify_valid is True


@pytest.mark.requires_bfcl
def test_ev301_ecs_export_smoke():
    run_dir = BENCHMARKS_ROOT / "results" / "_test_ev301_run"
    run_benchmarks(
        suites=["bfcl_caps"],
        limit=2,
        export_receipts=True,
        results_dir=run_dir,
    )
    from ev301_ecs_export import export_ecs_from_results

    payload = export_ecs_from_results(run_dir, profiles=["soc2"])
    assert payload["report"]["ecs_event_count"] >= 1
    assert "@timestamp" in payload["events"][0]
    assert "agent_receipts" in payload["events"][0]


@pytest.mark.requires_bfcl
def test_ev302_crosswalk_smoke():
    run_dir = BENCHMARKS_ROOT / "results" / "_test_ev302_run"
    run_benchmarks(
        suites=["bfcl_caps"],
        limit=2,
        export_receipts=True,
        results_dir=run_dir,
    )
    from ev302_crosswalk import crosswalk_coverage

    report = crosswalk_coverage(run_dir, profiles=["soc2"])
    assert "soc2" in report["profiles"]
    assert report["profiles"]["soc2"]["receipt_count"] >= 1
