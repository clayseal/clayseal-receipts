from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from harness.runner import RunReport, run_benchmarks
from harness.types import SuiteName, SuiteSummary


def _suite_latency(summary: SuiteSummary) -> dict[str, float | None]:
    return {
        "avg_ms": summary.avg_latency_ms,
        "p50_ms": summary.p50_latency_ms,
        "p95_ms": summary.p95_latency_ms,
    }


def build_prove_comparison(
    *,
    suite: str,
    limit: int,
    baseline: SuiteSummary,
    prove: SuiteSummary,
) -> dict[str, Any]:
    base_lat = _suite_latency(baseline)
    prove_lat = _suite_latency(prove)
    prove_metrics = prove.prove_metrics or {}

    slowdown = None
    if base_lat["avg_ms"] and prove_lat["avg_ms"] and base_lat["avg_ms"] > 0:
        slowdown = prove_lat["avg_ms"] / base_lat["avg_ms"]

    return {
        "suite": suite,
        "limit": limit,
        "bounded_auto": {
            "total": baseline.total,
            "passed": baseline.passed,
            "pass_rate": baseline.passed / baseline.total if baseline.total else None,
            "latency_ms": base_lat,
            "verify_valid_rate": baseline.verify_valid_rate,
            "export_ok_rate": baseline.export_ok_rate,
        },
        "prove": {
            "total": prove.total,
            "passed": prove.passed,
            "pass_rate": prove.passed / prove.total if prove.total else None,
            "latency_ms": prove_lat,
            "verify_valid_rate": prove.verify_valid_rate,
            "export_ok_rate": prove.export_ok_rate,
            "proof_bytes": (prove_metrics.get("proof_bytes") or {}),
        },
        "comparison": {
            "latency_slowdown_avg": slowdown,
            "verify_valid_delta": (
                (prove.verify_valid_rate or 0) - (baseline.verify_valid_rate or 0)
                if prove.verify_valid_rate is not None and baseline.verify_valid_rate is not None
                else None
            ),
            "pass_rate_delta": (
                (prove.passed / prove.total if prove.total else 0)
                - (baseline.passed / baseline.total if baseline.total else 0)
            ),
        },
    }


def run_prove_comparison(
    *,
    suite: SuiteName = "ulb_fraud",
    limit: int = 100,
    results_dir: Path | None = None,
) -> tuple[dict[str, Any], RunReport, RunReport]:
    """Run bounded_auto baseline then prove mode on the same suite/limit."""
    base_dir = (results_dir or Path("benchmarks/results")) / f"ev201_{suite}_{limit}_baseline"
    prove_dir = (results_dir or Path("benchmarks/results")) / f"ev201_{suite}_{limit}_prove"

    baseline_report = run_benchmarks(
        suites=[suite],
        limit=limit,
        mode="bounded_auto",
        export_receipts=True,
        results_dir=base_dir,
    )
    prove_report = run_benchmarks(
        suites=[suite],
        limit=limit,
        mode="prove",
        export_receipts=True,
        results_dir=prove_dir,
    )

    baseline_summary = baseline_report.suites[0]
    prove_summary = prove_report.suites[0]
    comparison = build_prove_comparison(
        suite=suite,
        limit=limit,
        baseline=baseline_summary,
        prove=prove_summary,
    )
    comparison["results_dirs"] = {
        "bounded_auto": str(base_dir),
        "prove": str(prove_dir),
    }

    out_path = prove_dir.parent / f"ev201_{suite}_{limit}_comparison.json"
    out_path.write_text(json.dumps(comparison, indent=2))
    comparison["comparison_path"] = str(out_path)
    return comparison, baseline_report, prove_report
