from __future__ import annotations

import json
import time
from pathlib import Path

from harness.paths import BENCHMARKS_ROOT
from harness.runner import RunReport, run_benchmarks

BACKENDS = ("ezkl", "risc0", "sp1")


def run_backend_smoke(*, backend: str, limit: int = 3) -> RunReport:
    return run_benchmarks(
        suites=["ulb_fraud"],
        limit=limit,
        mode="prove",
        export_receipts=True,
        inference_backend=backend,
        results_dir=BENCHMARKS_ROOT / "results" / f"_test_prove_{backend}_{limit}",
    )


def run_ev202_matrix(*, limit: int = 10, results_dir: Path) -> dict:
    rows: list[dict] = []
    for backend in BACKENDS:
        out_dir = results_dir / f"ev202_{backend}_{limit}"
        started = time.perf_counter()
        try:
            report = run_benchmarks(
                suites=["ulb_fraud"],
                limit=limit,
                mode="prove",
                export_receipts=True,
                inference_backend=backend,
                results_dir=out_dir,
            )
        except Exception as exc:  # noqa: BLE001
            rows.append(
                {
                    "backend": backend,
                    "status": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue

        summary = report.suites[0]
        pm = summary.prove_metrics or {}
        pb = pm.get("proof_bytes") or {}
        lat = pm.get("latency_ms") or {}
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        rows.append(
            {
                "backend": backend,
                "status": "ok" if summary.passed == summary.total else "failed",
                "passed": summary.passed,
                "total": summary.total,
                "verify_valid_rate": summary.verify_valid_rate,
                "proof_bytes_avg": pb.get("avg"),
                "latency_avg_ms": lat.get("avg"),
                "latency_p50_ms": lat.get("p50"),
                "latency_p95_ms": lat.get("p95"),
                "wall_ms": round(elapsed_ms),
                "results_dir": str(out_dir),
            }
        )

    matrix = {
        "suite": "ulb_fraud",
        "limit": limit,
        "backends": rows,
    }
    out_path = results_dir / f"ev202_matrix_{limit}.json"
    out_path.write_text(json.dumps(matrix, indent=2))
    matrix["matrix_path"] = str(out_path)
    return matrix
