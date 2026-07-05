from __future__ import annotations

from typing import Any

from harness.types import CaseResult


def proof_byte_counts(run_result: Any) -> dict[str, int]:
    bundle = run_result.proof.bundle
    policy = len(bundle.policy_proof or b"")
    inference = len(bundle.inference_proof or b"")
    composed = len(bundle.composed_proof or b"")
    return {
        "policy_proof_bytes": policy,
        "inference_proof_bytes": inference,
        "composed_proof_bytes": composed,
        "total_proof_bytes": policy + inference + composed,
    }


def summarize_prove(results: list[CaseResult], *, mode: str) -> dict[str, Any] | None:
    if mode != "prove":
        return None
    relevant = [item for item in results if item.metadata.get("total_proof_bytes") is not None]
    if not relevant:
        return {"counts": {"cases": 0}, "rates": {}, "latency_ms": {}}

    totals = [int(item.metadata["total_proof_bytes"]) for item in relevant]
    latencies = [item.latency_ms for item in relevant]
    verify_rates = [item.verify_valid for item in relevant if item.verify_valid is not None]
    sorted_lat = sorted(latencies)

    def _percentile(values: list[float], pct: float) -> float:
        if not values:
            return 0.0
        idx = min(len(values) - 1, int(len(values) * pct / 100))
        return values[idx]

    return {
        "counts": {"cases": len(relevant)},
        "proof_bytes": {
            "avg": sum(totals) / len(totals),
            "max": max(totals),
            "min": min(totals),
        },
        "latency_ms": {
            "avg": sum(latencies) / len(latencies),
            "p50": _percentile(sorted_lat, 50),
            "p95": _percentile(sorted_lat, 95),
        },
        "rates": {
            "verify_valid_rate": (
                sum(1 for value in verify_rates if value) / len(verify_rates)
                if verify_rates
                else None
            ),
        },
    }
