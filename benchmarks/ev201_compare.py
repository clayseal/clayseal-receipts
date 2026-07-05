#!/usr/bin/env python3
"""EV-201: compare prove mode vs bounded_auto on the same ULB subset."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

BENCHMARKS_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.paths import ensure_import_paths  # noqa: E402
from harness.prove_compare import run_prove_comparison  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="EV-201 prove vs bounded_auto comparison")
    parser.add_argument("--suite", default="ulb_fraud")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=BENCHMARKS_ROOT / "results",
        help="Parent directory for baseline/prove run folders",
    )
    args = parser.parse_args()

    ensure_import_paths()
    if args.suite == "ulb_fraud" and not os.environ.get("AGENT_RECEIPTS_ALLOW_STUB"):
        print(
            "Note: prove mode requires AGENT_RECEIPTS_ALLOW_STUB=1 for stub ZK proofs.",
            file=sys.stderr,
        )

    comparison, _, _ = run_prove_comparison(
        suite=args.suite,  # type: ignore[arg-type]
        limit=args.limit,
        results_dir=args.results_dir,
    )
    print(json.dumps(comparison, indent=2))

    base = comparison["bounded_auto"]["latency_ms"]
    prove = comparison["prove"]["latency_ms"]
    proof = comparison["prove"].get("proof_bytes") or {}
    slowdown = comparison["comparison"].get("latency_slowdown_avg")
    print(
        f"\nEV-201 {args.suite} N={args.limit}: "
        f"baseline p50={base['p50_ms']:.2f}ms · "
        f"prove p50={prove['p50_ms']:.2f}ms · "
        f"slowdown={slowdown:.1f}x · "
        f"proof_bytes_avg={proof.get('avg', 0):.0f} · "
        f"verify_valid prove={comparison['prove']['verify_valid_rate']}"
    )


if __name__ == "__main__":
    main()
