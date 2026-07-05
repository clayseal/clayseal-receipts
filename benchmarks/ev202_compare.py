#!/usr/bin/env python3
"""EV-202: composed prove backend matrix (ezkl / risc0 / sp1) on ULB subset."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

BENCHMARKS_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.ev202 import BACKENDS, run_ev202_matrix  # noqa: E402
from harness.paths import ensure_import_paths  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="EV-202 composed prove backend matrix")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=BENCHMARKS_ROOT / "results",
    )
    args = parser.parse_args()

    ensure_import_paths()
    if not os.environ.get("AGENT_RECEIPTS_ALLOW_STUB"):
        print(
            "Note: set AGENT_RECEIPTS_ALLOW_STUB=1 for stub composed proofs without zkVM builds.",
            file=sys.stderr,
        )

    args.results_dir.mkdir(parents=True, exist_ok=True)
    matrix = run_ev202_matrix(limit=args.limit, results_dir=args.results_dir)
    print(json.dumps(matrix, indent=2))
    ok = [row for row in matrix["backends"] if row.get("status") == "ok"]
    print(f"\nEV-202 matrix: {len(ok)}/{len(BACKENDS)} backends ok · limit={args.limit}")
    for row in ok:
        print(
            f"  {row['backend']}: verify={row.get('verify_valid_rate')} · "
            f"proof_bytes={row.get('proof_bytes_avg', 0):.0f} · "
            f"p50={row.get('latency_p50_ms', 0):.1f}ms"
        )


if __name__ == "__main__":
    main()
