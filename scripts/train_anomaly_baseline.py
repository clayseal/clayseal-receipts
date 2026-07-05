#!/usr/bin/env python3
"""Train the ATIF frequency baseline anomaly model (SM-9)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentauth.receipts.anomaly_baseline import train_baseline_from_trajectories, write_anomaly_model

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "benchmarks" / "corpus" / "mcp_agent_trajectory_benchmark"
DEFAULT_OUTPUT = ROOT / "benchmarks" / "models" / "atif_anomaly_baseline.json"


def load_trajectories(corpus: Path) -> list[dict]:
    trajectories: list[dict] = []
    for path in sorted(corpus.glob("*/trajectory.json")):
        trajectories.append(json.loads(path.read_text(encoding="utf-8")))
    return trajectories


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    trajectories = load_trajectories(args.corpus)
    if not trajectories:
        raise SystemExit(f"no trajectories found under {args.corpus}")

    model = train_baseline_from_trajectories(trajectories)
    write_anomaly_model(model, args.output)
    print(f"trained on {model.training_samples} trajectories -> {args.output}")
    print(f"model_commitment={model.model_commitment()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
