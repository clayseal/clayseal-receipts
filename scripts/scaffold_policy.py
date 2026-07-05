#!/usr/bin/env python3
"""Scaffold a structural policy YAML from your output schema constraints."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentauth.receipts.policy import Policy, PolicyCapability, PolicyTier  # noqa: E402


def parse_range(spec: str) -> tuple[str, float, float]:
    parts = spec.split(":")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(f"range must be field:min:max, got {spec!r}")
    return parts[0], float(parts[1]), float(parts[2])


def build_policy_dict(args: argparse.Namespace) -> dict:
    numeric_ranges = [
        {"field": field, "min": lo, "max": hi}
        for field, lo, hi in (parse_range(r) for r in args.range)
    ]
    required = list(args.required_field)
    policy: dict = {
        "version": 1,
        "name": args.name,
        "tier": args.tier,
        "capability": args.capability,
    }
    if numeric_ranges:
        policy["numeric_ranges"] = numeric_ranges
    if required:
        policy["output_schema"] = {
            "fields": required,
            "required": required,
        }
    return policy


def main() -> None:
    parser = argparse.ArgumentParser(description="Scaffold Agent Receipts policy YAML")
    parser.add_argument("--name", required=True, help="Policy name (e.g. spend_cap_v1)")
    parser.add_argument("--out", type=Path, help="Output path (default: policies/<name>.yaml)")
    parser.add_argument(
        "--required-field",
        action="append",
        default=[],
        help="Required output field (repeatable)",
    )
    parser.add_argument(
        "--range",
        action="append",
        default=[],
        metavar="FIELD:MIN:MAX",
        help="Numeric range on output (repeatable), e.g. fraud_score:0:1",
    )
    parser.add_argument(
        "--tier",
        default=PolicyTier.STRUCTURAL.value,
        choices=[t.value for t in PolicyTier],
    )
    parser.add_argument(
        "--capability",
        default=PolicyCapability.FULLY_PROVEN.value,
        choices=[c.value for c in PolicyCapability],
    )
    args = parser.parse_args()

    raw = build_policy_dict(args)
    policy = Policy.from_dict(raw)
    out = args.out or (ROOT / "policies" / f"{args.name}.yaml")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    print(f"Wrote {out}")
    print(f"policy_commitment: {policy.commitment()}")
    print("Next: reference this path in config/partner.yaml")


if __name__ == "__main__":
    main()
