#!/usr/bin/env python3
"""CI merge prerequisite: bind receipt to merge SHA and block flagged allows.

Usage (GitHub Actions / merge queue):

    python3.11 scripts/agentauth_merge_check.py \\
      --receipt path/to/gate.receipt.json \\
      --merge-head "$GITHUB_SHA" \\
      [--target-ref origin/main] \\
      [--repo .] \\
      [--policy .agentauth/policies/devin-pr-gate.policy.json]

Exit 0 only when merge is allowed. Combines GATE-4 TOCTOU binding (G2/M3/E9)
with hard-blocks on security review flags (capture-phase FN mitigation).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentauth.receipts.merge_binding import (  # noqa: E402
    MergeBindingPolicy,
    evaluate_merge_eligibility,
    stacked_base_warning,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--merge-head", required=True, help="SHA being merged")
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--target-ref", default="", help="True merge target (G2 stacked-base)")
    parser.add_argument("--policy", type=Path, help="Gate policy JSON with merge_policy block")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    merge_policy = MergeBindingPolicy()
    if args.policy and args.policy.is_file():
        policy_doc = json.loads(args.policy.read_text(encoding="utf-8"))
        merge_policy = MergeBindingPolicy.from_policy_dict(policy_doc.get("merge_policy"))

    result = evaluate_merge_eligibility(
        receipt,
        policy=merge_policy,
        merge_head_sha=args.merge_head,
    )

    stacked: dict | None = None
    if args.target_ref:
        git_block = receipt.get("git") or {}
        head_sha = git_block.get("head_sha") or git_block.get("evaluated_head_sha")
        base_sha = git_block.get("base_sha") or git_block.get("merge_base")
        if head_sha and base_sha:
            try:
                stacked = stacked_base_warning(
                    args.repo.resolve(),
                    provided_base_sha=str(base_sha),
                    target_ref=args.target_ref,
                    head_sha=str(head_sha),
                )
                if stacked.get("stacked_base_risk"):
                    result.issues.append(
                        "merge blocked: gate evaluated against stacked parent base, not merge target"
                    )
                    result.allowed = False
            except Exception as exc:
                result.issues.append(f"stacked-base check failed: {exc}")
                result.allowed = False

    payload = result.to_dict()
    if stacked is not None:
        payload["stacked_base"] = stacked

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        status = "ALLOW" if result.allowed else "BLOCK"
        print(f"merge check: {status}")
        for issue in result.issues:
            print(f"- {issue}")
        if stacked and stacked.get("stacked_base_risk"):
            print(f"- stacked base: {stacked.get('recommendation')}")

    return 0 if result.allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
