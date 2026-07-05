#!/usr/bin/env python3
"""Demonstrate CHAIN-1 receipt-chain linking I1 poison capture -> I2 execution.

    python3.11 scripts/evaluate_receipt_chain.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    spec = importlib.util.spec_from_file_location(
        "adv", ROOT / "scripts/evaluate_devin_advanced_attacks.py"
    )
    adv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adv)
    adv._ACTIVE_POLICY = adv.HARDENED_POLICY

    i1 = adv.scenario_I1_memory_capture()
    i2 = adv.scenario_I2_memory_execute()

    from agentauth.receipts.receipt_chain import link_receipt_chain

    # Scenarios tear down repos; synthesize receipts from harness outcomes + chain shape.
    i1_receipt = {
        "receipt_id": "rcpt_i1_capture",
        "receipt_hash": "hash_i1",
        "decision": {"outcome": i1["outcome"]},
        "git": {
            "changed_files": [{"path": ".devin/knowledge.md", "operation": "modify"}],
        },
    }
    i2_receipt = {
        "receipt_id": "rcpt_i2_execute",
        "receipt_hash": "hash_i2",
        "decision": {"outcome": i2["outcome"]},
        "flags": [{"code": item} for item in i2.get("codes", []) if item],
        "git": {
            "changed_files": [{"path": "swe_triage/parser.py", "operation": "modify"}],
        },
    }
    links = link_receipt_chain(i2_receipt, [i1_receipt])

    print(
        json.dumps(
            {
                "i1_outcome": i1["outcome"],
                "i2_outcome": i2["outcome"],
                "links": [link.to_dict() for link in links],
            },
            indent=2,
        )
    )
    ok = len(links) >= 1
    print(f"\nCHAIN-1 harness: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
