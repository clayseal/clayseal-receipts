#!/usr/bin/env python3
"""Demonstrate RT-1 runtime egress controls (#4 / C4 class).

The PR gate cannot see network exfil; this harness shows default-deny egress
capability enforcement at MCP tool-call time with receipt attestation.

    python3.11 scripts/evaluate_runtime_egress.py
"""

from __future__ import annotations

import json
from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy, ReceiptedMcpGateway
from agentauth.receipts.certificate import dev_certificate

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policies" / "egress_demo.yaml"


def run_case(label: str, url: str) -> dict[str, object]:
    policy = Policy.from_yaml(POLICY)
    cert = dev_certificate(policy.commitment(), scope=list(policy.allowed_tools or []))
    agent = AgentWrapper(
        model=lambda inp: {"status": "ok"},
        policy=policy,
        certificate=cert,
        mode="bounded_auto",
        audit_db=":memory:",
    )
    gateway = ReceiptedMcpGateway(agent, server_name="runtime-demo")
    gateway.register_tool("http_post", lambda args: {"status": "sent"})
    result = gateway.call_tool("http_post", {"url": url, "body": "payload"})
    auth = result.audit_record.authorization_context["authorization"]
    return {
        "label": label,
        "url": url,
        "blocked": result.blocked,
        "outcome": result.proof.decision_outcome.value,
        "egress": auth.get("egress"),
    }


def main() -> int:
    cases = [
        ("trusted host (allow)", "https://api.trusted.example/v1/events"),
        ("attacker host (deny)", "https://attacker.example/exfil"),
        ("localhost sink (allow via policy)", "http://127.0.0.1:8899/x"),
    ]
    results = [run_case(label, url) for label, url in cases]
    print(json.dumps(results, indent=2))
    ok = (
        results[0]["blocked"] is False
        and results[1]["blocked"] is True
        and results[2]["blocked"] is False
    )
    print(f"\nRT-1 harness: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
