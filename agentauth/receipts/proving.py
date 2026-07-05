"""Helpers to extract scoring fields from agent/MCP outputs for ZK proving."""

from __future__ import annotations

from typing import Any

from agentauth.receipts.inference import amount_to_score


def policy_check_target(output: dict[str, Any]) -> dict[str, Any]:
    """Dict passed to Policy.check_output (unwrap MCP tool result when present)."""
    inner = output.get("result")
    if isinstance(inner, dict):
        return inner
    return output


def proving_amount_and_score(
    context: dict[str, Any],
    output: dict[str, Any],
) -> tuple[float, float]:
    """Return (amount, fraud_score) for composed/policy EZKL proofs."""
    inp = context.get("input", context)
    amount = float(inp.get("amount", 0)) if isinstance(inp, dict) else 0.0
    target = policy_check_target(output)
    if "fraud_score" in target:
        score = float(target["fraud_score"])
    elif "fraud_score" in output:
        score = float(output["fraud_score"])
    else:
        score = amount_to_score(amount)
    return amount, score
