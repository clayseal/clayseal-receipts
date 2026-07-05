"""Shared fraud MCP tool implementations (server + local gateway)."""

from __future__ import annotations

from typing import Any


def score_fraud_model(arguments: dict[str, Any]) -> dict[str, Any]:
    """Score a transaction amount; returns policy-checkable output."""
    amount = float(arguments.get("amount", 0))
    score = min(1.0, amount / 10_000.0)
    decision = "deny" if score > 0.8 else "review" if score > 0.4 else "approve"
    return {
        "transaction_id": arguments.get("transaction_id"),
        "decision": decision,
        "fraud_score": round(score, 4),
    }


def score_transaction(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "transaction_id": arguments.get("transaction_id"),
        "scored": True,
    }


def fetch_customer_profile(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "customer_id": arguments.get("customer_id", "unknown"),
        "tier": "gold",
    }


FRAUD_TOOL_NAMES = (
    "score_fraud_model",
    "score_transaction",
    "fetch_customer_profile",
)
