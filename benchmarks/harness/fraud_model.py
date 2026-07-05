from __future__ import annotations

from typing import Any

from agentauth.receipts.inference import amount_to_score


def amount_fraud_agent(inp: dict[str, Any]) -> dict[str, Any]:
    """Composed-proof-compatible amount scorer (Amount -> exact fraud_score)."""
    amount = float(inp.get("amount", 0))
    score = amount_to_score(amount)
    decision = "deny" if score > 0.8 else "review" if score > 0.4 else "approve"
    return {
        "decision": decision,
        # Keep the exact inferred score so composed proof bindings and output agree.
        "fraud_score": score,
    }


def feature_fraud_agent(inp: dict[str, Any]) -> dict[str, Any]:
    """Tabular fraud stub for ARL-exported CSVs (feature signal -> fraud_score)."""
    signal = abs(float(inp.get("score_signal", 0)))
    score = min(1.0, signal)
    decision = "deny" if score > 0.8 else "review" if score > 0.4 else "approve"
    return {
        "decision": decision,
        "fraud_score": round(score, 4),
    }
