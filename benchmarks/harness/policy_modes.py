from __future__ import annotations

from agentauth.receipts import Policy

POLICY_MODE_CHOICES = ("permissive", "tight")


def tight_mcp_policy(name: str, allowed_tools: list[str]) -> Policy:
    return Policy.from_dict(
        {
            "version": 1,
            "name": name,
            "tier": "tool_trace",
            "capability": "operator_attested",
            "allowed_tools": {"tools": list(allowed_tools)},
            "output_schema": {"fields": ["status", "tool"], "required": []},
        }
    )
