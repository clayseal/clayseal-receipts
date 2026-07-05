"""Mandatory governed-tool path: block raw MCP / direct tool side effects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_TOOL_ACTION_MARKERS = ("mcp.", "tool.", "tools/")


@dataclass
class GovernedRuntimePolicy:
    """When enabled, tool calls must originate from ReceiptedMcpGateway."""

    require_gateway: bool = False
    block_ungoverned_tool_actions: bool = True

    @classmethod
    def from_policy_dict(cls, raw: dict[str, Any] | None) -> GovernedRuntimePolicy:
        if not isinstance(raw, dict):
            return cls()
        return cls(
            require_gateway=bool(raw.get("require_gateway", False)),
            block_ungoverned_tool_actions=bool(
                raw.get("block_ungoverned_tool_actions", True)
            ),
        )


class GovernedToolError(RuntimeError):
    """Raised when a tool side-effect bypasses the governed gateway."""


def is_tool_action(action_name: str) -> bool:
    lowered = action_name.lower()
    return any(marker in lowered for marker in _TOOL_ACTION_MARKERS) or lowered.startswith(
        "tool_"
    )


def evaluate_governed_tool_call(
    *,
    action_name: str,
    policy: GovernedRuntimePolicy,
    gateway_token: str | None,
) -> list[str]:
    """Return violations when tool calls are not routed through the gateway."""
    if not policy.require_gateway and not policy.block_ungoverned_tool_actions:
        return []
    if not is_tool_action(action_name):
        return []
    if gateway_token == "receipted_mcp_gateway":
        return []
    if policy.require_gateway:
        return [
            "ungoverned_tool_call: tool actions must use ReceiptedMcpGateway "
            "(set governed_runtime.require_gateway on the policy)"
        ]
    if policy.block_ungoverned_tool_actions:
        return ["ungoverned_tool_call: direct tool invocation outside governed gateway"]
    return []
