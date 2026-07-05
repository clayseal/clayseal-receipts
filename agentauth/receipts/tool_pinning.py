"""MCP tool pinning + anti-rug-pull (RT-2 / SM-18)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentauth.core.hash_util import hash_canonical_json


@dataclass
class ToolPinningPolicy:
    enabled: bool = False
    require_pinned: bool = False
    deny_on_mismatch: bool = True
    require_witness_tools: list[str] = field(default_factory=list)

    @classmethod
    def from_policy_dict(cls, raw: dict[str, Any] | None) -> ToolPinningPolicy:
        if not isinstance(raw, dict):
            return cls()
        witness = raw.get("require_witness_tools") or raw.get("require_witness") or []
        return cls(
            enabled=bool(raw.get("enabled", False)),
            require_pinned=bool(raw.get("require_pinned", False)),
            deny_on_mismatch=bool(raw.get("deny_on_mismatch", True)),
            require_witness_tools=[str(item) for item in witness],
        )


@dataclass(frozen=True)
class ToolPin:
    server: str
    tool: str
    identity_hash: str
    description_hash: str | None = None
    input_schema_hash: str | None = None

    @classmethod
    def compute(
        cls,
        *,
        server: str,
        tool: str,
        description: str | None = None,
        input_schema: dict[str, Any] | None = None,
    ) -> ToolPin:
        return cls(
            server=server,
            tool=tool,
            identity_hash=hash_canonical_json({"server": server, "tool": tool}),
            description_hash=(
                hash_canonical_json({"description": description})
                if description is not None
                else None
            ),
            input_schema_hash=(
                hash_canonical_json(input_schema) if input_schema is not None else None
            ),
        )


class ToolPinRegistry:
    """Session-local registry of pinned tool metadata."""

    def __init__(self) -> None:
        self._pins: dict[tuple[str, str], ToolPin] = {}

    def pin(
        self,
        server: str,
        tool: str,
        *,
        description: str | None = None,
        input_schema: dict[str, Any] | None = None,
    ) -> ToolPin:
        pin = ToolPin.compute(
            server=server,
            tool=tool,
            description=description,
            input_schema=input_schema,
        )
        self._pins[(server, tool)] = pin
        return pin

    def get(self, server: str, tool: str) -> ToolPin | None:
        return self._pins.get((server, tool))

    def verify(
        self,
        server: str,
        tool: str,
        *,
        description: str | None = None,
        input_schema: dict[str, Any] | None = None,
    ) -> list[str]:
        """Return violations when live metadata diverges from the pinned record."""
        pin = self._pins.get((server, tool))
        if pin is None:
            return ["tool not pinned"]
        live = ToolPin.compute(
            server=server,
            tool=tool,
            description=description,
            input_schema=input_schema,
        )
        violations: list[str] = []
        if live.description_hash != pin.description_hash:
            violations.append(
                f"tool {tool!r} description hash changed (possible MCP rug pull)"
            )
        if (
            pin.input_schema_hash is not None
            and live.input_schema_hash != pin.input_schema_hash
        ):
            violations.append(
                f"tool {tool!r} input schema hash changed (possible MCP rug pull)"
            )
        return violations


def tool_pinning_violations(
    *,
    policy: ToolPinningPolicy,
    registry: ToolPinRegistry,
    server: str,
    tool: str,
    description: str | None,
    input_schema: dict[str, Any] | None,
    tool_witness_present: bool,
) -> list[str]:
    violations: list[str] = []
    if not policy.enabled:
        return violations

    existing = registry.get(server, tool)
    if existing is None:
        registry.pin(server, tool, description=description, input_schema=input_schema)
        if policy.require_pinned and description is None and input_schema is None:
            violations.append(f"tool {tool!r} must be pinned with description or schema")
        return violations

    if policy.deny_on_mismatch:
        violations.extend(
            registry.verify(
                server,
                tool,
                description=description,
                input_schema=input_schema,
            )
        )

    if tool in policy.require_witness_tools and not tool_witness_present:
        violations.append(
            f"tool {tool!r} requires a tool witness co-signature (RT-2 / SOTA-16c)"
        )
    return violations
