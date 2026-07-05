from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from agentauth.core.hash_util import hash_canonical_json

from agentauth.core.runtime import ExecutionContext

MONITOR_INPUT_SCHEMA = "agent-receipts.monitor-input.v1"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def arguments_hash(input_obj: Any) -> str:
    """Hash canonical JSON for monitor inputs (avoid raw args by default)."""
    return f"sha256:{hash_canonical_json(input_obj)}"


@dataclass(frozen=True)
class MonitorTraceEvent:
    """Bounded, structured trace event (safe under tool-output prompt injection)."""

    action_name: str
    action_category: str
    side_effect_level: str
    resource_ref: str | None
    arguments_hash: str
    at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_name": self.action_name,
            "action_category": self.action_category,
            "side_effect_level": self.side_effect_level,
            "resource_ref": self.resource_ref,
            "arguments_hash": self.arguments_hash,
            "at": self.at,
        }


@dataclass(frozen=True)
class MonitorInput:
    """
    Structured monitor input contract (trusted telemetry only).

    This is intentionally designed to exclude raw tool outputs, file contents, and web text.
    """

    proposed: MonitorTraceEvent
    recent: list[MonitorTraceEvent] = field(default_factory=list)
    query_id: str | None = None
    touched_resources: list[str] = field(default_factory=list)
    authority_lease: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": MONITOR_INPUT_SCHEMA,
            "proposed": self.proposed.to_dict(),
            "recent": [item.to_dict() for item in self.recent],
            "query_id": self.query_id,
            "touched_resources": list(self.touched_resources),
            "authority_lease": dict(self.authority_lease),
        }

    def trace_commitment(self) -> str:
        """Non-repudiable commitment to the exact contract object (sha256 of canonical JSON)."""
        return f"sha256:{hash_canonical_json(self.to_dict())}"


def build_monitor_input(
    ctx: ExecutionContext,
    *,
    recent: list[MonitorTraceEvent] | None = None,
    at: str | None = None,
) -> MonitorInput:
    """
    Build the monitor input contract from an ExecutionContext.

    Contract rules:
    - includes action identity + side-effect level + resource_ref
    - includes `arguments_hash` (not raw args)
    - includes lease facts as data (expiry/query_id/ceilings)
    - excludes untrusted tool outputs by design
    """
    at = at or _utc_now_iso()
    proposed = MonitorTraceEvent(
        action_name=ctx.action.action_name,
        action_category=ctx.action.action_category,
        side_effect_level=ctx.action.side_effect_level.value,
        resource_ref=ctx.action.resource_ref,
        arguments_hash=arguments_hash(ctx.input),
        at=at,
    )
    lease = {
        "authority_id": ctx.authority.authority_id,
        "authority_version": int(ctx.authority.authority_version),
        "permit_epoch": int(ctx.authority.permit_epoch),
        "expires_at": ctx.authority.expires_at,
        "lease_query_id": ctx.authority.lease_query_id,
        "lease_remaining_calls": ctx.authority.lease_remaining_calls,
    }
    return MonitorInput(
        proposed=proposed,
        recent=list(recent or []),
        query_id=ctx.query_id,
        touched_resources=list(ctx.touched_resources),
        authority_lease=lease,
    )

