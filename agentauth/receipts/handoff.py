"""Session handoff artifacts for kill/respawn and authority rotation (L4-4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


@dataclass
class SessionHandoffArtifact:
    handoff_id: str
    session_id: str
    from_authority_version: int
    to_authority_version: int
    reason: str
    prior_receipt_refs: list[str] = field(default_factory=list)
    budget_snapshot: list[dict[str, Any]] = field(default_factory=list)
    pending_obligations: list[dict[str, Any]] = field(default_factory=list)
    approval_state: str | None = None
    touched_resources: list[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def create(
        cls,
        *,
        session_id: str,
        from_authority_version: int,
        to_authority_version: int,
        reason: str,
        **kwargs: Any,
    ) -> SessionHandoffArtifact:
        return cls(
            handoff_id=str(uuid4()),
            session_id=session_id,
            from_authority_version=from_authority_version,
            to_authority_version=to_authority_version,
            reason=reason,
            **kwargs,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "handoff_id": self.handoff_id,
            "session_id": self.session_id,
            "from_authority_version": self.from_authority_version,
            "to_authority_version": self.to_authority_version,
            "reason": self.reason,
            "prior_receipt_refs": list(self.prior_receipt_refs),
            "budget_snapshot": list(self.budget_snapshot),
            "pending_obligations": list(self.pending_obligations),
            "approval_state": self.approval_state,
            "touched_resources": list(self.touched_resources),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> SessionHandoffArtifact:
        return cls(
            handoff_id=str(raw["handoff_id"]),
            session_id=str(raw["session_id"]),
            from_authority_version=int(raw["from_authority_version"]),
            to_authority_version=int(raw["to_authority_version"]),
            reason=str(raw["reason"]),
            prior_receipt_refs=list(raw.get("prior_receipt_refs", [])),
            budget_snapshot=list(raw.get("budget_snapshot", [])),
            pending_obligations=list(raw.get("pending_obligations", [])),
            approval_state=raw.get("approval_state"),
            touched_resources=list(raw.get("touched_resources", [])),
            created_at=str(raw.get("created_at", datetime.now(timezone.utc).isoformat())),
        )
