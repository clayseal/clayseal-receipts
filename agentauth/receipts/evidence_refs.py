"""Optional evidence cross-references for replay (L3-13, L4-2 partial)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class EvidenceRefs:
    state_snapshot_id: str | None = None
    decision_context_hash: str | None = None
    handoff_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "state_snapshot_id": self.state_snapshot_id,
            "decision_context_hash": self.decision_context_hash,
            "handoff_ref": self.handoff_ref,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> EvidenceRefs:
        return cls(
            state_snapshot_id=raw.get("state_snapshot_id"),
            decision_context_hash=raw.get("decision_context_hash"),
            handoff_ref=raw.get("handoff_ref"),
        )
