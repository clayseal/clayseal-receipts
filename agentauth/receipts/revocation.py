"""Signer / witness revocation keyed by log integrated time (SOTA-16b).

Revocation is effective from a transparency-log sequence number (integrated time),
not from signer-asserted timestamps inside receipt bodies. This bounds backdating
after key compromise: a signature from a revoked key is rejected when the record's
``seq`` is at or after the revocation threshold.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RevocationEntry:
    public_key_hex: str
    revoked_at_seq: int


@dataclass
class SignerRevocationRegistry:
    """In-memory revocation table: public key hex → first invalid integrated-time seq."""

    _entries: dict[str, int] = field(default_factory=dict)

    def revoke(self, public_key_hex: str, *, at_seq: int) -> RevocationEntry:
        """Mark ``public_key_hex`` invalid for log records with ``seq >= at_seq``."""
        existing = self._entries.get(public_key_hex)
        if existing is None or at_seq < existing:
            self._entries[public_key_hex] = int(at_seq)
        return RevocationEntry(
            public_key_hex=public_key_hex,
            revoked_at_seq=self._entries[public_key_hex],
        )

    def revoked_at_seq(self, public_key_hex: str) -> int | None:
        return self._entries.get(public_key_hex)

    def is_revoked_at_seq(self, public_key_hex: str, seq: int) -> bool:
        threshold = self._entries.get(public_key_hex)
        return threshold is not None and int(seq) >= threshold

    def record_revocation_issues(
        self,
        *,
        public_key_hex: str | None,
        seq: int,
    ) -> list[str]:
        if not public_key_hex:
            return []
        threshold = self._entries.get(public_key_hex)
        if threshold is not None and int(seq) >= threshold:
            return [
                f"signer revoked at log integrated time {threshold}; "
                f"record seq {seq} is not valid"
            ]
        return []

    def checkpoint_revocation_issues(
        self,
        checkpoint: dict[str, Any],
    ) -> list[str]:
        """Reject checkpoints signed by a key revoked at or before the checkpoint count."""
        signature = checkpoint.get("signature")
        if not isinstance(signature, dict):
            return []
        public_key = signature.get("public_key")
        if not isinstance(public_key, str) or not public_key:
            return []
        count = checkpoint.get("count")
        if count is None:
            return []
        return self.record_revocation_issues(public_key_hex=public_key, seq=int(count))

    def to_dict(self) -> dict[str, int]:
        return dict(self._entries)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> SignerRevocationRegistry:
        registry = cls()
        for key, value in raw.items():
            registry._entries[str(key)] = int(value)
        return registry
