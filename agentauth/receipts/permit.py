from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from agentauth.core.runtime import ExecutionContext
from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.signing import SigningKey, signature_key_id_matches, verify

TOOL_PERMIT_SCHEMA = "agent-receipts.tool-permit.v1"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class ToolPermit:
    """
    Signed, short-lived authorization for a single tool call.

    This is designed to be *verified at the tool proxy boundary*, not by the agent.
    """

    permit_id: str
    issued_at: str
    expires_at: str
    query_id: str | None
    authority_id: str
    authority_version: int
    permit_epoch: int
    tool_name: str
    resource_ref: str | None
    arguments_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": TOOL_PERMIT_SCHEMA,
            "permit_id": self.permit_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "query_id": self.query_id,
            "authority_id": self.authority_id,
            "authority_version": int(self.authority_version),
            "permit_epoch": int(self.permit_epoch),
            "tool_name": self.tool_name,
            "resource_ref": self.resource_ref,
            "arguments_hash": self.arguments_hash,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ToolPermit:
        return cls(
            permit_id=str(raw["permit_id"]),
            issued_at=str(raw["issued_at"]),
            expires_at=str(raw["expires_at"]),
            query_id=raw.get("query_id"),
            authority_id=str(raw["authority_id"]),
            authority_version=int(raw.get("authority_version", 1)),
            permit_epoch=int(raw.get("permit_epoch", 0)),
            tool_name=str(raw["tool_name"]),
            resource_ref=raw.get("resource_ref"),
            arguments_hash=str(raw["arguments_hash"]),
        )


@dataclass(frozen=True)
class SignedToolPermit:
    permit: ToolPermit
    signature: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "permit": self.permit.to_dict(),
            "signature": dict(self.signature),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> SignedToolPermit:
        return cls(
            permit=ToolPermit.from_dict(dict(raw["permit"])),
            signature=dict(raw["signature"]),
        )


def issue_tool_permit(
    ctx: ExecutionContext,
    *,
    key: SigningKey,
    ttl_seconds: int,
) -> SignedToolPermit:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be > 0")

    tool_name = ctx.action.action_name.rsplit("/", 1)[-1]
    now = _utc_now()
    permit = ToolPermit(
        permit_id=str(uuid4()),
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
        query_id=ctx.query_id,
        authority_id=ctx.authority.authority_id,
        authority_version=int(ctx.authority.authority_version),
        permit_epoch=int(ctx.authority.permit_epoch),
        tool_name=tool_name,
        resource_ref=ctx.action.resource_ref,
        arguments_hash=hash_canonical_json(ctx.input),
    )
    permit_dict = permit.to_dict()
    signature = key.sign(permit_dict)
    return SignedToolPermit(permit=permit, signature=signature)


def verify_tool_permit(
    signed: SignedToolPermit,
    *,
    ctx: ExecutionContext,
    at: datetime | None = None,
) -> tuple[bool, str | None]:
    """
    Verify permit cryptography + expiry + binding to the supplied ExecutionContext.

    Returns (ok, reason).
    """
    at = at or _utc_now()
    permit_dict = signed.permit.to_dict()
    if not signature_key_id_matches(signed.signature):
        return False, "permit signature key_id does not match public_key"
    if not verify(permit_dict, signed.signature):
        return False, "permit signature invalid"

    expires_at = _parse_dt(signed.permit.expires_at)
    if expires_at is None:
        return False, "permit expires_at invalid"
    if expires_at <= at.astimezone(timezone.utc):
        return False, "permit expired"

    tool_name = ctx.action.action_name.rsplit("/", 1)[-1]
    if signed.permit.tool_name != tool_name:
        return False, "permit tool_name mismatch"
    if signed.permit.resource_ref != ctx.action.resource_ref:
        return False, "permit resource_ref mismatch"
    if signed.permit.arguments_hash != hash_canonical_json(ctx.input):
        return False, "permit arguments_hash mismatch"
    if signed.permit.authority_id != ctx.authority.authority_id:
        return False, "permit authority_id mismatch"
    if int(signed.permit.authority_version) != int(ctx.authority.authority_version):
        return False, "permit authority_version mismatch"
    if int(signed.permit.permit_epoch) != int(ctx.authority.permit_epoch):
        return False, "permit epoch mismatch"
    if signed.permit.query_id != ctx.query_id:
        return False, "permit query_id mismatch"

    return True, None
