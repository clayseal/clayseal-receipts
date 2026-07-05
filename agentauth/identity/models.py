"""Typed response models for the SDK.

Plain dataclasses (no pydantic dependency for SDK consumers). Shapes mirror the
backend's Pydantic responses 1:1 so the Python and (future) TypeScript SDKs
return identical data. ``from_api`` constructors ignore unknown fields so the
SDK keeps working if the backend adds fields.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Credential:
    """The result of ``identify`` - an issued, attested agent token."""

    agent_id: str
    token: str
    spiffe_id: str
    agent_type: str
    owner: str
    scopes: list[str]
    selectors: list[str]
    expires_at: str
    # Capability token (Biscuit) bound to the workload's SPIFFE keypair, plus the
    # customer's root public key so it can be authorized offline. ``biscuit`` is
    # None when the workload presented no public key (JWT-only fallback).
    capabilities: list[dict] = field(default_factory=list)
    biscuit: Optional[str] = None
    biscuit_root_public_key: Optional[str] = None
    bound_keyhash: Optional[str] = None

    @classmethod
    def from_api(cls, d: dict) -> "Credential":
        return cls(
            agent_id=d["agent_id"],
            token=d["token"],
            spiffe_id=d.get("spiffe_id", ""),
            agent_type=d["agent_type"],
            owner=d["owner"],
            scopes=list(d.get("scopes", [])),
            selectors=list(d.get("selectors", [])),
            expires_at=d.get("expires_at", ""),
            capabilities=list(d.get("capabilities", [])),
            biscuit=d.get("biscuit"),
            biscuit_root_public_key=d.get("biscuit_root_public_key"),
            bound_keyhash=d.get("bound_keyhash"),
        )

    def to_binding_dict(self) -> dict[str, Any]:
        """The L1/L2 authority facts, in the shape the receipts runtime's
        ``AuthorityBinding.from_agentauth_credential`` consumes. This is the
        seam that binds an attested identity into every execution receipt."""
        return {
            "agent_id": self.agent_id,
            "spiffe_id": self.spiffe_id,
            "agent_type": self.agent_type,
            "owner": self.owner,
            "scopes": list(self.scopes),
            "selectors": list(self.selectors),
            "expires_at": self.expires_at,
            "capabilities": list(self.capabilities),
            "biscuit": self.biscuit,
            "has_biscuit": bool(self.biscuit),
            "bound_keyhash": self.bound_keyhash,
        }


@dataclass
class AgentInfo:
    """A read-model of an agent (dashboard/admin views)."""

    id: str
    agent_type: str
    owner: str
    scopes: list[str]
    spiffe_id: str
    selectors: list[str]
    status: str
    action_count: int
    issued_at: str
    expires_at: str
    capabilities: list[dict] = field(default_factory=list)
    bound_keyhash: Optional[str] = None
    has_biscuit: bool = False

    @classmethod
    def from_api(cls, d: dict) -> "AgentInfo":
        return cls(
            id=d["id"],
            agent_type=d["agent_type"],
            owner=d["owner"],
            scopes=list(d.get("scopes", [])),
            spiffe_id=d.get("spiffe_id", ""),
            selectors=list(d.get("selectors", [])),
            status=d["status"],
            action_count=d.get("action_count", 0),
            issued_at=d.get("issued_at", ""),
            expires_at=d.get("expires_at", ""),
            capabilities=list(d.get("capabilities", [])),
            bound_keyhash=d.get("bound_keyhash"),
            has_biscuit=d.get("has_biscuit", False),
        )


@dataclass
class ValidationResult:
    valid: bool
    claims: Optional[dict[str, Any]] = None

    @classmethod
    def from_api(cls, d: dict) -> "ValidationResult":
        return cls(valid=d.get("valid", False), claims=d.get("claims"))
