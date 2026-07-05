"""Pydantic request/response models for the public API."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator


# --- Customers ------------------------------------------------------------- #
class CustomerCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)


class CustomerOut(BaseModel):
    customer_id: str
    name: str
    api_key: str


# --- Node attestors (admin: register trust anchors) ------------------------ #
class NodeAttestorCreate(BaseModel):
    type: str = Field(..., pattern="^(k8s_psat|aws_iid|gcp_iit)$")
    public_pem: str = Field(..., min_length=1)
    description: str = Field(default="", max_length=500)


class NodeAttestorOut(BaseModel):
    id: str
    customer_id: str
    type: str
    description: str
    created_at: datetime

    model_config = {"from_attributes": True}


# --- Capabilities ---------------------------------------------------------- #
class Capability(BaseModel):
    """A fine-grained ``(resource, action)`` right.

    ``action`` may be ``"*"`` to grant every action on a resource.
    Optional ``constraints`` are rejected until constraint-aware Biscuit rules exist.
    """

    resource: str = Field(..., min_length=1, max_length=200)
    action: str = Field(..., min_length=1, max_length=200)
    constraints: dict | None = Field(
        default=None,
        description="Rejected: not enforced by the authorizer yet.",
    )

    @field_validator("constraints")
    @classmethod
    def reject_unsupported_constraints(cls, value: dict | None) -> dict | None:
        if value:
            raise ValueError("Capability constraints are not supported yet")
        return value


# --- Registration entries (admin: pre-approve identities) ------------------ #
class RegistrationEntryCreate(BaseModel):
    agent_type: str = Field(..., min_length=1, max_length=200)
    selectors: list[str] = Field(..., min_length=1)
    # Capabilities are the source of truth; legacy ``scopes`` are accepted and
    # parsed into capabilities when no capabilities are given.
    capabilities: list[Capability] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)
    owner: str | None = Field(default=None, max_length=200)
    ttl_seconds: int | None = None
    description: str = Field(default="", max_length=500)


class RegistrationEntryOut(BaseModel):
    id: str
    agent_type: str
    selectors: list[str]
    # Stored capability dicts pass through verbatim (no null constraint noise).
    capabilities: list[dict] = Field(default_factory=list)
    scopes: list[str]
    owner: str | None = None
    ttl_seconds: int | None = None
    description: str
    created_at: datetime

    model_config = {"from_attributes": True}


class RegistrationOverlapConflict(BaseModel):
    selector_count: int
    entry_ids: list[str]
    agent_types: list[str]
    selectors: list[list[str]]
    witness_selectors: list[str]
    reason: str


class RegistrationLintReport(BaseModel):
    ok: bool
    conflicts: list[RegistrationOverlapConflict]


# --- Identity -------------------------------------------------------------- #
class IdentifyRequest(BaseModel):
    """Attestation request. The workload presents a signed attestation document;
    agent_type and scopes are NOT self-declared -- they come from the matched
    registration entry."""

    attestation_document: str = Field(..., min_length=1)
    ttl_seconds: int | None = None


class CredentialOut(BaseModel):
    agent_id: str
    token: str
    spiffe_id: str
    agent_type: str
    owner: str
    capabilities: list[dict] = Field(default_factory=list)
    scopes: list[str]
    selectors: list[str] = Field(default_factory=list)
    # Capability token bound to the workload's SPIFFE keypair (None when the
    # workload presented no public key). ``biscuit_root_public_key`` lets a
    # holder verify/authorize it offline.
    biscuit: str | None = None
    biscuit_root_public_key: str | None = None
    bound_keyhash: str | None = None
    expires_at: datetime


class PopIn(BaseModel):
    """Request-bound proof-of-possession from the workload's SPIFFE key."""

    challenge: str = Field(..., min_length=1)
    signature: str = Field(..., min_length=1)
    pubkey_pem: str = Field(..., min_length=1)
    htm: str = Field(..., min_length=1)
    htu: str = Field(..., min_length=1)
    ath: str = Field(..., min_length=1)
    iat: int
    jti: str = Field(..., min_length=1)


class ValidateRequest(BaseModel):
    token: str
    pop: PopIn | None = None


class ValidateResponse(BaseModel):
    valid: bool
    claims: dict | None = None


# --- Capability authorization --------------------------------------------- #
class OperationIn(BaseModel):
    resource: str = Field(..., min_length=1, max_length=200)
    action: str = Field(..., min_length=1, max_length=200)


class AuthorizeRequest(BaseModel):
    token: str = Field(..., min_length=1)
    operation: OperationIn
    pop: PopIn | None = None


class AuthorizeResponse(BaseModel):
    allowed: bool
    reason: str


class ChallengeResponse(BaseModel):
    challenge: str


# --- Agents (dashboard reads) --------------------------------------------- #
class AgentOut(BaseModel):
    id: str
    agent_type: str
    owner: str
    capabilities: list[dict] = Field(default_factory=list)
    scopes: list[str]
    spiffe_id: str | None = None
    selectors: list[str] = Field(default_factory=list)
    bound_keyhash: str | None = None
    has_biscuit: bool = False
    status: str
    action_count: int
    issued_at: datetime
    expires_at: datetime

    model_config = {"from_attributes": True}
