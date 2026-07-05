"""Persistence models.

Datetimes are stored as naive UTC. SQLite has no native tz support, so we
standardise on "naive == UTC" everywhere and never mix aware/naive values.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def new_id() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    # Naive UTC -- see module docstring.
    return datetime.utcnow()


def to_epoch(dt: datetime) -> int:
    """Convert a naive-UTC datetime to a Unix timestamp.

    ``datetime.utcnow()`` returns a *naive* value; calling ``.timestamp()`` on
    it would wrongly interpret it as local time. We pin tzinfo to UTC first.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def spiffe_id(trust_domain: str, customer_id: str, agent_type: str) -> str:
    """Build the SPIFFE ID for an agent of ``agent_type`` owned by a customer.

    Mirrors the production SPIRE layout from ``identity/identity.md``:
    ``spiffe://agentauth.io/customer/{customer_id}/agent/{agent_type}``.
    """
    return f"spiffe://{trust_domain}/customer/{customer_id}/agent/{agent_type}"


class Customer(Base):
    """A tenant. Owns its own signing keys and agents."""

    __tablename__ = "customers"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String, nullable=False)
    # ``api_key`` stores only the public lookup prefix, not the full secret.
    api_key: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    api_key_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class CapabilityChallenge(Base):
    """A short-lived, one-time server challenge for PoP authorization."""

    __tablename__ = "capability_challenges"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    customer_id: Mapped[str] = mapped_column(
        ForeignKey("customers.id"), index=True, nullable=False
    )
    challenge: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AttestationUse(Base):
    """Record of a consumed attestation document ``jti`` (one-time identify)."""

    __tablename__ = "attestation_uses"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    customer_id: Mapped[str] = mapped_column(
        ForeignKey("customers.id"), index=True, nullable=False
    )
    jti: Mapped[str] = mapped_column(String, index=True, nullable=False)
    used_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class SigningKey(Base):
    """An Ed25519 keypair used to sign/verify a customer's agent credentials.

    Rotation: at any time exactly one key per customer is ``active``. Rotating
    creates a new active key and marks the previous one ``retired`` -- retired
    keys still verify already-issued tokens until those tokens expire.
    """

    __tablename__ = "signing_keys"

    kid: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    customer_id: Mapped[str] = mapped_column(
        ForeignKey("customers.id"), index=True, nullable=False
    )
    private_pem: Mapped[str] = mapped_column(Text, nullable=False)
    public_pem: Mapped[str] = mapped_column(Text, nullable=False)
    algorithm: Mapped[str] = mapped_column(String, default="EdDSA")
    status: Mapped[str] = mapped_column(String, default="active")  # active | retired
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class BiscuitRootKey(Base):
    """An Ed25519 keypair that roots a customer's Biscuit capability tokens.

    Parallel to :class:`SigningKey` (which roots JWT-SVIDs) but a distinct key
    lifecycle: both use Ed25519, while Biscuit stores raw root-key bytes and JWT
    signing stores PEM keys for JOSE/JWKS interop. Anyone with the ``public_hex``
    can verify and authorize a customer's capability tokens **offline** -- it's
    published the way ``jwks.json`` publishes JWT-signing keys.
    Rotation mirrors SigningKey: exactly one ``active`` key per customer; rotating
    retires the old one (retired keys still verify already-minted tokens).
    """

    __tablename__ = "biscuit_root_keys"

    kid: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    customer_id: Mapped[str] = mapped_column(
        ForeignKey("customers.id"), index=True, nullable=False
    )
    # Raw Ed25519 key bytes, hex-encoded (biscuit_auth keys serialize to bytes).
    private_hex: Mapped[str] = mapped_column(Text, nullable=False)
    public_hex: Mapped[str] = mapped_column(Text, nullable=False)
    algorithm: Mapped[str] = mapped_column(String, default="ed25519")
    status: Mapped[str] = mapped_column(String, default="active")  # active | retired
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class BiscuitRevocation(Base):
    """A tenant-scoped Biscuit revocation-id deny-list entry."""

    __tablename__ = "biscuit_revocations"
    __table_args__ = (
        UniqueConstraint("customer_id", "revocation_id", name="uq_biscuit_revocation"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    customer_id: Mapped[str] = mapped_column(
        ForeignKey("customers.id"), index=True, nullable=False
    )
    revocation_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    reason: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class NodeAttestor(Base):
    """A registered trust anchor for node attestation.

    The production analogue is bootstrapping the SPIRE Server with the material
    needed to verify a cloud/cluster: the public half of the key that AWS (IID),
    a Kubernetes cluster (PSAT), or GCP (IIT) uses to sign node evidence.
    Registering one here means "this tenant trusts nodes whose attestation
    documents are signed by this key." An agent's attestation document must
    verify against one of these or attestation is denied.
    """

    __tablename__ = "node_attestors"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    customer_id: Mapped[str] = mapped_column(
        ForeignKey("customers.id"), index=True, nullable=False
    )
    # k8s_psat | aws_iid | gcp_iit
    type: Mapped[str] = mapped_column(String, index=True, nullable=False)
    public_pem: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class RegistrationEntry(Base):
    """An admin-pre-approved identity: which agent_type (and scopes) a workload
    may receive *if* it can attest the required selectors.

    This is the SPIRE registration entry. The workload never picks its own
    agent_type or scopes; they come from the matching entry. ``selectors`` is
    the set of node + workload selectors that must ALL be present (a subset of
    what the attestors derive) for this entry to match.
    """

    __tablename__ = "registration_entries"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    customer_id: Mapped[str] = mapped_column(
        ForeignKey("customers.id"), index=True, nullable=False
    )
    agent_type: Mapped[str] = mapped_column(String, index=True, nullable=False)
    selectors: Mapped[list] = mapped_column(JSON, default=list)
    # Fine-grained capabilities are the source of truth: a list of
    # ``{"resource": str, "action": str, "constraints": dict?}`` objects. The
    # legacy flat ``scopes`` list is kept as a derived ``"resource:action"``
    # mirror for back-compat (see identity.derive_* helpers).
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    owner: Mapped[str | None] = mapped_column(String, nullable=True)
    ttl_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    description: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Agent(Base):
    """One agent instance that has been issued a credential."""

    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_id)
    customer_id: Mapped[str] = mapped_column(
        ForeignKey("customers.id"), index=True, nullable=False
    )
    agent_type: Mapped[str] = mapped_column(String, index=True, nullable=False)
    owner: Mapped[str] = mapped_column(String, index=True, nullable=False)
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(
        String, default="active", index=True
    )  # active | expired | revoked

    # SPIFFE ID this agent was issued (`sub` of its JWT-SVID).
    spiffe_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    # The attested selectors that produced this identity.
    selectors: Mapped[list] = mapped_column(JSON, default=list)

    # Capability token (Biscuit, base64) bound to the workload's SPIFFE keypair,
    # the root key that signed it, and the SHA-256 hash of the bound public key.
    biscuit: Mapped[str | None] = mapped_column(Text, nullable=True)
    biscuit_kid: Mapped[str | None] = mapped_column(String, nullable=True)
    biscuit_revocation_ids: Mapped[list] = mapped_column(JSON, default=list)
    bound_keyhash: Mapped[str | None] = mapped_column(String, nullable=True)
    workload_pubkey_pem: Mapped[str | None] = mapped_column(Text, nullable=True)

    jti: Mapped[str] = mapped_column(String, index=True, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    action_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    @property
    def has_biscuit(self) -> bool:
        """Whether a capability token was minted for this agent (vs JWT-only)."""
        return self.biscuit is not None


class AuditEvent(Base):
    """A single credential-lifecycle event in the identity audit log.

    Replaces the legacy flat ``audit.jsonl`` file: events live in the same
    durable, queryable SQLite store as everything else, still as a tamper-evident
    hash chain. ``sequence`` is a monotonic per-log counter (not DB-assigned, so
    it is part of the hashed material); ``entry_hash`` chains to ``prev_hash``.
    """

    __tablename__ = "audit_events"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True)
    customer_id: Mapped[str] = mapped_column(String, index=True)
    type: Mapped[str] = mapped_column(String, index=True)
    # ISO-8601 string actually used in the hash material (avoids datetime
    # round-trip ambiguity when re-verifying the chain).
    ts: Mapped[str] = mapped_column(String)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    entry_hash: Mapped[str] = mapped_column(String)
