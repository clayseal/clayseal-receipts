"""Identity Service.

Issues and validates signed agent credentials. Each credential is a JWT
(EdDSA/Ed25519) signed with a per-customer keypair that this service manages,
including automatic rotation. Developers never see a key.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from sqlalchemy import select
from sqlalchemy.orm import Session

from agentauth.workload_keys import canonical_public_pem

from . import capabilities as cap_service
from .attestation import derive_workload_selectors, record_attestation_use, verify_node_attestation
from .audit import record_event
from .config import get_settings
from .errors import (
    AgentRevokedError,
    AttestationDeniedError,
    BiscuitError,
    InvalidTokenError,
    NodeAttestorError,
    RegistrationEntryError,
    TokenExpiredError,
    TTLOutOfRangeError,
)
from .models import (
    Agent,
    BiscuitRootKey,
    Customer,
    NodeAttestor,
    RegistrationEntry,
    SigningKey,
    new_id,
    spiffe_id,
    to_epoch,
    utcnow,
)
from .signing_keys import decrypt_private_pem, encrypt_private_pem, maybe_reencrypt_signing_key

# --------------------------------------------------------------------------- #
# Key management
# --------------------------------------------------------------------------- #
JWT_ALGORITHM = "EdDSA"
JWT_TYPE = "agentauth-svid+jwt"


def generate_ed25519_keypair() -> tuple[str, str]:
    """Return a fresh Ed25519 ``(private_pem, public_pem)`` pair."""
    key = ed25519.Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


def create_signing_key(db: Session, customer_id: str) -> SigningKey:
    private_pem, public_pem = generate_ed25519_keypair()
    key = SigningKey(
        kid=new_id(),
        customer_id=customer_id,
        private_pem=encrypt_private_pem(private_pem),
        public_pem=public_pem,
        algorithm=JWT_ALGORITHM,
        status="active",
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return key


def get_active_key(db: Session, customer_id: str) -> SigningKey:
    """Return the customer's active signing key, creating one if needed."""
    active_keys = list(
        db.scalars(
            select(SigningKey)
            .where(SigningKey.customer_id == customer_id, SigningKey.status == "active")
            .order_by(SigningKey.created_at.desc())
        ).all()
    )
    ed25519_keys = [key for key in active_keys if key.algorithm == JWT_ALGORITHM]
    key = ed25519_keys[0] if ed25519_keys else None
    changed = False
    for stale in active_keys:
        if stale.algorithm != JWT_ALGORITHM or (key is not None and stale.kid != key.kid):
            stale.status = "retired"
            stale.retired_at = utcnow()
            db.add(stale)
            changed = True
    if changed:
        db.commit()
    if key is None:
        key = create_signing_key(db, customer_id)
    else:
        db.refresh(key)
    maybe_reencrypt_signing_key(db, key)
    return key


def _active_signing_key(db: Session, customer_id: str) -> SigningKey | None:
    return db.scalar(
        select(SigningKey).where(
            SigningKey.customer_id == customer_id, SigningKey.status == "active"
        )
    )


def rotate_key(db: Session, customer_id: str) -> SigningKey:
    """Retire the current active key and create a new one.

    Retired keys remain in the DB so already-issued tokens still verify until
    they expire; only new tokens use the new key.
    """
    current = _active_signing_key(db, customer_id)
    if current is not None:
        current.status = "retired"
        current.retired_at = utcnow()
        db.add(current)
        db.commit()
    new_key = create_signing_key(db, customer_id)
    record_event("key.rotated", customer_id, new_kid=new_key.kid,
                 retired_kid=current.kid if current else None)
    return new_key


# --------------------------------------------------------------------------- #
# Credential issuance & validation
# --------------------------------------------------------------------------- #
def _clamp_ttl(ttl_seconds: int | None) -> int:
    settings = get_settings()
    if ttl_seconds is None:
        return settings.default_ttl_seconds
    if ttl_seconds < settings.min_ttl_seconds or ttl_seconds > settings.max_ttl_seconds:
        raise TTLOutOfRangeError(
            f"ttl_seconds={ttl_seconds} is outside the allowed range "
            f"[{settings.min_ttl_seconds}, {settings.max_ttl_seconds}].",
            suggestion=(
                f"Pass ttl_seconds between {settings.min_ttl_seconds} (5 min) and "
                f"{settings.max_ttl_seconds} (24 h)."
            ),
            min_ttl_seconds=settings.min_ttl_seconds,
            max_ttl_seconds=settings.max_ttl_seconds,
        )
    return ttl_seconds


def issue_credential(
    db: Session,
    customer: Customer,
    *,
    agent_type: str,
    owner: str,
    capabilities: list[dict] | None = None,
    scopes: list[str] | None = None,
    ttl_seconds: int | None = None,
    agent_id: str | None = None,
    selectors: list[str] | None = None,
    workload_pubkey_pem: str | None = None,
    extra_claims: dict | None = None,
) -> tuple[Agent, str]:
    """Mint a new agent identity and return ``(agent_row, jwt_svid_string)``.

    This is the low-level mint primitive; root identities go through
    :func:`attest` (which proves selectors first). The credential is a
    **JWT-SVID**: its ``sub`` is the agent's SPIFFE ID and the instance is
    carried in the ``agent_id`` claim.

    Capabilities are the source of truth for authorization; ``scopes`` is kept as
    a derived ``"resource:action"`` mirror so existing JWT consumers keep working.
    Every credential is sender-constrained to the workload SPIFFE key presented
    at identify time; a Biscuit capability token is minted when rights are granted.
    """
    if not workload_pubkey_pem:
        raise AttestationDeniedError(
            "Cannot mint a credential without the workload SPIFFE public key.",
            suggestion=(
                "Include workload_pubkey_pem in the attestation evidence so the "
                "issued JWT-SVID can be bound with proof-of-possession."
            ),
        )
    capabilities, scopes = cap_service.reconcile_capabilities(capabilities, scopes)
    selectors = list(selectors or [])
    ttl = _clamp_ttl(ttl_seconds)
    settings = get_settings()
    key = get_active_key(db, customer.id)

    now = utcnow()
    expires_at = now + timedelta(seconds=ttl)
    agent_id = agent_id or new_id()
    jti = new_id()
    sid = spiffe_id(settings.trust_domain, customer.id, agent_type)

    claims: dict = {
        "iss": settings.jwt_issuer,
        "sub": sid,
        "aud": customer.id,
        "iat": to_epoch(now),
        "nbf": to_epoch(now),
        "exp": to_epoch(expires_at),
        "jti": jti,
        "customer_id": customer.id,
        "spiffe_id": sid,
        "agent_id": agent_id,
        "agent_type": agent_type,
        "owner": owner,
        "scope": scopes,
        "selectors": selectors,
    }
    if extra_claims:
        claims.update(extra_claims)

    # Bind the JWT-SVID and (when granted) the Biscuit to the Ed25519 workload key.
    try:
        workload_pubkey_pem = canonical_public_pem(workload_pubkey_pem)
        bound_keyhash = cap_service.keyhash_for_pem(workload_pubkey_pem)
    except ValueError as exc:
        raise AttestationDeniedError(
            "The workload SPIFFE public key must be an Ed25519 public key.",
            suggestion=(
                "Generate an ephemeral Ed25519 workload key via the workload identity "
                "agent and include its SPKI PEM public key in attestation evidence."
            ),
        ) from exc
    claims["cnf"] = {"jkt": bound_keyhash}
    biscuit = None
    biscuit_kid = None
    biscuit_revocation_ids: list[str] = []
    if capabilities:
        root = cap_service.get_active_root_key(db, customer.id)
        biscuit = cap_service.mint_biscuit(
            root_private_hex=cap_service.resolve_root_private_hex(root),
            spiffe_id=sid,
            agent_id=agent_id,
            capabilities=capabilities,
            bound_keyhash=bound_keyhash,
            expires_at=expires_at,
        )
        biscuit_kid = root.kid
        biscuit_revocation_ids = cap_service.read_revocation_ids(biscuit, root.public_hex)

    token = jwt.encode(
        claims,
        decrypt_private_pem(key.private_pem),
        algorithm=JWT_ALGORITHM,
        headers={"kid": key.kid, "typ": JWT_TYPE},
    )

    agent = Agent(
        id=agent_id,
        customer_id=customer.id,
        agent_type=agent_type,
        owner=owner,
        capabilities=capabilities,
        scopes=scopes,
        status="active",
        spiffe_id=sid,
        selectors=selectors,
        biscuit=biscuit,
        biscuit_kid=biscuit_kid,
        biscuit_revocation_ids=biscuit_revocation_ids,
        bound_keyhash=bound_keyhash,
        workload_pubkey_pem=workload_pubkey_pem,
        jti=jti,
        issued_at=now,
        expires_at=expires_at,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)

    record_event(
        "identity.issued",
        customer.id,
        agent_id=agent.id,
        agent_type=agent_type,
        owner=owner,
        capabilities=capabilities,
        scopes=scopes,
        spiffe_id=sid,
        selectors=selectors,
        expires_at=expires_at.isoformat() + "Z",
        kid=key.kid,
    )
    if biscuit is not None:
        record_event(
            "capability.issued",
            customer.id,
            agent_id=agent.id,
            capabilities=capabilities,
            bound_keyhash=bound_keyhash,
            biscuit_kid=biscuit_kid,
            revocation_ids=biscuit_revocation_ids,
        )
    return agent, token


# --------------------------------------------------------------------------- #
# Attestation: registering trust anchors / entries and proving identity
# --------------------------------------------------------------------------- #
def _validate_node_attestor_public_pem(public_pem: str) -> str:
    """Parse and normalize PEM public key material for node attestors."""
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_pem_public_key,
    )

    stripped = public_pem.strip()
    if not stripped:
        raise NodeAttestorError(
            "public_pem must be a PEM-encoded public key.",
            suggestion="Send the public half of the key your node agent signs evidence with.",
        )
    try:
        key = load_pem_public_key(stripped.encode())
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise NodeAttestorError(
            "public_pem must be a valid PEM-encoded public key.",
            suggestion="Send an RSA public key in SPKI PEM format (RS256 attestation).",
        ) from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise NodeAttestorError(
            "public_pem must be an RSA public key.",
            suggestion="Node attestation documents are verified with RS256.",
        )
    min_bits = get_settings().rsa_key_size
    if key.key_size < min_bits:
        raise NodeAttestorError(
            f"public_pem RSA key must be at least {min_bits} bits.",
            suggestion=f"Generate a {min_bits}-bit or stronger RSA key for the node attestor.",
        )
    return key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def register_node_attestor(
    db: Session,
    customer: Customer,
    *,
    type: str,
    public_pem: str,
    description: str = "",
) -> NodeAttestor:
    """Register a node trust anchor (admin op): the public key whose signatures
    this tenant will accept as proof of node provenance."""
    from .attestation import SUPPORTED_ATTESTOR_TYPES

    if type not in SUPPORTED_ATTESTOR_TYPES:
        raise NodeAttestorError(
            f"Unknown node attestor type '{type}'.",
            suggestion=f"type must be one of {sorted(SUPPORTED_ATTESTOR_TYPES)}.",
        )
    normalized_pem = _validate_node_attestor_public_pem(public_pem)
    attestor = NodeAttestor(
        id=new_id(),
        customer_id=customer.id,
        type=type,
        public_pem=normalized_pem,
        description=description,
    )
    db.add(attestor)
    db.commit()
    db.refresh(attestor)
    record_event(
        "node_attestor.created", customer.id, attestor_id=attestor.id, attestor_type=type
    )
    return attestor


def register_entry(
    db: Session,
    customer: Customer,
    *,
    agent_type: str,
    selectors: list[str],
    capabilities: list[dict] | None = None,
    scopes: list[str] | None = None,
    owner: str | None = None,
    ttl_seconds: int | None = None,
    description: str = "",
) -> RegistrationEntry:
    """Pre-approve an identity (admin op): the selectors a workload must attest
    to receive ``agent_type`` and its capabilities.

    Capabilities are the source of truth; if only legacy ``scopes`` are given
    they are parsed into capabilities, and ``scopes`` is always stored as the
    derived mirror.
    """
    selectors = [s for s in (selectors or []) if s]
    if not selectors:
        raise RegistrationEntryError(
            "A registration entry must require at least one selector.",
            suggestion="List the node/workload selectors a workload must prove, e.g. "
            "['k8s:ns:customer-acme', 'k8s:sa:finance-agent'].",
        )
    capabilities, scopes = cap_service.reconcile_capabilities(capabilities, scopes)
    entry = RegistrationEntry(
        id=new_id(),
        customer_id=customer.id,
        agent_type=agent_type,
        selectors=selectors,
        capabilities=capabilities,
        scopes=scopes,
        owner=owner,
        ttl_seconds=ttl_seconds,
        description=description,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    record_event(
        "registration.created",
        customer.id,
        entry_id=entry.id,
        agent_type=agent_type,
        selectors=selectors,
        capabilities=capabilities,
        scopes=entry.scopes,
    )
    return entry


def lint_registration_entries(
    db: Session, customer: Customer
) -> list[dict]:
    """Find registration entries that would collide at equal match specificity.

    Two entries conflict when they require the same number of selectors and a
    workload could attest the union of both selector sets, leaving
    :func:`_match_entry` with an ambiguous tie.
    """
    entries = list(
        db.scalars(
            select(RegistrationEntry).where(RegistrationEntry.customer_id == customer.id)
        ).all()
    )
    conflicts: list[dict] = []
    seen_pairs: set[tuple[str, str]] = set()

    for i, left in enumerate(entries):
        left_selectors = set(left.selectors or [])
        left_count = len(left_selectors)
        for right in entries[i + 1:]:
            right_selectors = set(right.selectors or [])
            if len(right_selectors) != left_count:
                continue
            pair = tuple(sorted((left.id, right.id)))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            conflicts.append(
                {
                    "selector_count": left_count,
                    "entry_ids": [left.id, right.id],
                    "agent_types": [left.agent_type, right.agent_type],
                    "selectors": [
                        sorted(left_selectors),
                        sorted(right_selectors),
                    ],
                    "witness_selectors": sorted(left_selectors | right_selectors),
                    "reason": (
                        "equal-specificity registration entries can both match the "
                        "same attested selector set"
                    ),
                }
            )

    return conflicts


def _match_entry(
    db: Session, customer: Customer, presented: set[str]
) -> RegistrationEntry | None:
    """Return the most-specific entry whose required selectors are all present.

    SPIRE would issue an SVID for *every* matching entry; we mint a single
    credential, so we pick the entry that requires the most selectors (the most
    specific match), breaking ties by earliest creation for determinism.
    """
    entries = db.scalars(
        select(RegistrationEntry).where(RegistrationEntry.customer_id == customer.id)
    ).all()
    matches = [e for e in entries if set(e.selectors or []) <= presented]
    if not matches:
        return None
    matches.sort(key=lambda e: (-len(e.selectors or []), e.created_at))
    best = matches[0]
    best_specificity = len(best.selectors or [])
    ambiguous = [
        entry for entry in matches
        if len(entry.selectors or []) == best_specificity
    ]
    if len(ambiguous) > 1:
        raise AttestationDeniedError(
            "Attestation matched multiple registration entries with equal specificity.",
            suggestion=(
                "Tighten or de-duplicate your registration entries so one proven "
                "selector set maps to exactly one identity."
            ),
            matching_entry_ids=[entry.id for entry in ambiguous],
            presented_selectors=sorted(presented),
        )
    return best


def attest(
    db: Session,
    customer: Customer,
    *,
    attestation_document: str,
    ttl_seconds: int | None = None,
) -> tuple[Agent, str]:
    """Prove an identity from verified evidence and mint a JWT-SVID.

    Node attestation verifies the signed document; workload attestation derives
    selectors from it; the union must match a pre-registered entry, which
    dictates the ``agent_type`` and ``scopes`` (never the caller). No match ->
    :class:`AttestationDeniedError`.
    """
    node_payload, node_selectors = verify_node_attestation(db, customer, attestation_document)
    exp_claim = node_payload.get("exp")
    if not isinstance(exp_claim, (int, float)):
        raise AttestationDeniedError(
            "Attestation document is missing a valid exp claim.",
            suggestion="Node attestation documents must be short-lived JWTs with exp and jti.",
        )
    record_attestation_use(
        db,
        customer.id,
        jti=str(node_payload["jti"]),
        expires_at=datetime.fromtimestamp(int(exp_claim), tz=timezone.utc).replace(tzinfo=None),
    )
    workload = node_payload.get("workload") or {}
    workload_selectors = derive_workload_selectors(workload)
    presented = set(node_selectors) | set(workload_selectors)

    entry = _match_entry(db, customer, presented)
    if entry is None:
        raise AttestationDeniedError(
            "Attestation succeeded but no registration entry matches the proven selectors.",
            suggestion=(
                "The workload's environment is not pre-approved for any agent type. "
                "Register an entry at POST /v1/registration-entries whose selectors are "
                "a subset of what was attested."
            ),
            presented_selectors=sorted(presented),
        )

    resolved_owner = entry.owner or "unknown"
    resolved_ttl = ttl_seconds if ttl_seconds is not None else entry.ttl_seconds
    # Record only the selectors the entry actually keyed on (the proof that
    # mattered), not every incidental selector the workload carried.
    matched_selectors = sorted(set(entry.selectors or []))
    # The workload may carry its SPIFFE public key in the verified evidence so
    # the capability token can be bound to it (proof-of-possession).
    workload_pubkey_pem = workload.get("workload_pubkey_pem")
    if not workload_pubkey_pem:
        raise AttestationDeniedError(
            "Attestation evidence must include the workload SPIFFE public key.",
            suggestion=(
                "Present workload_pubkey_pem in the attestation document workload block "
                "so the minted credential is sender-constrained."
            ),
        )

    return issue_credential(
        db,
        customer,
        agent_type=entry.agent_type,
        owner=resolved_owner,
        capabilities=list(entry.capabilities or []),
        scopes=list(entry.scopes or []),
        ttl_seconds=resolved_ttl,
        selectors=matched_selectors,
        workload_pubkey_pem=workload_pubkey_pem,
    )


def _decode(token: str, public_pem: str, customer_id: str) -> dict:
    settings = get_settings()
    return jwt.decode(
        token,
        public_pem,
        algorithms=[JWT_ALGORITHM],
        audience=customer_id,
        issuer=settings.jwt_issuer,
        options={"require": ["exp", "iat", "sub", "jti"]},
    )


def validate_token(
    db: Session,
    customer: Customer,
    token: str,
    *,
    pop: cap_service.PopProof | None = None,
) -> tuple[dict, Agent]:
    """Verify signature + expiry + agent status. Returns ``(claims, agent)``.

    Raises an :class:`AgentAuthError` subclass on any failure.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise InvalidTokenError(
            "Token is malformed and could not be parsed.",
            suggestion="Ensure you are passing the full JWT string returned by identify().",
        ) from exc

    kid = header.get("kid")
    key = db.get(SigningKey, kid) if kid else None
    if key is None or key.customer_id != customer.id:
        raise InvalidTokenError(
            "Token was not signed by a key belonging to this customer.",
            suggestion="Check that you're validating with the same API key that issued the token.",
        )
    if header.get("alg") != JWT_ALGORITHM or key.algorithm != JWT_ALGORITHM:
        raise InvalidTokenError(
            "Token uses an unsupported signing algorithm.",
            suggestion="Mint a fresh Ed25519-signed credential with identify().",
        )
    if header.get("typ") != JWT_TYPE:
        raise InvalidTokenError(
            "Token type is not an AgentAuth SVID.",
            suggestion="Pass the credential JWT returned by identify(), not another JWT type.",
        )

    try:
        claims = _decode(token, key.public_pem, customer.id)
    except jwt.ExpiredSignatureError as exc:
        # Best-effort: mark the agent expired so the dashboard reflects reality.
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            agent = db.get(Agent, unverified.get("agent_id"))
            if agent is not None and agent.status == "active":
                agent.status = "expired"
                db.add(agent)
                db.commit()
        except Exception:  # noqa: BLE001 - never let bookkeeping mask the error
            pass
        raise TokenExpiredError(
            "Token has expired.",
            suggestion="Call identify() again to mint a fresh credential.",
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise InvalidTokenError(
            f"Token failed validation: {exc}",
            suggestion="The token may be corrupted or issued for a different service.",
        ) from exc

    agent = db.get(Agent, claims.get("agent_id"))
    if agent is None:
        raise InvalidTokenError(
            "Token references an unknown agent.",
            suggestion="The agent record may have been deleted; mint a new credential.",
        )
    if agent.status == "revoked":
        raise AgentRevokedError(
            "This agent's credential has been revoked.",
            suggestion="Mint a new credential; the old one can no longer be used.",
            agent_id=agent.id,
        )

    expected_keyhash = (
        (claims.get("cnf") or {}).get("jkt")
        or agent.bound_keyhash
    )
    if not expected_keyhash:
        raise InvalidTokenError(
            "Token is not sender-constrained to a workload key.",
            suggestion=(
                "Mint credentials via identify() with workload_pubkey_pem in the "
                "attestation evidence."
            ),
        )
    if pop is None:
        raise InvalidTokenError(
            "Sender-constrained token requires proof of possession.",
            suggestion=(
                "Fetch a fresh challenge from POST /v1/challenge and sign a "
                "request-bound proof for POST /v1/validate with the workload key "
                "bound to the token."
            ),
        )
    if not cap_service.verify_request_pop(
        pop.pubkey_pem,
        expected_keyhash,
        pop.challenge,
        htm=pop.htm,
        htu=pop.htu,
        ath=pop.ath,
        iat=pop.iat,
        jti=pop.jti,
        signature_b64=pop.signature_b64,
        operation=("jwt", "validate"),
        expected_htm="POST",
        expected_htu="/v1/validate",
        expected_ath=cap_service.token_hash(token),
    ):
        raise InvalidTokenError(
            "Proof of possession for this token is invalid.",
            suggestion=(
                "Sign the server challenge with the workload private key that "
                "matches the token's bound public key."
            ),
        )
    return claims, agent


def revoke_agent(db: Session, customer: Customer, agent_id: str) -> Agent | None:
    """Revoke an agent's credential so it can no longer validate."""
    agent = db.get(Agent, agent_id)
    if agent is None or agent.customer_id != customer.id:
        return None

    agent.status = "revoked"
    db.add(agent)
    revoked_biscuit_ids: list[str] = []
    if agent.biscuit and agent.biscuit_kid:
        root = db.get(BiscuitRootKey, agent.biscuit_kid)
        if root is not None:
            revoked_biscuit_ids = cap_service.revoke_biscuit_ids(
                db,
                customer.id,
                agent.biscuit,
                root.public_hex,
                agent_id=agent.id,
                reason="agent credential revoked",
            )
    db.commit()
    db.refresh(agent)

    record_event("identity.revoked", customer.id, agent_id=agent_id)
    if revoked_biscuit_ids:
        record_event(
            "capability.revoked",
            customer.id,
            agent_id=agent_id,
            revocation_ids=revoked_biscuit_ids,
            reason="agent credential revoked",
        )
    return agent


# --------------------------------------------------------------------------- #
# Capability authorization (server-side path). The fully-offline path lives in
# the SDK; this endpoint backs the dashboard, non-Python clients, and layers in
# revocation -- which an offline verifier (holding only the token) cannot see.
# --------------------------------------------------------------------------- #
def _customer_root_public_hexes(db: Session, customer_id: str) -> list[str]:
    keys = db.scalars(
        select(BiscuitRootKey).where(BiscuitRootKey.customer_id == customer_id)
    ).all()
    # Try the active key first for the common case.
    return [k.public_hex for k in sorted(keys, key=lambda k: k.status != "active")]


def verify_capability(
    db: Session,
    customer: Customer,
    *,
    token_b64: str,
    operation: tuple[str, str],
    pop: cap_service.PopProof | None = None,
    expected_htm: str | None = None,
    expected_htu: str | None = None,
) -> dict:
    """Authorize ``operation`` against a capability token for this customer.

    Verifies the token against the customer's root keys (active or retired),
    checks the agent has not been revoked, then runs the offline authorizer.
    Returns ``{"allowed": bool, "reason": str}``.
    """
    public_hexes = _customer_root_public_hexes(db, customer.id)
    if not public_hexes:
        raise BiscuitError(
            "This customer has no Biscuit root key; no capability token could have been issued.",
            suggestion="Issue a credential with capabilities first (POST /v1/identify).",
        )

    last_error: BiscuitError | None = None
    for public_hex in public_hexes:
        try:
            # Revocation check: the token names its agent; a revoked agent's
            # capabilities are dead even if the token is cryptographically valid.
            agent_id = cap_service.read_agent_id(token_b64, public_hex)
            if cap_service.token_has_revocation(db, customer.id, token_b64, public_hex):
                return {"allowed": False, "reason": "capability token has been revoked"}
            if agent_id:
                agent = db.get(Agent, agent_id)
                if agent is not None and agent.status == "revoked":
                    return {"allowed": False, "reason": "agent credential has been revoked"}
            return cap_service.authorize_biscuit(
                token_b64=token_b64,
                root_public_hex=public_hex,
                operation=operation,
                pop=pop,
                expected_htm=expected_htm,
                expected_htu=expected_htu,
            )
        except BiscuitError as exc:  # wrong key -- try the next one
            last_error = exc
            continue
    raise last_error  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# JWKS (public keys) -- lets downstream services verify tokens offline.
# --------------------------------------------------------------------------- #
def build_jwks(db: Session, customer_id: str) -> dict:
    keys = db.scalars(
        select(SigningKey).where(
            SigningKey.customer_id == customer_id,
            SigningKey.algorithm == JWT_ALGORITHM,
        )
    ).all()
    jwk_list = []
    for k in keys:
        public_key = serialization.load_pem_public_key(k.public_pem.encode())
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            continue
        jwk = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(public_key))
        jwk.update({"kid": k.kid, "use": "sig", "alg": JWT_ALGORITHM})
        jwk_list.append(jwk)
    return {"keys": jwk_list}
