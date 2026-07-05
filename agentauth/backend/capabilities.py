"""Capability tokens: Biscuit minting, attenuation, and offline authorization.

Where the JWT-SVID answers *who* an agent is, the Biscuit answers *what it may
do*. A capability is a fine-grained ``(resource, action)`` right expressed as a
Datalog fact in the token's authority block. The token is:

* **Rooted** in a per-customer Ed25519 keypair (:class:`models.BiscuitRootKey`),
  so anyone holding the customer's published root public key can verify and
  authorize it **offline** -- no call back to this service.
* **Bound** to the workload's Ed25519 SPIFFE keypair: the authority block carries
  ``bound_key(<jwk-thumbprint>)`` and gates every decision on
  ``check if valid_pop(true)``. The ``valid_pop`` fact is only added by an
  authorizer that has *cryptographically* verified a fresh request-bound
  signature from the workload's private key (proof-of-possession). A stolen token
  is inert.
* **Attenuable**: a holder can append a caveat block narrowing the rights (and
  shortening the lifetime) entirely offline. Biscuit's block scoping makes this
  monotonic -- an appended block can *restrict* but never *re-grant*, so a
  narrowed token can't claw back a right its parent dropped.

Datalog reference (the strings below are the contract; the SDK mirrors them in
``agentauth/_capabilities.py`` and a parity test keeps the two in lockstep):

    authority block   capability("db", "read"); ... bound_key("<hash>");
                      check if valid_pop(true);
                      check if time($t), $t <= <expiry>;
    attenuation       allowed_cap("db","read"); ...
                      check if operation($r,$a), allowed_cap($r,$a);
    authorizer        operation("db","read");
                      allow if capability($r,$a), operation($r,$a);
                      allow if capability($r,"*"), operation($r,$_);
                      deny if true;
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from biscuit_auth import (
    Algorithm,
    Authorizer,  # noqa: F401  (re-exported for type clarity)
    AuthorizerBuilder,
    Biscuit,
    BiscuitBuilder,
    BlockBuilder,
    Check,
    Fact,
    KeyPair,
    PrivateKey,
    PublicKey,
    Rule,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from agentauth.workload_keys import (
    keyhash_for_pem,
    sign_request_pop,
    token_hash,
    verify_request_pop,
)

from agentauth.biscuit_scope import (
    FILE_RESOURCE,
    evaluate_path_scope,
    path_patterns_from_biscuit_blocks,
)

from .audit import record_event
from .biscuit_keys import (
    decrypt_private_hex,
    encrypt_private_hex,
    maybe_reencrypt_biscuit_root_key,
)
from .errors import BiscuitError, RegistrationEntryError
from .models import BiscuitRevocation, BiscuitRootKey, CapabilityChallenge, new_id, utcnow

__all__ = [
    "PopProof",
    "authorize_biscuit",
    "keyhash_for_pem",
    "read_revocation_ids",
    "revoke_biscuit_ids",
    "token_has_revocation",
    "sign_request_pop",
    "token_hash",
    "verify_request_pop",
]

# Authorizer policy: state the requested operation, allow if a surviving
# capability covers it (exact or action-wildcard), else deny.
_AUTHORIZER_POLICY = """
    operation({resource}, {action});
    allow if capability($r, $a), operation($r, $a);
    allow if capability($r, "*"), operation($r, $_);
    deny if true;
"""


# --------------------------------------------------------------------------- #
# Capability <-> scope conversion (capabilities are the source of truth; the
# flat "resource:action" scope list is a derived back-compat mirror).
# --------------------------------------------------------------------------- #
def normalize_capabilities(capabilities: list[dict] | None) -> list[dict]:
    """Coerce raw capability dicts to ``{resource, action}`` (constraints rejected)."""
    out: list[dict] = []
    for cap in capabilities or []:
        resource = str(cap.get("resource", "")).strip()
        action = str(cap.get("action", "")).strip()
        if not resource or not action:
            continue
        entry: dict = {"resource": resource, "action": action}
        constraints = cap.get("constraints")
        if constraints:
            raise RegistrationEntryError(
                "Capability constraints are not supported yet.",
                suggestion=(
                    "Remove 'constraints' from capability entries for now, or wait "
                    "until constraint-aware authorization is implemented."
                ),
                capability=entry,
            )
        out.append(entry)
    return out


def capabilities_to_scopes(capabilities: list[dict] | None) -> list[str]:
    """Derive the flat ``"resource:action"`` scope list for back-compat."""
    return [f"{c['resource']}:{c['action']}" for c in normalize_capabilities(capabilities)]


def scopes_to_capabilities(scopes: list[str] | None) -> list[dict]:
    """Parse legacy ``"resource:action"`` scope strings into capabilities.

    A bare scope with no colon (e.g. ``"admin"``) becomes ``(admin, *)``.
    """
    caps: list[dict] = []
    for scope in scopes or []:
        scope = str(scope).strip()
        if not scope:
            continue
        resource, sep, action = scope.partition(":")
        caps.append({"resource": resource, "action": action if sep else "*"})
    return caps


def reconcile_capabilities(
    capabilities: list[dict] | None, scopes: list[str] | None
) -> tuple[list[dict], list[str]]:
    """Return a consistent ``(capabilities, scopes)`` pair.

    Capabilities win when present; otherwise they're derived from scopes. The
    scopes returned are always the canonical mirror of the capabilities.
    """
    caps = normalize_capabilities(capabilities)
    if not caps and scopes:
        caps = scopes_to_capabilities(scopes)
    return caps, capabilities_to_scopes(caps)


# --------------------------------------------------------------------------- #
# Root key management (mirrors identity.get_active_key / rotate_key).
# --------------------------------------------------------------------------- #
def _keypair() -> tuple[str, str]:
    kp = KeyPair()
    return kp.private_key.to_bytes().hex(), kp.public_key.to_bytes().hex()


def create_root_key(db: Session, customer_id: str) -> BiscuitRootKey:
    private_hex, public_hex = _keypair()
    key = BiscuitRootKey(
        kid=new_id(),
        customer_id=customer_id,
        private_hex=encrypt_private_hex(private_hex),
        public_hex=public_hex,
        algorithm="ed25519",
        status="active",
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return key


def get_active_root_key(db: Session, customer_id: str) -> BiscuitRootKey:
    """Return the customer's active Biscuit root key, creating one if needed."""
    key = db.scalar(
        select(BiscuitRootKey).where(
            BiscuitRootKey.customer_id == customer_id,
            BiscuitRootKey.status == "active",
        )
    )
    if key is None:
        key = create_root_key(db, customer_id)
    maybe_reencrypt_biscuit_root_key(db, key)
    return key


def resolve_root_private_hex(key: BiscuitRootKey) -> str:
    """Return the decrypted Ed25519 private key bytes as hex."""
    return decrypt_private_hex(key.private_hex)


def rotate_root_key(db: Session, customer_id: str) -> BiscuitRootKey:
    """Retire the active root key and mint a new one.

    Retired keys stay in the DB so already-issued capability tokens still verify
    until they expire; only new tokens use the new key.
    """
    current = db.scalar(
        select(BiscuitRootKey).where(
            BiscuitRootKey.customer_id == customer_id,
            BiscuitRootKey.status == "active",
        )
    )
    if current is not None:
        current.status = "retired"
        current.retired_at = utcnow()
        db.add(current)
        db.commit()
    new_key = create_root_key(db, customer_id)
    record_event(
        "capability_root.rotated",
        customer_id,
        new_kid=new_key.kid,
        retired_kid=current.kid if current else None,
    )
    return new_key


def _private_key(private_hex: str) -> PrivateKey:
    return PrivateKey.from_bytes(bytes.fromhex(private_hex), Algorithm.Ed25519)


def _public_key(public_hex: str) -> PublicKey:
    return PublicKey.from_bytes(bytes.fromhex(public_hex), Algorithm.Ed25519)


# --------------------------------------------------------------------------- #
# Proof-of-possession: the workload signs a challenge with its SPIFFE key; the
# verifier checks that signature *outside* Datalog and feeds the boolean in.
# --------------------------------------------------------------------------- #
@dataclass
class PopProof:
    """A request-bound proof-of-possession from the workload key."""

    challenge: str
    signature_b64: str
    pubkey_pem: str
    htm: str
    htu: str
    ath: str
    iat: int
    jti: str


def issue_challenge() -> str:
    """A fresh nonce for a proof-of-possession exchange."""
    return secrets.token_urlsafe(32)


SERVER_CHALLENGE_TTL_SECONDS = 5 * 60


def issue_server_challenge(db: Session, customer_id: str) -> str:
    """Mint and persist a one-time challenge for the server auth path."""
    challenge = issue_challenge()
    now = utcnow()
    record = CapabilityChallenge(
        id=new_id(),
        customer_id=customer_id,
        challenge=challenge,
        issued_at=now,
        expires_at=now + timedelta(seconds=SERVER_CHALLENGE_TTL_SECONDS),
    )
    db.add(record)
    db.commit()
    return challenge


def consume_server_challenge(db: Session, customer_id: str, challenge: str) -> str | None:
    """Consume a server-issued challenge or return a denial reason."""
    record = db.scalar(
        select(CapabilityChallenge).where(
            CapabilityChallenge.customer_id == customer_id,
            CapabilityChallenge.challenge == challenge,
        )
    )
    if record is None:
        return "proof-of-possession challenge is unknown or was not issued by this server"
    if record.used_at is not None:
        return "proof-of-possession challenge has already been used"
    now = utcnow()
    if record.expires_at <= now:
        return "proof-of-possession challenge has expired"
    record.used_at = now
    db.add(record)
    db.commit()
    return None


# --------------------------------------------------------------------------- #
# Mint / attenuate / authorize
# --------------------------------------------------------------------------- #
def _to_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def mint_biscuit(
    *,
    root_private_hex: str,
    spiffe_id: str,
    agent_id: str,
    capabilities: list[dict],
    bound_keyhash: str,
    expires_at: datetime,
) -> str:
    """Build and serialize a capability token. Returns base64.

    The authority block grants each capability and pins the PoP + expiry gates.
    """
    builder = BiscuitBuilder("")
    for cap in normalize_capabilities(capabilities):
        builder.add_fact(
            Fact("capability({r}, {a})", {"r": cap["resource"], "a": cap["action"]})
        )
    builder.add_fact(Fact("spiffe_id({s})", {"s": spiffe_id}))
    builder.add_fact(Fact("agent_id({a})", {"a": agent_id}))
    builder.add_fact(Fact("bound_key({k})", {"k": bound_keyhash}))
    builder.add_check(Check("check if valid_pop(true)"))
    builder.add_check(
        Check("check if time($t), $t <= {exp}", {"exp": _to_aware(expires_at)})
    )
    token = builder.build(_private_key(root_private_hex))
    return token.to_base64()


def read_path_scope(token_b64: str, root_public_hex: str) -> tuple[list[str], list[str]]:
    token = _parse(token_b64, root_public_hex)
    return path_patterns_from_biscuit_blocks(token)


def attenuate_biscuit(
    *,
    token_b64: str,
    root_public_hex: str,
    capabilities: list[dict] | None = None,
    path_patterns: list[str] | None = None,
    denied_paths: list[str] | None = None,
    expires_at: datetime | None = None,
) -> str:
    """Append an offline caveat block narrowing rights and/or shortening life.

    ``capabilities`` restricts the operations the token may authorize to that
    subset (exact resource+action pairs). ``path_patterns`` / ``denied_paths``
    add dynamic file-scope facts (SM-7). ``expires_at`` adds a tighter expiry.
    Returns the new base64 token. Cannot widen anything -- Biscuit blocks only
    restrict.
    """
    token = _parse(token_b64, root_public_hex)
    block = BlockBuilder("")
    caps = normalize_capabilities(capabilities)
    if caps:
        for cap in caps:
            block.add_fact(
                Fact(
                    "allowed_cap({r}, {a})",
                    {"r": cap["resource"], "a": cap["action"]},
                )
            )
        block.add_check(Check("check if operation($r, $a), allowed_cap($r, $a)"))
    for pattern in path_patterns or []:
        block.add_fact(Fact("allowed_path({p})", {"p": str(pattern)}))
    for pattern in denied_paths or []:
        block.add_fact(Fact("denied_path({p})", {"p": str(pattern)}))
    if expires_at is not None:
        block.add_check(
            Check("check if time($t), $t <= {exp}", {"exp": _to_aware(expires_at)})
        )
    return token.append(block).to_base64()


def _parse(token_b64: str, root_public_hex: str) -> Biscuit:
    try:
        return Biscuit.from_base64(token_b64, _public_key(root_public_hex))
    except Exception as exc:  # noqa: BLE001
        raise BiscuitError(
            "Capability token is malformed or not signed by this customer's root key.",
            suggestion=(
                "Pass the biscuit returned by identify() and verify it against the "
                "customer's published root key from GET /v1/biscuit-keys.json."
            ),
        ) from exc


def read_bound_keys(token_b64: str, root_public_hex: str) -> list[str]:
    """Return the ``bound_key`` hashes declared in the token's authority block."""
    token = _parse(token_b64, root_public_hex)
    facts = AuthorizerBuilder("").build(token).query(Rule("k($k) <- bound_key($k)"))
    return [f.terms[0] for f in facts]


def read_agent_id(token_b64: str, root_public_hex: str) -> str | None:
    """Return the ``agent_id`` declared in the token's authority block, if any."""
    token = _parse(token_b64, root_public_hex)
    facts = AuthorizerBuilder("").build(token).query(Rule("a($a) <- agent_id($a)"))
    return facts[0].terms[0] if facts else None


def read_revocation_ids(token_b64: str, root_public_hex: str) -> list[str]:
    """Return Biscuit revocation IDs carried by the token's blocks."""
    token = _parse(token_b64, root_public_hex)
    return list(token.revocation_ids)


def token_has_revocation(
    db: Session, customer_id: str, token_b64: str, root_public_hex: str
) -> bool:
    """True if any block revocation ID for ``token_b64`` is deny-listed."""
    ids = read_revocation_ids(token_b64, root_public_hex)
    if not ids:
        return False
    revoked = db.scalar(
        select(BiscuitRevocation.id).where(
            BiscuitRevocation.customer_id == customer_id,
            BiscuitRevocation.revocation_id.in_(ids),
        )
    )
    return revoked is not None


def revoke_biscuit_ids(
    db: Session,
    customer_id: str,
    token_b64: str,
    root_public_hex: str,
    *,
    agent_id: str | None = None,
    reason: str = "",
) -> list[str]:
    """Deny-list every revocation ID carried by a Biscuit token."""
    ids = read_revocation_ids(token_b64, root_public_hex)
    inserted: list[str] = []
    for revocation_id in ids:
        exists = db.scalar(
            select(BiscuitRevocation.id).where(
                BiscuitRevocation.customer_id == customer_id,
                BiscuitRevocation.revocation_id == revocation_id,
            )
        )
        if exists is not None:
            continue
        db.add(
            BiscuitRevocation(
                customer_id=customer_id,
                revocation_id=revocation_id,
                agent_id=agent_id,
                reason=reason,
            )
        )
        inserted.append(revocation_id)
    if inserted:
        db.flush()
    return ids


def authorize_biscuit(
    *,
    token_b64: str,
    root_public_hex: str,
    operation: tuple[str, str],
    pop: PopProof | None = None,
    expected_htm: str | None = None,
    expected_htu: str | None = None,
    file_path: str | None = None,
) -> dict:
    """Offline authorization decision for ``operation`` against the token.

    Verifies proof-of-possession (if presented) against the token's bound key,
    then runs the Datalog authorizer. When ``file_path`` is set (or resource is
    ``file``), enforces ``allowed_path`` / ``denied_path`` facts (SM-7).
    Returns ``{"allowed": bool, "reason": str}``.
    Raises :class:`BiscuitError` only when the token itself is unverifiable.
    """
    token = _parse(token_b64, root_public_hex)
    bound = read_bound_keys(token_b64, root_public_hex)

    if operation[0] == FILE_RESOURCE or file_path is not None:
        allowed_paths, denied_paths = read_path_scope(token_b64, root_public_hex)
        if allowed_paths or denied_paths:
            path_ok, path_reason = evaluate_path_scope(
                file_path,
                allowed_paths=allowed_paths,
                denied_paths=denied_paths,
            )
            if not path_ok:
                return {"allowed": False, "reason": path_reason}

    valid_pop = False
    pop_reason = "no proof-of-possession presented"
    if pop is not None:
        try:
            keyhash = keyhash_for_pem(pop.pubkey_pem)
        except ValueError:
            keyhash = ""
        if bound and keyhash not in bound:
            pop_reason = "presented key is not the token's bound workload key"
        elif verify_request_pop(
            pop.pubkey_pem,
            keyhash,
            pop.challenge,
            htm=pop.htm,
            htu=pop.htu,
            ath=pop.ath,
            iat=pop.iat,
            jti=pop.jti,
            signature_b64=pop.signature_b64,
            operation=operation,
            expected_htm=expected_htm,
            expected_htu=expected_htu,
            expected_ath=token_hash(token_b64),
        ):
            valid_pop = True
            pop_reason = "request-bound proof-of-possession verified"
        else:
            pop_reason = "request-bound proof-of-possession signature is invalid"

    builder = AuthorizerBuilder(
        _AUTHORIZER_POLICY, {"resource": operation[0], "action": operation[1]}
    )
    if valid_pop:
        builder.add_fact(Fact("valid_pop(true)"))
    builder.set_time()

    try:
        builder.build(token).authorize()
        return {"allowed": True, "reason": "authorized"}
    except Exception as exc:  # noqa: BLE001 - AuthorizationError + datalog failures
        reason = pop_reason if not valid_pop else str(exc)
        return {"allowed": False, "reason": reason}


def build_biscuit_jwks(db: Session, customer_id: str) -> dict:
    """Publish a customer's Biscuit root public keys for offline verifiers
    (the capability-token analogue of ``jwks.json``)."""
    keys = db.scalars(
        select(BiscuitRootKey).where(BiscuitRootKey.customer_id == customer_id)
    ).all()
    return {
        "keys": [
            {
                "kid": k.kid,
                "public_key": k.public_hex,
                "alg": "ed25519",
                "use": "cap",
                "status": k.status,
            }
            for k in keys
        ]
    }
