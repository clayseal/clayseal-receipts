"""Capability token (Biscuit) tests.

These exercise the full capability path over real HTTP + real Biscuit crypto:
fine-grained issuance, offline authorization (allow/deny/wildcard), proof-of-
possession (required, request-bound, forgery-resistant), offline attenuation
(narrowing + monotonicity), root-key rotation, and revocation.
"""
from __future__ import annotations

import time
import uuid

from agentauth.backend import capabilities as cap_service
from agentauth.backend.db import SessionLocal
from agentauth.backend.models import Agent, BiscuitRevocation, CapabilityChallenge

from tests.attest import (
    ROGUE_WORKLOAD_PRIVATE_PEM,
    WORKLOAD_PRIVATE_PEM,
    WORKLOAD_PUBLIC_PEM,
    register_and_identify,
)

DB_READ = [{"resource": "db", "action": "read"}]
DB_RW = [{"resource": "db", "action": "read"}, {"resource": "db", "action": "write"}]
DB_READ_WEB_ALL = [
    {"resource": "db", "action": "read"},
    {"resource": "web", "action": "*"},
]


def _issued_challenge(client, headers):
    resp = client.post("/v1/challenge", headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["challenge"]


def _pop(
    operation,
    *,
    token,
    challenge,
    priv=WORKLOAD_PRIVATE_PEM,
    pub=WORKLOAD_PUBLIC_PEM,
):
    """Build a proof-of-possession payload for the /v1/authorize endpoint."""
    keyhash = cap_service.keyhash_for_pem(pub)
    iat = int(time.time())
    jti = uuid.uuid4().hex
    return {
        "challenge": challenge,
        "signature": cap_service.sign_request_pop(
            priv,
            keyhash,
            challenge,
            htm="POST",
            htu="/v1/authorize",
            ath=cap_service.token_hash(token),
            iat=iat,
            jti=jti,
            operation=operation,
        ),
        "pubkey_pem": pub,
        "htm": "POST",
        "htu": "/v1/authorize",
        "ath": cap_service.token_hash(token),
        "iat": iat,
        "jti": jti,
    }


def _authorize(client, headers, token, resource, action, pop=None):
    body = {"token": token, "operation": {"resource": resource, "action": action}}
    if pop is not None:
        body["pop"] = pop
    return client.post("/v1/authorize", json=body, headers=headers)


# --------------------------------------------------------------------------- #
# Issuance
# --------------------------------------------------------------------------- #
def test_identify_returns_capabilities_and_biscuit(client, customer):
    resp = register_and_identify(
        client, customer["headers"], capabilities=DB_READ_WEB_ALL
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["capabilities"] == DB_READ_WEB_ALL
    # Derived scope mirror keeps legacy consumers working.
    assert data["scopes"] == ["db:read", "web:*"]
    assert data["biscuit"], "a capability token should be minted"
    assert data["biscuit_root_public_key"]
    assert data["bound_keyhash"] == cap_service.keyhash_for_pem(WORKLOAD_PUBLIC_PEM)

    with SessionLocal() as db:
        agent = db.get(Agent, data["agent_id"])
        assert agent is not None
        assert agent.biscuit_revocation_ids == cap_service.read_revocation_ids(
            data["biscuit"], data["biscuit_root_public_key"]
        )


def test_scopes_only_entry_derives_capabilities(client, customer):
    resp = register_and_identify(client, customer["headers"], scopes=["db:read"])
    data = resp.json()
    assert data["capabilities"] == [{"resource": "db", "action": "read"}]
    assert data["scopes"] == ["db:read"]
    assert data["biscuit"]


def test_identify_requires_workload_key_for_capabilities(client, customer):
    resp = register_and_identify(
        client, customer["headers"], capabilities=DB_READ, with_pubkey=False
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "attestation_denied"


# --------------------------------------------------------------------------- #
# Offline authorization via /v1/authorize
# --------------------------------------------------------------------------- #
def test_authorize_allows_granted_with_pop(client, customer):
    token = register_and_identify(
        client, customer["headers"], capabilities=DB_READ_WEB_ALL
    ).json()["biscuit"]
    challenge = _issued_challenge(client, customer["headers"])
    resp = _authorize(
        client,
        customer["headers"],
        token,
        "db",
        "read",
        _pop(("db", "read"), token=token, challenge=challenge),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["allowed"] is True


def test_authorize_denies_ungranted(client, customer):
    token = register_and_identify(
        client, customer["headers"], capabilities=DB_READ
    ).json()["biscuit"]
    challenge = _issued_challenge(client, customer["headers"])
    resp = _authorize(
        client,
        customer["headers"],
        token,
        "db",
        "write",
        _pop(("db", "write"), token=token, challenge=challenge),
    )
    assert resp.json()["allowed"] is False


def test_authorize_action_wildcard(client, customer):
    token = register_and_identify(
        client, customer["headers"], capabilities=DB_READ_WEB_ALL
    ).json()["biscuit"]
    challenge = _issued_challenge(client, customer["headers"])
    resp = _authorize(
        client,
        customer["headers"],
        token,
        "web",
        "post",
        _pop(("web", "post"), token=token, challenge=challenge),
    )
    assert resp.json()["allowed"] is True


def test_authorize_requires_proof_of_possession(client, customer):
    token = register_and_identify(
        client, customer["headers"], capabilities=DB_READ
    ).json()["biscuit"]
    resp = _authorize(client, customer["headers"], token, "db", "read")  # no pop
    body = resp.json()
    assert body["allowed"] is False
    assert "possession" in body["reason"].lower()


def test_authorize_forged_signature_denied(client, customer):
    token = register_and_identify(
        client, customer["headers"], capabilities=DB_READ
    ).json()["biscuit"]
    # Present the real (bound) public key but sign with a key we don't own.
    challenge = _issued_challenge(client, customer["headers"])
    forged = _pop(
        ("db", "read"),
        token=token,
        challenge=challenge,
        priv=ROGUE_WORKLOAD_PRIVATE_PEM,
    )
    resp = _authorize(client, customer["headers"], token, "db", "read", forged)
    assert resp.json()["allowed"] is False


def test_authorize_signature_is_operation_bound(client, customer):
    # Both actions are granted, so the only thing that can deny db:write is the
    # PoP being bound to db:read -- proving op-binding, not a missing grant.
    token = register_and_identify(
        client, customer["headers"], capabilities=DB_RW
    ).json()["biscuit"]
    pop_for_read = _pop(
        ("db", "read"),
        token=token,
        challenge=_issued_challenge(client, customer["headers"]),
    )
    resp = _authorize(client, customer["headers"], token, "db", "write", pop_for_read)
    assert resp.json()["allowed"] is False
    # Sanity: the same token authorizes db:write with a correctly-bound proof.
    ok = _authorize(
        client,
        customer["headers"],
        token,
        "db",
        "write",
        _pop(
            ("db", "write"),
            token=token,
            challenge=_issued_challenge(client, customer["headers"]),
        ),
    )
    assert ok.json()["allowed"] is True


# --------------------------------------------------------------------------- #
# Offline attenuation (no server involved in narrowing)
# --------------------------------------------------------------------------- #
def test_attenuation_narrows_rights(client, customer):
    cred = register_and_identify(
        client, customer["headers"], capabilities=DB_READ_WEB_ALL
    ).json()
    root_pub = cred["biscuit_root_public_key"]
    narrowed = cap_service.attenuate_biscuit(
        token_b64=cred["biscuit"], root_public_hex=root_pub, capabilities=DB_READ
    )
    # The narrowed token authorizes only db:read.
    assert _authorize(
        client,
        customer["headers"],
        narrowed,
        "db",
        "read",
        _pop(
            ("db", "read"),
            token=narrowed,
            challenge=_issued_challenge(client, customer["headers"]),
        ),
    ).json()["allowed"]
    assert not _authorize(
        client,
        customer["headers"],
        narrowed,
        "web",
        "post",
        _pop(
            ("web", "post"),
            token=narrowed,
            challenge=_issued_challenge(client, customer["headers"]),
        ),
    ).json()["allowed"]


def test_attenuated_token_cannot_regain_rights(client, customer):
    cred = register_and_identify(
        client, customer["headers"], capabilities=DB_READ_WEB_ALL
    ).json()
    root_pub = cred["biscuit_root_public_key"]
    narrowed = cap_service.attenuate_biscuit(
        token_b64=cred["biscuit"], root_public_hex=root_pub, capabilities=DB_READ
    )
    # Attempt to widen back to web:* by appending another block.
    regained = cap_service.attenuate_biscuit(
        token_b64=narrowed, root_public_hex=root_pub,
        capabilities=[{"resource": "web", "action": "post"}],
    )
    resp = _authorize(
        client,
        customer["headers"],
        regained,
        "web",
        "post",
        _pop(
            ("web", "post"),
            token=regained,
            challenge=_issued_challenge(client, customer["headers"]),
        ),
    )
    assert resp.json()["allowed"] is False


# --------------------------------------------------------------------------- #
# Root keys + rotation
# --------------------------------------------------------------------------- #
def test_biscuit_keys_endpoint(client, customer):
    register_and_identify(client, customer["headers"], capabilities=DB_READ)
    resp = client.get("/v1/biscuit-keys.json", headers=customer["headers"])
    assert resp.status_code == 200
    keys = resp.json()["keys"]
    assert keys and keys[0]["alg"] == "ed25519"
    assert any(k["status"] == "active" for k in keys)


def test_challenge_endpoint(client, customer):
    resp = client.post("/v1/challenge", headers=customer["headers"])
    assert resp.status_code == 200
    assert len(resp.json()["challenge"]) > 16


def test_root_key_rotation_keeps_old_tokens_valid(client, customer):
    headers = customer["headers"]
    token = register_and_identify(client, headers, capabilities=DB_READ).json()["biscuit"]
    # Rotate the Biscuit root key.
    rot = client.post("/v1/biscuit-keys/rotate", headers=headers)
    assert rot.status_code == 200
    # The server tries retired keys too, so the pre-rotation token still authorizes.
    resp = _authorize(
        client,
        headers,
        token,
        "db",
        "read",
        _pop(("db", "read"), token=token, challenge=_issued_challenge(client, headers)),
    )
    assert resp.json()["allowed"] is True


# --------------------------------------------------------------------------- #
# Revocation interaction (server-side path only)
# --------------------------------------------------------------------------- #
def test_revoked_agent_capability_denied(client, customer):
    headers = customer["headers"]
    cred = register_and_identify(client, headers, capabilities=DB_READ).json()
    token = cred["biscuit"]
    # Works before revocation.
    assert _authorize(
        client,
        headers,
        token,
        "db",
        "read",
        _pop(("db", "read"), token=token, challenge=_issued_challenge(client, headers)),
    ).json()["allowed"]
    # Revoke and confirm the capability is now dead even with valid PoP.
    client.post(f"/v1/agents/{cred['agent_id']}/revoke", headers=headers)
    resp = _authorize(
        client,
        headers,
        token,
        "db",
        "read",
        _pop(("db", "read"), token=token, challenge=_issued_challenge(client, headers)),
    )
    body = resp.json()
    assert body["allowed"] is False
    assert "revoked" in body["reason"].lower()


def test_biscuit_revocation_id_denies_attenuated_descendant(client, customer):
    headers = customer["headers"]
    cred = register_and_identify(
        client, headers, capabilities=DB_READ_WEB_ALL
    ).json()
    root_pub = cred["biscuit_root_public_key"]
    narrowed = cap_service.attenuate_biscuit(
        token_b64=cred["biscuit"], root_public_hex=root_pub, capabilities=DB_READ
    )

    revoke = client.post(f"/v1/agents/{cred['agent_id']}/revoke", headers=headers)
    assert revoke.status_code == 200
    with SessionLocal() as db:
        revocations = db.query(BiscuitRevocation).filter_by(agent_id=cred["agent_id"]).all()
        assert revocations
        # Prove the deny-list, not just the agent status check, is doing work.
        agent = db.get(Agent, cred["agent_id"])
        agent.status = "active"
        db.add(agent)
        db.commit()

    resp = _authorize(
        client,
        headers,
        narrowed,
        "db",
        "read",
        _pop(("db", "read"), token=narrowed, challenge=_issued_challenge(client, headers)),
    )
    body = resp.json()
    assert body["allowed"] is False
    assert "capability token has been revoked" in body["reason"].lower()


def test_authorize_rejects_replayed_server_challenge(client, customer):
    headers = customer["headers"]
    token = register_and_identify(client, headers, capabilities=DB_READ).json()["biscuit"]
    challenge = _issued_challenge(client, headers)
    pop = _pop(("db", "read"), token=token, challenge=challenge)

    first = _authorize(client, headers, token, "db", "read", pop)
    assert first.json()["allowed"] is True

    replay = _authorize(client, headers, token, "db", "read", pop)
    body = replay.json()
    assert body["allowed"] is False
    assert "already been used" in body["reason"].lower()


def test_authorize_rejects_expired_server_challenge(client, customer):
    headers = customer["headers"]
    challenge = _issued_challenge(client, headers)
    with SessionLocal() as db:
        record = db.query(CapabilityChallenge).filter_by(challenge=challenge).one()
        record.expires_at = record.issued_at
        db.add(record)
        db.commit()

    token = register_and_identify(client, headers, capabilities=DB_READ).json()["biscuit"]
    resp = _authorize(
        client,
        headers,
        token,
        "db",
        "read",
        _pop(("db", "read"), token=token, challenge=challenge),
    )
    body = resp.json()
    assert body["allowed"] is False
    assert "expired" in body["reason"].lower()
