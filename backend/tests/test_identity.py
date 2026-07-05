"""Tests for the Identity Service (attestation-based).

Identity is now *attested*, not declared: a workload proves its environment with
a signed attestation document, and the matched registration entry — not the
caller — determines agent_type and scopes. See ``identity/identity.md``.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid
from datetime import timedelta

import jwt

from agentauth.backend import capabilities as cap_service
from agentauth.backend.audit import read_events, verify_event_log
from agentauth.backend.db import SessionLocal
from agentauth.backend.models import Customer
from tests.attest import (
    NODE_PUBLIC_PEM,
    ROGUE_PRIVATE_PEM,
    WORKLOAD_PRIVATE_PEM,
    WORKLOAD_PUBLIC_PEM,
    ensure_node_attestor,
    register_and_identify,
    register_entry,
    sign_attestation,
    workload_for,
)


def _validate_pop(client, headers, token):
    challenge = client.post("/v1/challenge", headers=headers).json()["challenge"]
    keyhash = cap_service.keyhash_for_pem(WORKLOAD_PUBLIC_PEM)
    iat = int(time.time())
    jti = uuid.uuid4().hex
    return {
        "challenge": challenge,
        "signature": cap_service.sign_request_pop(
            WORKLOAD_PRIVATE_PEM,
            keyhash,
            challenge,
            htm="POST",
            htu="/v1/validate",
            ath=cap_service.token_hash(token),
            iat=iat,
            jti=jti,
            operation=("jwt", "validate"),
        ),
        "pubkey_pem": WORKLOAD_PUBLIC_PEM,
        "htm": "POST",
        "htu": "/v1/validate",
        "ath": cap_service.token_hash(token),
        "iat": iat,
        "jti": jti,
    }


# --------------------------------------------------------------------------- #
# Customers / auth
# --------------------------------------------------------------------------- #
def test_create_customer_returns_api_key(client):
    resp = client.post("/v1/customers", json={"name": "Beta Corp"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["api_key"].startswith("aa_")
    assert data["customer_id"]

    with SessionLocal() as db:
        customer = db.get(Customer, data["customer_id"])
        assert customer is not None
        assert customer.api_key != data["api_key"]
        assert customer.api_key_hash is not None


def test_identify_requires_api_key(client):
    resp = client.post("/v1/identify", json={"attestation_document": "x"}, headers={})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "invalid_api_key"


def test_identify_rejects_bad_api_key(client):
    resp = client.post(
        "/v1/identify",
        json={"attestation_document": "x"},
        headers={"X-API-Key": "aa_nope"},
    )
    assert resp.status_code == 401


def test_plaintext_api_key_row_is_migrated_on_successful_use(client):
    resp = client.post("/v1/customers", json={"name": "Legacy Corp"})
    assert resp.status_code == 201
    data = resp.json()

    with SessionLocal() as db:
        customer = db.get(Customer, data["customer_id"])
        assert customer is not None
        customer.api_key = data["api_key"]
        customer.api_key_hash = None
        db.add(customer)
        db.commit()

    resp = client.get("/v1/agents", headers={"X-API-Key": data["api_key"]})
    assert resp.status_code == 200, resp.text

    with SessionLocal() as db:
        customer = db.get(Customer, data["customer_id"])
        assert customer is not None
        assert customer.api_key != data["api_key"]
        assert customer.api_key_hash is not None


# --------------------------------------------------------------------------- #
# Admin: node attestors + registration entries
# --------------------------------------------------------------------------- #
def test_register_and_list_node_attestor(client, customer):
    h = customer["headers"]
    resp = client.post(
        "/v1/node-attestors",
        json={"type": "k8s_psat", "public_pem": NODE_PUBLIC_PEM, "description": "prod"},
        headers=h,
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["type"] == "k8s_psat"

    listing = client.get("/v1/node-attestors", headers=h).json()
    assert any(a["type"] == "k8s_psat" for a in listing)


def test_register_node_attestor_rejects_bad_type(client, customer):
    resp = client.post(
        "/v1/node-attestors",
        json={"type": "magic", "public_pem": NODE_PUBLIC_PEM},
        headers=customer["headers"],
    )
    assert resp.status_code == 422  # pattern-constrained by the schema


def test_register_node_attestor_rejects_invalid_pem(client, customer):
    resp = client.post(
        "/v1/node-attestors",
        json={
            "type": "k8s_psat",
            "public_pem": "-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----",
        },
        headers=customer["headers"],
    )
    assert resp.status_code == 400
    assert "public_pem" in resp.json()["error"]["message"].lower()


def test_register_node_attestor_rejects_fake_begin_marker(client, customer):
    resp = client.post(
        "/v1/node-attestors",
        json={
            "type": "k8s_psat",
            "public_pem": "-----BEGIN FAKE-----\nxxx\n-----END FAKE-----",
        },
        headers=customer["headers"],
    )
    assert resp.status_code == 400


def test_register_entry_requires_selectors(client, customer):
    resp = client.post(
        "/v1/registration-entries",
        json={"agent_type": "researcher", "selectors": [], "scopes": ["db:read"]},
        headers=customer["headers"],
    )
    assert resp.status_code == 422  # min_length=1


def test_register_and_list_entries(client, customer):
    h = customer["headers"]
    reg = register_entry(client, h, agent_type="finance", scopes=["pay:send"])
    assert reg.status_code == 201, reg.text
    listing = client.get("/v1/registration-entries", headers=h).json()
    assert any(e["agent_type"] == "finance" for e in listing)


# --------------------------------------------------------------------------- #
# Attestation -> issuance
# --------------------------------------------------------------------------- #
def test_attestation_issues_jwt_svid(client, customer):
    resp = register_and_identify(
        client, customer["headers"], scopes=["db:read", "web:search"]
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["agent_id"]
    assert data["scopes"] == ["db:read", "web:search"]
    assert data["spiffe_id"] == (
        f"spiffe://agentauth.io/customer/{customer['customer_id']}/agent/researcher"
    )

    # The credential is a JWT-SVID: three segments + a kid header.
    assert data["token"].count(".") == 2
    header = jwt.get_unverified_header(data["token"])
    assert header["alg"] == "EdDSA"
    assert header["typ"] == "agentauth-svid+jwt"
    assert header["kid"]


def test_jwt_svid_claims_are_correct(client, customer):
    data = register_and_identify(
        client, customer["headers"], scopes=["db:read", "web:search"]
    ).json()
    claims = jwt.decode(data["token"], options={"verify_signature": False})
    sid = f"spiffe://agentauth.io/customer/{customer['customer_id']}/agent/researcher"
    assert claims["sub"] == sid
    assert claims["spiffe_id"] == sid
    assert claims["agent_id"] == data["agent_id"]
    assert claims["agent_type"] == "researcher"
    assert claims["owner"] == "alice@acme.ai"
    assert claims["scope"] == ["db:read", "web:search"]
    assert claims["cnf"]["jkt"] == data["bound_keyhash"]
    assert claims["iss"] == "agentauth.io"  # trust domain
    assert claims["aud"] == customer["customer_id"]


def test_workload_binding_uses_jwk_thumbprint(client, customer):
    data = register_and_identify(client, customer["headers"], scopes=["db:read"]).json()
    assert data["bound_keyhash"] == cap_service.keyhash_for_pem(WORKLOAD_PUBLIC_PEM)
    assert len(data["bound_keyhash"]) == 43
    assert "=" not in data["bound_keyhash"]


def test_scopes_and_type_come_from_entry_not_caller(client, customer):
    """The workload cannot self-declare its identity; the entry dictates it."""
    data = register_and_identify(
        client, customer["headers"], agent_type="finance", scopes=["pay:send"]
    ).json()
    assert data["agent_type"] == "finance"
    assert data["scopes"] == ["pay:send"]


def test_ambiguous_registration_entries_are_denied(client, customer):
    h = customer["headers"]
    ensure_node_attestor(client, h)
    selectors = [
        "k8s:ns:customer-acme",
        "k8s:sa:researcher",
        "k8s:pod-label:agentauth.io/agent-type:researcher",
    ]
    first = client.post(
        "/v1/registration-entries",
        json={"agent_type": "researcher", "selectors": selectors, "scopes": ["db:read"]},
        headers=h,
    )
    second = client.post(
        "/v1/registration-entries",
        json={"agent_type": "researcher-shadow", "selectors": selectors, "scopes": ["web:read"]},
        headers=h,
    )
    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text

    document = sign_attestation(
        workload=workload_for("researcher"), aud=customer["customer_id"]
    )
    resp = client.post("/v1/identify", json={"attestation_document": document}, headers=h)
    assert resp.status_code == 403
    body = resp.json()["error"]
    assert body["code"] == "attestation_denied"
    assert "multiple registration entries" in body["message"].lower()


def test_owner_comes_from_entry_not_identify_request(client, customer):
    h = customer["headers"]
    ensure_node_attestor(client, h)
    register_entry(
        client,
        h,
        agent_type="researcher",
        scopes=["db:read"],
        owner="entry-owner@acme.ai",
    )
    document = sign_attestation(
        workload=workload_for("researcher"), aud=customer["customer_id"]
    )
    resp = client.post(
        "/v1/identify",
        json={
            "attestation_document": document,
            "owner": "caller-owner@acme.ai",
        },
        headers=h,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["owner"] == "entry-owner@acme.ai"


# --------------------------------------------------------------------------- #
# Attestation denials (you must prove, not claim)
# --------------------------------------------------------------------------- #
def test_no_node_attestor_registered_is_denied(client, customer):
    h = customer["headers"]
    register_entry(client, h, agent_type="researcher", scopes=["db:read"])
    document = sign_attestation(workload=workload_for("researcher"))
    resp = client.post("/v1/identify", json={"attestation_document": document}, headers=h)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "attestation_denied"


def test_forged_unparseable_document_is_denied(client, customer):
    h = customer["headers"]
    ensure_node_attestor(client, h)
    register_entry(client, h, agent_type="researcher", scopes=["db:read"])
    resp = client.post(
        "/v1/identify", json={"attestation_document": "not-a-jwt"}, headers=h
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "attestation_denied"


def test_document_signed_by_unregistered_key_is_denied(client, customer):
    """A valid-looking document signed by a key we don't trust proves nothing."""
    h = customer["headers"]
    ensure_node_attestor(client, h)
    register_entry(client, h, agent_type="researcher", scopes=["db:read"])
    document = sign_attestation(
        workload=workload_for("researcher"),
        key_pem=ROGUE_PRIVATE_PEM,
        aud=customer["customer_id"],
    )
    resp = client.post("/v1/identify", json={"attestation_document": document}, headers=h)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "attestation_denied"


def test_no_matching_entry_is_denied(client, customer):
    h = customer["headers"]
    ensure_node_attestor(client, h)
    register_entry(client, h, agent_type="finance", scopes=["pay:send"])
    # Attest as a researcher -- no entry approves that environment.
    document = sign_attestation(
        workload=workload_for("researcher"), aud=customer["customer_id"]
    )
    resp = client.post("/v1/identify", json={"attestation_document": document}, headers=h)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "attestation_denied"


def test_rogue_agent_wrong_pod_label_is_denied(client, customer):
    """The headline property: right service account, wrong pod label -> no SVID.

    The signature is valid (same trusted node) and the SA matches, but the
    agent-type pod-label doesn't match the finance entry, so attestation fails.
    A stolen credential can't impersonate finance from the wrong environment.
    """
    h = customer["headers"]
    resp = register_and_identify(
        client, h, agent_type="finance", scopes=["pay:send"], pod_label="impostor"
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "attestation_denied"


def test_expired_attestation_document_is_denied(client, customer):
    h = customer["headers"]
    ensure_node_attestor(client, h)
    register_entry(client, h, agent_type="researcher", scopes=["db:read"])
    stale = sign_attestation(
        workload=workload_for("researcher"), exp=1, aud=customer["customer_id"]
    )  # 1970
    resp = client.post("/v1/identify", json={"attestation_document": stale}, headers=h)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "attestation_denied"


def test_identify_rejects_replayed_attestation_document(client, customer):
    """The same attestation jti cannot mint two credentials."""
    h = customer["headers"]
    ensure_node_attestor(client, h)
    register_entry(client, h, agent_type="researcher", scopes=["db:read"])
    jti = "replay-once"
    document = sign_attestation(
        workload=workload_for("researcher"),
        aud=customer["customer_id"],
        jti=jti,
    )
    first = client.post("/v1/identify", json={"attestation_document": document}, headers=h)
    assert first.status_code == 200, first.text
    replay = client.post("/v1/identify", json={"attestation_document": document}, headers=h)
    assert replay.status_code == 403
    body = replay.json()["error"]
    assert body["code"] == "attestation_denied"
    assert "already been used" in body["message"].lower()
    assert body.get("details", {}).get("attestation_jti") == jti


# --------------------------------------------------------------------------- #
# TTL bounds (still enforced at issuance)
# --------------------------------------------------------------------------- #
def test_default_ttl_applied(client, customer):
    data = register_and_identify(client, customer["headers"]).json()
    claims = jwt.decode(data["token"], options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == 3600  # default 1h


def test_ttl_below_minimum_rejected(client, customer):
    resp = register_and_identify(client, customer["headers"], ttl=60)
    assert resp.status_code == 400
    body = resp.json()["error"]
    assert body["code"] == "ttl_out_of_range"
    assert "300" in body["suggestion"]


def test_ttl_above_maximum_rejected(client, customer):
    resp = register_and_identify(client, customer["headers"], ttl=10**7)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "ttl_out_of_range"


def test_custom_ttl_within_range(client, customer):
    data = register_and_identify(client, customer["headers"], ttl=600).json()
    claims = jwt.decode(data["token"], options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == 600


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def test_validate_accepts_fresh_token(client, customer):
    token = register_and_identify(
        client,
        customer["headers"],
        scopes=["db:read"],
    ).json()["token"]
    resp = client.post(
        "/v1/validate",
        json={"token": token, "pop": _validate_pop(client, customer["headers"], token)},
        headers=customer["headers"],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True
    assert body["claims"]["agent_type"] == "researcher"


def test_validate_rejects_missing_pop_for_sender_constrained_token(client, customer):
    token = register_and_identify(
        client,
        customer["headers"],
        scopes=["db:read"],
    ).json()["token"]
    resp = client.post("/v1/validate", json={"token": token}, headers=customer["headers"])
    assert resp.status_code == 401
    assert "proof of possession" in resp.json()["error"]["message"].lower()


def test_identify_rejects_missing_workload_pubkey(client, customer):
    resp = register_and_identify(
        client,
        customer["headers"],
        with_pubkey=False,
    )
    assert resp.status_code == 403
    body = resp.json()["error"]
    assert body["code"] == "attestation_denied"
    assert "workload spiffe public key" in body["message"].lower()


def test_identify_rejects_rsa_workload_pubkey(client, customer):
    h = customer["headers"]
    ensure_node_attestor(client, h)
    register_entry(client, h, agent_type="researcher", scopes=["db:read"])
    workload = workload_for("researcher")
    workload["workload_pubkey_pem"] = NODE_PUBLIC_PEM
    document = sign_attestation(workload=workload, aud=customer["customer_id"])
    resp = client.post("/v1/identify", json={"attestation_document": document}, headers=h)
    assert resp.status_code == 403
    body = resp.json()["error"]
    assert body["code"] == "attestation_denied"
    assert "ed25519" in body["message"].lower()


def test_validate_rejects_garbage(client, customer):
    resp = client.post(
        "/v1/validate", json={"token": "not-a-jwt"}, headers=customer["headers"]
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "invalid_token"


def test_token_cannot_be_validated_by_other_customer(client, customer):
    token = register_and_identify(client, customer["headers"]).json()["token"]
    other = client.post("/v1/customers", json={"name": "Evil Inc"}).json()
    resp = client.post(
        "/v1/validate",
        json={"token": token},
        headers={"X-API-Key": other["api_key"]},
    )
    # Different customer -> kid does not belong to them.
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "invalid_token"


def test_tampered_token_rejected(client, customer):
    token = register_and_identify(client, customer["headers"]).json()["token"]
    head, payload, sig = token.split(".")
    bad_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    tampered = f"{head}.{payload}.{bad_sig}"
    resp = client.post(
        "/v1/validate", json={"token": tampered}, headers=customer["headers"]
    )
    assert resp.status_code == 401


def test_live_token_is_valid_now(client, customer):
    token = register_and_identify(
        client,
        customer["headers"],
        scopes=["db:read"],
        ttl=300,
    ).json()["token"]
    resp = client.post(
        "/v1/validate",
        json={"token": token, "pop": _validate_pop(client, customer["headers"], token)},
        headers=customer["headers"],
    )
    assert resp.status_code == 200


def test_validate_rejects_replayed_sender_constrained_challenge(client, customer):
    token = register_and_identify(
        client,
        customer["headers"],
        scopes=["db:read"],
    ).json()["token"]
    pop = _validate_pop(client, customer["headers"], token)
    first = client.post(
        "/v1/validate",
        json={"token": token, "pop": pop},
        headers=customer["headers"],
    )
    assert first.status_code == 200

    second = client.post(
        "/v1/validate",
        json={"token": token, "pop": pop},
        headers=customer["headers"],
    )
    assert second.status_code == 401
    assert "already been used" in second.json()["error"]["message"].lower()


def test_expired_token_rejected_and_marks_agent_expired(client, customer):
    """Sign a JWT-SVID with the customer's real active key but a past exp.

    Exercises the expiry branch deterministically (valid signature, expired
    claim) and verifies the agent row is flipped to 'expired'.
    """
    from agentauth.backend.db import SessionLocal
    from agentauth.backend.identity import get_active_key
    from agentauth.backend.models import Agent, Customer, new_id, spiffe_id, to_epoch, utcnow
    from agentauth.backend.signing_keys import decrypt_private_pem

    with SessionLocal() as db:
        cust = db.get(Customer, customer["customer_id"])
        key = get_active_key(db, cust.id)
        agent_id = new_id()
        sid = spiffe_id("agentauth.io", cust.id, "ghost")
        now = utcnow()
        agent = Agent(
            id=agent_id,
            customer_id=cust.id,
            agent_type="ghost",
            owner="alice@acme.ai",
            scopes=[],
            status="active",
            spiffe_id=sid,
            selectors=[],
            jti=new_id(),
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
        )
        db.add(agent)
        db.commit()
        past = to_epoch(now - timedelta(hours=1))
        token = jwt.encode(
            {
                "iss": "agentauth.io",
                "sub": sid,
                "aud": cust.id,
                "iat": past - 60,
                "nbf": past - 60,
                "exp": past,
                "jti": agent.jti,
                "customer_id": cust.id,
                "spiffe_id": sid,
                "agent_id": agent_id,
                "agent_type": "ghost",
                "owner": "alice@acme.ai",
                "scope": [],
                "selectors": [],
            },
            decrypt_private_pem(key.private_pem),
            algorithm="EdDSA",
            headers={"kid": key.kid, "typ": "agentauth-svid+jwt"},
        )

    resp = client.post("/v1/validate", json={"token": token}, headers=customer["headers"])
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "token_expired"

    got = client.get(f"/v1/agents/{agent_id}", headers=customer["headers"]).json()
    assert got["status"] == "expired"


# --------------------------------------------------------------------------- #
# Revocation
# --------------------------------------------------------------------------- #
def test_revoked_agent_fails_validation(client, customer):
    data = register_and_identify(client, customer["headers"]).json()
    rv = client.post(
        f"/v1/agents/{data['agent_id']}/revoke", headers=customer["headers"]
    )
    assert rv.status_code == 200
    assert rv.json()["status"] == "revoked"

    resp = client.post(
        "/v1/validate", json={"token": data["token"]}, headers=customer["headers"]
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "agent_revoked"


def test_revoke_unknown_agent_404(client, customer):
    resp = client.post("/v1/agents/deadbeef/revoke", headers=customer["headers"])
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "agent_not_found"


# --------------------------------------------------------------------------- #
# Agent listing (dashboard reads)
# --------------------------------------------------------------------------- #
def test_list_and_get_agents(client, customer):
    h = customer["headers"]
    a1 = register_and_identify(client, h, agent_type="planner").json()
    register_and_identify(client, h, agent_type="worker").json()

    listing = client.get("/v1/agents", headers=h).json()
    assert len(listing) >= 2

    filtered = client.get("/v1/agents?agent_type=planner", headers=h).json()
    assert all(a["agent_type"] == "planner" for a in filtered)

    one = client.get(f"/v1/agents/{a1['agent_id']}", headers=h)
    assert one.status_code == 200
    assert one.json()["id"] == a1["agent_id"]
    assert one.json()["spiffe_id"].endswith("/agent/planner")


def test_tenant_isolation_on_listing(client, customer):
    register_and_identify(client, customer["headers"]).json()
    other = client.post("/v1/customers", json={"name": "Other"}).json()
    other_headers = {"X-API-Key": other["api_key"]}
    assert client.get("/v1/agents", headers=other_headers).json() == []


# --------------------------------------------------------------------------- #
# Key rotation
# --------------------------------------------------------------------------- #
def test_rotation_keeps_old_tokens_valid(client, customer):
    h = customer["headers"]
    old = register_and_identify(client, h).json()["token"]
    old_kid = jwt.get_unverified_header(old)["kid"]

    rotate = client.post("/v1/keys/rotate", headers=h)
    assert rotate.status_code == 200
    new_kid = rotate.json()["active_kid"]
    assert new_kid != old_kid

    # Old token still validates (retired key retained).
    resp = client.post(
        "/v1/validate",
        json={"token": old, "pop": _validate_pop(client, h, old)},
        headers=h,
    )
    assert resp.status_code == 200

    # New token uses the new kid.
    new = register_and_identify(client, h).json()["token"]
    assert jwt.get_unverified_header(new)["kid"] == new_kid


def test_jwks_exposes_public_keys(client, customer):
    h = customer["headers"]
    register_and_identify(client, h)
    client.post("/v1/keys/rotate", headers=h)
    jwks = client.get("/v1/jwks.json", headers=h).json()
    assert len(jwks["keys"]) >= 2
    for k in jwks["keys"]:
        assert k["kty"] == "OKP"
        assert k["crv"] == "Ed25519"
        assert k["alg"] == "EdDSA"
        assert k["kid"]


# --------------------------------------------------------------------------- #
# Audit trail
# --------------------------------------------------------------------------- #
def test_issuance_is_audited(client, customer):
    data = register_and_identify(client, customer["headers"]).json()
    events = read_events(customer["customer_id"])
    issued = [
        e for e in events
        if e["type"] == "identity.issued" and e.get("agent_id") == data["agent_id"]
    ]
    assert len(issued) == 1
    assert issued[0]["customer_id"] == customer["customer_id"]
    assert issued[0]["spiffe_id"].endswith("/agent/researcher")


def test_attestor_and_entry_registration_audited(client, customer):
    h = customer["headers"]
    ensure_node_attestor(client, h)
    register_entry(client, h, agent_type="researcher", scopes=["db:read"])
    types = {e["type"] for e in read_events(customer["customer_id"])}
    assert "node_attestor.created" in types
    assert "registration.created" in types


def test_audit_log_is_hash_chained(client, customer):
    register_and_identify(client, customer["headers"])
    issues = verify_event_log()
    assert issues == []

    events = read_events()
    assert events
    assert events[0]["schema"] == "agentauth.audit.v1"
    assert events[0]["sequence"] == 1
    assert "entry_hash" in events[0]
    assert "prev_hash" in events[0]


def test_audit_log_appends_from_multiple_processes(client):
    script = """
from agentauth.backend.audit import record_event
for i in range(6):
    record_event("process.event", "parallel-review", worker=WORKER, index=i)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd() + os.pathsep + env.get("PYTHONPATH", "")
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", script.replace("WORKER", repr(str(worker)))],
            cwd=os.getcwd(),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for worker in range(4)
    ]
    for proc in procs:
        stdout, stderr = proc.communicate(timeout=20)
        assert proc.returncode == 0, stdout + stderr

    assert verify_event_log() == []
    events = [
        event
        for event in read_events("parallel-review")
        if event["type"] == "process.event"
    ]
    assert len(events) == 24
    assert len({event["sequence"] for event in events}) == 24


def test_audit_log_tampering_is_detected(client, customer):
    from sqlalchemy import select

    from agentauth.backend.db import SessionLocal
    from agentauth.backend.models import AuditEvent

    h = customer["headers"]
    ensure_node_attestor(client, h)
    register_entry(client, h, agent_type="researcher", scopes=["db:read"])

    # Tamper with a stored row in place: its recomputed hash no longer matches.
    with SessionLocal() as db:
        last = db.scalars(
            select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1)
        ).first()
        last.type = "registration.deleted"
        db.commit()

    issues = verify_event_log()
    assert any("entry_hash mismatch" in issue for issue in issues)
