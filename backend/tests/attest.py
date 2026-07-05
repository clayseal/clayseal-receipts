"""Shared attestation helpers for the test suite.

Issuing an identity now requires (1) a registered node trust anchor, (2) a
registration entry pre-approving the agent_type, and (3) a signed attestation
document whose verified selectors match the entry. These helpers package that
flow so each test can keep expressing intent as "an agent of type X with scopes
Y" while exercising the real attestation path.

A module-level RSA keypair plays the node's signing key (what AWS/k8s/GCP would
sign evidence with in production). ``ROGUE_PRIVATE_PEM`` is an *unregistered*
key used to prove that forged provenance is rejected.
"""
from __future__ import annotations

import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


def _rsa_keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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


def _ed25519_keypair() -> tuple[str, str]:
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


# The trusted node key (registered as the tenant's node attestor) ...
NODE_PRIVATE_PEM, NODE_PUBLIC_PEM = _rsa_keypair()
# ... and an unregistered key, for forgery tests.
ROGUE_PRIVATE_PEM, _ROGUE_PUBLIC_PEM = _rsa_keypair()

# The workload's own SPIFFE keypair. In production the SPIRE agent/workload
# holds this; the capability token (Biscuit) is bound to its public half and
# every authorization requires a fresh signature from the private half.
WORKLOAD_PRIVATE_PEM, WORKLOAD_PUBLIC_PEM = _ed25519_keypair()
ROGUE_WORKLOAD_PRIVATE_PEM, ROGUE_WORKLOAD_PUBLIC_PEM = _ed25519_keypair()

# Node evidence a k8s_psat attestor would verify (the SPIRE Agent's own node).
DEFAULT_NODE = {"cluster": "prod-cluster", "agent_ns": "spire", "agent_sa": "spire-agent"}

# Cache: register the node attestor once per tenant (keyed by API key).
_attestor_registered: set[str] = set()
# Map API keys to tenant ids so attestation JWTs get the correct aud claim.
_customer_id_by_api_key: dict[str, str] = {}


def bind_customer_api_key(api_key: str, customer_id: str) -> None:
    """Associate a tenant id with an API key (set by the ``customer`` fixture)."""
    _customer_id_by_api_key[api_key] = customer_id


def selectors_for(agent_type: str) -> list[str]:
    """The workload selectors a given agent_type must prove (the entry's keys)."""
    return [
        "k8s:ns:customer-acme",
        f"k8s:sa:{agent_type}",
        f"k8s:pod-label:agentauth.io/agent-type:{agent_type}",
    ]


def workload_for(
    agent_type: str, *, pod_label: str | None = None, with_pubkey: bool = True
) -> dict:
    """Workload evidence for an agent_type. ``pod_label`` overrides the
    agent-type label so a test can simulate a rogue/mismatched workload.

    When ``with_pubkey`` the workload's SPIFFE public key is included so the
    backend can bind a capability token to it. Set it False to exercise the
    JWT-only fallback (no key presented -> no biscuit)."""
    workload = {
        "k8s_ns": "customer-acme",
        "k8s_sa": agent_type,
        "pod_labels": {"agentauth.io/agent-type": pod_label or agent_type},
    }
    if with_pubkey:
        workload["workload_pubkey_pem"] = WORKLOAD_PUBLIC_PEM
    return workload


def sign_attestation(
    *,
    node: dict | None = None,
    workload: dict | None = None,
    key_pem: str = NODE_PRIVATE_PEM,
    attestor_type: str = "k8s_psat",
    exp: int | None = None,
    jti: str | None = None,
    aud: str | None = None,
) -> str:
    """Produce a signed attestation document (a JWS) the node agent would emit."""
    now = int(time.time())
    payload: dict = {
        "type": attestor_type,
        "node": node if node is not None else DEFAULT_NODE,
        "workload": workload or {},
        "jti": jti or uuid.uuid4().hex,
        "iat": now,
        "exp": exp if exp is not None else now + 300,
    }
    if aud is not None:
        payload["aud"] = aud
    return jwt.encode(payload, key_pem, algorithm="RS256")


def ensure_node_attestor(client, headers) -> None:
    """Register the trusted node attestor for this tenant exactly once."""
    api_key = headers["X-API-Key"]
    if api_key in _attestor_registered:
        return
    resp = client.post(
        "/v1/node-attestors",
        json={"type": "k8s_psat", "public_pem": NODE_PUBLIC_PEM},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    _attestor_registered.add(api_key)


def register_entry(
    client, headers, *, agent_type, scopes=None, capabilities=None, owner=None, ttl=None
):
    """Create a registration entry pre-approving ``agent_type`` + its rights.

    Pass ``capabilities`` (list of ``{resource, action}``) for the fine-grained
    path, or ``scopes`` for the legacy path (the backend derives the other)."""
    body = {
        "agent_type": agent_type,
        "selectors": selectors_for(agent_type),
    }
    if capabilities is not None:
        body["capabilities"] = capabilities
    if scopes is not None:
        body["scopes"] = list(scopes)
    if owner is not None:
        body["owner"] = owner
    if ttl is not None:
        body["ttl_seconds"] = ttl
    listing = client.get("/v1/registration-entries", headers=headers)
    assert listing.status_code == 200, listing.text
    for entry in listing.json():
        if (
            entry["agent_type"] == body["agent_type"]
            and entry["selectors"] == body["selectors"]
            and entry.get("capabilities", []) == body.get("capabilities", [])
            and entry.get("scopes", []) == body.get("scopes", [])
            and entry.get("owner") == body.get("owner")
            and entry.get("ttl_seconds") == body.get("ttl_seconds")
        ):
            class _Existing:
                status_code = 200
                text = "existing registration entry"

                def json(self_nonlocal):
                    return entry

            return _Existing()
    return client.post("/v1/registration-entries", json=body, headers=headers)


def register_and_identify(
    client,
    headers,
    *,
    agent_type="researcher",
    scopes=None,
    capabilities=None,
    owner="alice@acme.ai",
    ttl=None,
    pod_label=None,
    with_pubkey=True,
    customer_id: str | None = None,
):
    """End-to-end attestation: ensure anchor + entry, sign matching evidence,
    and call ``/v1/identify``. Returns the raw response (callers ``.json()`` it).

    ``pod_label`` lets a test present mismatched workload evidence (the rogue
    case) so the entry no longer matches. ``with_pubkey=False`` omits the
    workload public key to exercise the JWT-only fallback.
    """
    ensure_node_attestor(client, headers)
    register_entry(
        client, headers, agent_type=agent_type, scopes=scopes,
        owner=owner,
        capabilities=capabilities, ttl=ttl,
    )
    resolved_customer_id = customer_id or _customer_id_by_api_key.get(headers["X-API-Key"])
    document = sign_attestation(
        workload=workload_for(agent_type, pod_label=pod_label, with_pubkey=with_pubkey),
        aud=resolved_customer_id,
    )
    body = {"attestation_document": document}
    if ttl is not None:
        body["ttl_seconds"] = ttl
    return client.post("/v1/identify", json=body, headers=headers)
