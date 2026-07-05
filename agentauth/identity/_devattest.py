#TODO Remove in production !!!
# USE SPIRE server in production environment with real node-attestation
# Requires cloud/kubernetes deployment

"""Local dev attestation — the SDK standing in for a SPIRE Agent.

The backend issues identities only after attestation: a workload presents a
*signed* attestation document, the node attestor verifies it against a registered
trust anchor, the workload attestor derives selectors, and a pre-registered entry
must match (see ``identity/identity.md`` and ``docs/v2-decisions``).

In production a SPIRE Agent on the node does this and the platform pre-registers
which environments may receive which identity. For **local development** we keep
the one-line ``auth.identify(agent_type, owner, scopes)`` ergonomic by having the
SDK play both roles: it generates a node keypair, registers it as the tenant's
node trust anchor, registers a registration entry for the requested
``agent_type``/``scopes``, and signs a matching attestation document. The
selectors it derives mirror the backend's ``attestation.py`` exactly so the
match succeeds.

This is a developer convenience, not the production path — a real deployment
would register trust anchors + entries out-of-band and let SPIRE attest. The
``DevAttestor`` is created lazily by :class:`~agentauth.client.AgentAuth`, so SDK
users who never call ``identify`` pay nothing.
"""
from __future__ import annotations

import hashlib
import json
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


# Stable, dev-only environment evidence. The entry keys on the workload
# selectors (namespace / service account / agent-type pod label); the node block
# just needs to verify against the registered anchor.
_DEV_NS = "agentauth-dev"
_DEV_NODE = {"cluster": "dev", "agent_ns": "spire", "agent_sa": "spire-agent"}


class DevAttestor:
    """Generates and registers everything needed to attest locally."""

    def __init__(self) -> None:
        # The node anchor key (plays AWS/k8s/GCP signing the node evidence) ...
        self._private_pem, self._public_pem = _rsa_keypair()
        # ... and the workload's own SPIFFE keypair. The capability token gets
        # bound to its public half; proof-of-possession at authorize time is a
        # fresh signature from the private half (held only here, in the SDK).
        self.workload_private_pem, self.workload_public_pem = _ed25519_keypair()
        self._anchor_registered = False
        self._entries: dict[str, str] = {}
        # The backend binds attestation documents to the tenant (aud claim) to
        # reject cross-tenant replay; we learn our customer id from the
        # node-attestor registration response.
        self._customer_id: str | None = None

    @staticmethod
    def _selectors_for(agent_type: str, dev_entry: str | None = None) -> list[str]:
        selectors = [
            f"k8s:ns:{_DEV_NS}",
            f"k8s:sa:{agent_type}",
            f"k8s:pod-label:agentauth.io/agent-type:{agent_type}",
        ]
        if dev_entry:
            selectors.append(f"k8s:pod-label:agentauth.io/dev-entry:{dev_entry}")
        return selectors

    @staticmethod
    def _entry_cache_key(
        agent_type: str,
        scopes: list[str],
        capabilities: list[dict] | None,
        owner: str | None,
    ) -> tuple[str, str]:
        material = {
            "agent_type": agent_type,
            "owner": owner or "",
            "scopes": list(scopes or []),
            "capabilities": list(capabilities or []),
        }
        canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
        return canonical, digest

    def _ensure_anchor(self, http) -> None:
        if self._anchor_registered:
            return
        attestor = http.post(
            "/v1/node-attestors",
            json={
                "type": "k8s_psat",
                "public_pem": self._public_pem,
                "description": "agentauth-sdk dev attestor",
            },
        )
        if isinstance(attestor, dict):
            self._customer_id = attestor.get("customer_id")
        self._anchor_registered = True

    def _ensure_entry(
        self,
        http,
        agent_type: str,
        scopes: list[str],
        capabilities: list[dict] | None = None,
        owner: str | None = None,
    ) -> str:
        # Identity is attested, not declared: the backend reads agent_type,
        # scopes, and owner from the matched registration entry — not the
        # identify request — so the dev entry must carry the owner.
        cache_key, dev_entry = self._entry_cache_key(
            agent_type, scopes, capabilities, owner
        )
        if cache_key in self._entries:
            return self._entries[cache_key]
        body = {
            "agent_type": agent_type,
            "selectors": self._selectors_for(agent_type, dev_entry),
            "description": "agentauth-sdk dev entry",
        }
        if owner:
            body["owner"] = owner
        if capabilities:
            body["capabilities"] = capabilities
        else:
            body["scopes"] = list(scopes or [])
        http.post("/v1/registration-entries", json=body)
        self._entries[cache_key] = dev_entry
        return dev_entry

    def attestation_document(
        self,
        http,
        agent_type: str,
        scopes: list[str],
        capabilities: list[dict] | None = None,
        owner: str | None = None,
    ) -> str:
        """Ensure the anchor + entry exist, then return a signed document whose
        verified selectors match the entry for ``agent_type``.

        The workload's SPIFFE public key rides in the ``workload`` block so the
        backend can bind the capability token to it (proof-of-possession)."""
        self._ensure_anchor(http)
        dev_entry = self._ensure_entry(http, agent_type, scopes, capabilities, owner)
        now = int(time.time())
        payload = {
            "type": "k8s_psat",
            "node": _DEV_NODE,
            "workload": {
                "k8s_ns": _DEV_NS,
                "k8s_sa": agent_type,
                "pod_labels": {
                    "agentauth.io/agent-type": agent_type,
                    "agentauth.io/dev-entry": dev_entry,
                },
                "workload_pubkey_pem": self.workload_public_pem,
            },
            # Bind the document to this tenant and make it one-time + short-lived
            # so the hardened backend (aud + jti + exp) accepts it.
            "aud": self._customer_id,
            "jti": uuid.uuid4().hex,
            "iat": now,
            "exp": now + 300,
        }
        return jwt.encode(payload, self._private_pem, algorithm="RS256")
