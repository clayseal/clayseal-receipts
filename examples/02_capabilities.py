"""02 - Capabilities: fine-grained, attenuable, offline-verifiable authorization.

Where 01 covered *identity* (who an agent is), this covers *authorization*
(what it may do). Each agent carries a Biscuit capability token, bound to its
SPIFFE keypair, that expresses fine-grained ``resource:action`` rights and can
be:
  1. authorized entirely offline (no call back to the service),
  2. attenuated -- narrowed to fewer rights, offline, by the holder,
  3. delegated -- a least-privilege token handed to a sub-agent,
  4. trusted only with proof-of-possession -- a stolen token is inert.

Run:  python examples/02_capabilities.py
"""
from __future__ import annotations

import time
import uuid

import common

from agentauth.identity import _capabilities as caps


def main() -> None:
    common.title("AgentAuth - Capability-Based Authorization")
    auth, _api_key, _url = common.bootstrap("Acme AI")

    # 1. Issue an identity with fine-grained capabilities (not flat scopes).
    common.step("Issue a 'researcher' with capabilities db:read and web:*")
    agent = auth.identify(
        agent_type="researcher",
        owner="alice@acme.ai",
        capabilities=[
            {"resource": "db", "action": "read"},
            {"resource": "web", "action": "*"},
        ],
    )
    common.info(f"agent_id      = {common.code(agent.agent_id)}")
    common.detail(f"capabilities = {agent.capabilities}")
    common.detail(f"biscuit      = {agent.biscuit[:32]}... (bound to workload key)")

    # 2. Authorize operations offline -- no server round-trip, proof-of-possession
    #    is signed locally with the workload key.
    common.step("Authorize operations offline")
    common.allow(f'db:read   -> {agent.can("db", "read")}')
    common.allow(f'web:post  -> {agent.can("web", "post")}  (action wildcard)')
    common.deny(f'db:write  -> {agent.can("db", "write")}  (never granted)')

    # 3. Attenuate: the holder narrows the token to fewer rights, offline.
    common.step("Attenuate to a read-only token (offline, monotonic)")
    readonly = agent.attenuate(capabilities=[{"resource": "db", "action": "read"}])
    common.allow(f'db:read   -> {readonly.can("db", "read")}')
    common.deny(f'web:post  -> {readonly.can("web", "post")}  (attenuated away)')
    common.detail("a narrowed token can never claw back a dropped right")

    # 4. Delegate: hand a sub-agent the least privilege it needs.
    common.step("Delegate db:read to a sub-agent")
    delegated_token = agent.delegate(capabilities=[{"resource": "db", "action": "read"}])
    sub = auth.session_from_token(
        {
            "agent_id": agent.agent_id,
            "token": agent.token,
            "agent_type": "sub-researcher",
            "owner": agent.owner,
            "biscuit": delegated_token,
            "biscuit_root_public_key": agent.credential.biscuit_root_public_key,
            "bound_keyhash": agent.credential.bound_keyhash,
        },
        workload_private_pem=agent._workload_private_pem,
    )
    common.allow(f'sub db:read  -> {sub.can("db", "read")}')
    common.deny(f'sub web:post -> {sub.can("web", "post")}  (outside delegated set)')

    # 5. Proof-of-possession: a stolen token can't be used without the key.
    common.step("A stolen token is inert without the workload private key")
    root_pub = agent.credential.biscuit_root_public_key
    # An attacker forges a signature with a key they own (not the bound one).
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    attacker = ed25519.Ed25519PrivateKey.generate()
    attacker_priv = attacker.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    attacker_pub = attacker.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    attacker_keyhash = caps.keyhash_for_pem(attacker_pub)
    challenge = "stolen"
    iat = int(time.time())
    jti = uuid.uuid4().hex
    ath = caps.token_hash(agent.biscuit)
    forged = caps.PopProof(
        challenge=challenge,
        signature_b64=caps.sign_request_pop(
            attacker_priv,
            attacker_keyhash,
            challenge,
            htm="OFFLINE",
            htu="agentauth:authorize",
            ath=ath,
            iat=iat,
            jti=jti,
            operation=("db", "read"),
        ),
        pubkey_pem=attacker_pub,
        htm="OFFLINE",
        htu="agentauth:authorize",
        ath=ath,
        iat=iat,
        jti=jti,
    )
    result = caps.authorize_biscuit(
        token_b64=agent.biscuit,
        root_public_hex=root_pub,
        operation=("db", "read"),
        pop=forged,
        expected_htm="OFFLINE",
        expected_htu="agentauth:authorize",
    )
    common.deny(f"forged proof-of-possession -> allowed={result['allowed']}")
    common.detail(f"reason: {result['reason']}")

    common.title("Done - express, attenuate, delegate, and verify rights offline")


if __name__ == "__main__":
    main()
