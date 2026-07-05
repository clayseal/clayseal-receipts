"""SDK capability tests: offline authorization, attenuation, delegation, and
cross-package proof-of-possession parity with the backend."""
from __future__ import annotations

import pytest

from agentauth.identity.errors import BiscuitError, CapabilityDeniedError

DB_READ_WEB_ALL = [
    {"resource": "db", "action": "read"},
    {"resource": "web", "action": "*"},
]


def _agent(auth, capabilities=DB_READ_WEB_ALL):
    return auth.identify(
        agent_type="researcher", owner="alice@acme.ai", capabilities=capabilities
    )


def test_identify_yields_capability_token(auth):
    agent = _agent(auth)
    assert agent.biscuit, "a capability token should be minted"
    assert agent.capabilities == DB_READ_WEB_ALL


def test_dev_attestor_does_not_reuse_stale_capabilities(auth):
    first = auth.identify(
        agent_type="worker",
        owner="alice@acme.ai",
        capabilities=[{"resource": "admin", "action": "*"}],
    )
    second = auth.identify(
        agent_type="worker",
        owner="alice@acme.ai",
        capabilities=[{"resource": "db", "action": "read"}],
    )
    assert first.capabilities == [{"resource": "admin", "action": "*"}]
    assert second.capabilities == [{"resource": "db", "action": "read"}]


def test_authorize_allow_and_deny_offline(auth):
    agent = _agent(auth)
    assert agent.can("db", "read") is True
    assert agent.can("web", "post") is True  # action wildcard
    assert agent.can("db", "write") is False


def test_enforce_raises_on_denied(auth):
    agent = _agent(auth, capabilities=[{"resource": "db", "action": "read"}])
    agent.enforce("db", "read")  # no raise
    with pytest.raises(CapabilityDeniedError):
        agent.enforce("db", "write")


def test_attenuate_narrows_rights(auth):
    agent = _agent(auth)
    narrowed = agent.attenuate(capabilities=[{"resource": "db", "action": "read"}])
    assert narrowed.can("db", "read") is True
    assert narrowed.can("web", "post") is False
    # The original session is unchanged.
    assert agent.can("web", "post") is True


def test_attenuated_cannot_regain(auth):
    agent = _agent(auth)
    narrowed = agent.attenuate(capabilities=[{"resource": "db", "action": "read"}])
    regained = narrowed.attenuate(capabilities=[{"resource": "web", "action": "post"}])
    assert regained.can("web", "post") is False


def test_delegate_produces_narrowed_token(auth):
    agent = _agent(auth)
    delegated = agent.delegate(capabilities=[{"resource": "db", "action": "read"}])
    # Rehydrate the delegated token as a sub-agent session (same workload key).
    sub = auth.session_from_token(
        {
            "agent_id": agent.agent_id,
            "token": agent.token,
            "agent_type": agent.agent_type,
            "owner": agent.owner,
            "biscuit": delegated,
            "biscuit_root_public_key": agent.credential.biscuit_root_public_key,
            "bound_keyhash": agent.credential.bound_keyhash,
        },
        workload_private_pem=agent._workload_private_pem,
    )
    assert sub.can("db", "read") is True
    assert sub.can("web", "post") is False


def test_jwt_only_session_has_no_biscuit(auth):
    # scopes-only still works and yields capabilities + a biscuit (the SDK always
    # presents a workload key); a session with no biscuit raises on capability ops.
    agent = auth.identify(agent_type="legacy", owner="x", scopes=["db:read"])
    assert agent.biscuit
    # Simulate a biscuit-less session (e.g. an old backend).
    bare = auth.session_from_token(
        {"agent_id": "a", "token": agent.token, "agent_type": "legacy", "owner": "x"}
    )
    with pytest.raises(BiscuitError):
        bare.can("db", "read")


def test_pop_signing_matches_backend():
    """The SDK's proof-of-possession signature must verify with the backend's
    verifier (the two reimplement the same crypto in separate packages)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from agentauth.backend import capabilities as backend_caps
    from agentauth.identity import _capabilities as sdk_caps

    ed = ed25519.Ed25519PrivateKey.generate()
    ed_priv = ed.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    ed_pub = ed.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    ed_keyhash = sdk_caps.keyhash_for_pem(ed_pub)
    op = ("db", "read")
    sig = sdk_caps.sign_request_pop(
        ed_priv,
        ed_keyhash,
        "nonce-xyz",
        htm="POST",
        htu="/v1/authorize",
        ath=sdk_caps.token_hash("token-abc"),
        iat=1234,
        jti="proof-1",
        operation=op,
    )
    assert backend_caps.verify_request_pop(
        ed_pub,
        ed_keyhash,
        "nonce-xyz",
        htm="POST",
        htu="/v1/authorize",
        ath=backend_caps.token_hash("token-abc"),
        iat=1234,
        jti="proof-1",
        signature_b64=sig,
        operation=op,
        expected_htm="POST",
        expected_htu="/v1/authorize",
        expected_ath=backend_caps.token_hash("token-abc"),
        now=1234,
    )
    assert not backend_caps.verify_request_pop(
        ed_pub,
        ed_keyhash,
        "nonce-xyz",
        htm="POST",
        htu="/v1/authorize",
        ath=backend_caps.token_hash("other-token"),
        iat=1234,
        jti="proof-1",
        signature_b64=sig,
        operation=op,
        expected_htm="POST",
        expected_htu="/v1/authorize",
        expected_ath=backend_caps.token_hash("other-token"),
        now=1234,
    )
