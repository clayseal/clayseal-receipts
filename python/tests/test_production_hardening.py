"""Production hardening: soundness deny-list, managed signer, audit-store resolution,
verifier identity-binding toggle, and SCITT transparency single-writer + rate limits.

Covers fixes #1 (state/signer), #3 (transparency/rate limit), #4 (verifier toggle),
and #5 (production escape-hatch guardrail)."""

from __future__ import annotations

import pytest

from agentauth.receipts import environment as env


def _configure_production_baseline(monkeypatch) -> None:
    """Minimum env for production startup checks added in agentauth-core 0.5+."""
    monkeypatch.setenv(
        "AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS",
        "a336f3cb3b2d1199b62fd727ed122f580b1d613b9b2934a67e9a9b74432c9160",
    )
    monkeypatch.setenv("AGENTAUTH_HTTP_ALLOWED_HOSTS", "example.com")
    monkeypatch.setenv("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES", "1")
    monkeypatch.setenv("AGENT_RECEIPTS_VERIFIER_API_KEY", "test-verifier-key")


# --------------------------------------------------------------------------- #
# Fix #5: production soundness deny-list
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("AGENT_RECEIPTS_ALLOW_STUB", "1"),
        ("AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE", "1"),
        ("AGENT_RECEIPTS_ALLOW_UNSIGNED_CHECKPOINT", "1"),
        ("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES", "0"),
        ("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES", ""),
    ],
)
def test_production_refuses_soundness_downgrades(monkeypatch, flag, value):
    monkeypatch.setenv("AGENT_RECEIPTS_ENV", "production")
    _configure_production_baseline(monkeypatch)
    if value:
        monkeypatch.setenv(flag, value)
    else:
        monkeypatch.delenv(flag, raising=False)
    with pytest.raises(RuntimeError, match="soundness-downgrading"):
        env.enforce_production_soundness()


def test_non_production_allows_downgrade_flags(monkeypatch):
    monkeypatch.delenv("AGENT_RECEIPTS_ENV", raising=False)
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_STUB", "1")
    env.enforce_production_soundness()  # no-op outside production


def test_production_implies_require_prover(monkeypatch):
    monkeypatch.delenv("AGENT_RECEIPTS_REQUIRE_PROVER", raising=False)
    monkeypatch.setenv("AGENT_RECEIPTS_ENV", "production")
    assert env.require_prover_active() is True


def test_agent_wrapper_fails_closed_in_production_with_stub(monkeypatch):
    from pathlib import Path

    from agentauth.receipts import AgentWrapper, Policy
    from agentauth.receipts.certificate import dev_certificate

    root = Path(__file__).resolve().parents[2]
    policy = Policy.from_yaml(root / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    monkeypatch.setenv("AGENT_RECEIPTS_ENV", "production")
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_STUB", "1")
    with pytest.raises(RuntimeError, match="soundness-downgrading"):
        AgentWrapper(
            model=lambda inp: inp,
            policy=policy,
            certificate=cert,
            mode="shadow",
            audit_db=":memory:",
        )


# --------------------------------------------------------------------------- #
# Fix #1b: managed / stable signing key
# --------------------------------------------------------------------------- #
def test_managed_signer_none_by_default(monkeypatch):
    monkeypatch.delenv("AGENT_RECEIPTS_ENV", raising=False)
    monkeypatch.delenv("AGENT_RECEIPTS_SIGNING_KEY_PATH", raising=False)
    monkeypatch.delenv("AGENT_RECEIPTS_REQUIRE_STABLE_SIGNER", raising=False)
    assert env.load_managed_signing_key() is None


def test_require_stable_signer_without_path_raises(monkeypatch):
    monkeypatch.delenv("AGENT_RECEIPTS_SIGNING_KEY_PATH", raising=False)
    monkeypatch.setenv("AGENT_RECEIPTS_REQUIRE_STABLE_SIGNER", "1")
    with pytest.raises(RuntimeError, match="stable signing key"):
        env.load_managed_signing_key()


def test_managed_signer_stable_across_loads(monkeypatch, tmp_path):
    key_path = tmp_path / "agent_ed25519.key"
    monkeypatch.setenv("AGENT_RECEIPTS_SIGNING_KEY_PATH", str(key_path))
    first = env.load_managed_signing_key()
    second = env.load_managed_signing_key()
    assert first is not None and second is not None
    # Same on-disk key -> same key_id across replicas/restarts.
    assert first.key_id == second.key_id


def test_managed_signer_wired_into_audit_chain(monkeypatch, tmp_path):
    from pathlib import Path

    from agentauth.receipts import AgentWrapper, Policy
    from agentauth.receipts.certificate import dev_certificate

    root = Path(__file__).resolve().parents[2]
    policy = Policy.from_yaml(root / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    monkeypatch.setenv("AGENT_RECEIPTS_SIGNING_KEY_PATH", str(tmp_path / "signer.key"))
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    assert agent.signing_key is not None
    assert agent.audit.signing_key is agent.signing_key


# --------------------------------------------------------------------------- #
# Fix #1a: audit store resolution / durability guard
# --------------------------------------------------------------------------- #
def test_resolve_audit_db_rejects_remote_backend():
    with pytest.raises(RuntimeError, match="unsupported audit store backend"):
        env.resolve_audit_db("postgresql://user@host/db")


def test_resolve_audit_db_accepts_sqlite_url():
    assert env.resolve_audit_db("sqlite:///relative/audit.db") == "relative/audit.db"
    assert env.resolve_audit_db("sqlite:////abs/audit.db") == "/abs/audit.db"


def test_resolve_audit_db_env_override_only_for_default(monkeypatch, tmp_path):
    override = str(tmp_path / "shared.sqlite")
    monkeypatch.setenv("AGENT_RECEIPTS_AUDIT_DB", override)
    # Explicit non-default argument wins.
    assert env.resolve_audit_db("custom.sqlite") == "custom.sqlite"
    # The wrapper default is replaced by the env value.
    assert env.resolve_audit_db(env.DEFAULT_AUDIT_DB) == override


def test_production_refuses_ephemeral_audit_store(monkeypatch):
    monkeypatch.setenv("AGENT_RECEIPTS_ENV", "production")
    monkeypatch.delenv("AGENT_RECEIPTS_AUDIT_STORE_ACK", raising=False)
    with pytest.raises(RuntimeError, match="ephemeral/relative audit store"):
        env.enforce_durable_audit_store(".audit/chain.sqlite")


def test_production_accepts_absolute_or_acknowledged_store(monkeypatch):
    monkeypatch.setenv("AGENT_RECEIPTS_ENV", "production")
    monkeypatch.delenv("AGENT_RECEIPTS_AUDIT_STORE_ACK", raising=False)
    env.enforce_durable_audit_store("/mnt/shared/audit/chain.sqlite")  # absolute -> ok
    monkeypatch.setenv("AGENT_RECEIPTS_AUDIT_STORE_ACK", "1")
    env.enforce_durable_audit_store(".audit/chain.sqlite")  # acknowledged single instance


# --------------------------------------------------------------------------- #
# Fix #4 + #3: verifier identity-binding toggle and transparency controls
# --------------------------------------------------------------------------- #
pytest.importorskip("starlette")

from pathlib import Path  # noqa: E402

from agentauth.core.signing import generate_keypair  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from agentauth.receipts import AgentWrapper, Policy, scitt, scrapi  # noqa: E402
from agentauth.receipts.certificate import dev_certificate  # noqa: E402
from agentauth.receipts.export import build_receipt_bundle  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def _fresh_verifier(monkeypatch) -> TestClient:
    import agentauth.receipts.verifier_server as vs

    vs._app = None
    monkeypatch.delenv("AGENT_RECEIPTS_VERIFIER_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_RECEIPTS_VERIFIER_REQUIRE_API_KEY", raising=False)
    from agentauth.receipts.verifier_server import get_app

    return TestClient(get_app())


def _unbound_bundle() -> dict:
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    return build_receipt_bundle(result, certificate=cert, policy=policy)


def test_verifier_env_requires_identity_binding(monkeypatch):
    monkeypatch.setenv("AGENT_RECEIPTS_REQUIRE_IDENTITY_BINDING", "1")
    client = _fresh_verifier(monkeypatch)
    r = client.post("/v1/verify", json=_unbound_bundle())
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is False
    assert any(issue["code"] == "authority_unbound" for issue in body["issues"])


def test_verifier_default_allows_unbound(monkeypatch):
    monkeypatch.delenv("AGENT_RECEIPTS_REQUIRE_IDENTITY_BINDING", raising=False)
    client = _fresh_verifier(monkeypatch)
    r = client.post("/v1/verify", json=_unbound_bundle())
    body = r.json()
    assert not any(issue["code"] == "authority_unbound" for issue in body["issues"])


def _statement(payload: bytes = b"receipt-claim") -> bytes:
    key = generate_keypair()
    return scitt.sign_statement(payload, key, issuer="issuer.example", subject="agent-42")


def test_transparency_register_blocked_in_production_without_single_writer(monkeypatch):
    import agentauth.receipts.verifier_server as vs

    vs._reset_transparency_service()
    monkeypatch.setenv("AGENT_RECEIPTS_ENV", "production")
    _configure_production_baseline(monkeypatch)
    monkeypatch.delenv("AGENT_RECEIPTS_TRANSPARENCY_SINGLE_WRITER", raising=False)
    monkeypatch.setenv("AGENT_RECEIPTS_TRANSPARENCY_SINGLE_WRITER", "")
    client = TestClient(vs.create_app())
    r = client.post("/entries", content=_statement(), headers={"Content-Type": scrapi.MEDIA_COSE})
    assert r.status_code == 409
    assert scrapi.decode_problem_details(r.content)["title"] == "Transparency Registration Disabled"


def test_transparency_register_allowed_with_single_writer_flag(monkeypatch):
    import agentauth.receipts.verifier_server as vs

    vs._reset_transparency_service()
    monkeypatch.setenv("AGENT_RECEIPTS_ENV", "production")
    _configure_production_baseline(monkeypatch)
    monkeypatch.setenv("AGENT_RECEIPTS_TRANSPARENCY_SINGLE_WRITER", "1")
    client = TestClient(vs.create_app())
    r = client.post("/entries", content=_statement(), headers={"Content-Type": scrapi.MEDIA_COSE})
    assert r.status_code == 201


def test_entries_are_rate_limited(monkeypatch):
    import agentauth.receipts.verifier_server as vs

    vs._reset_transparency_service()
    vs._app = None
    monkeypatch.delenv("AGENT_RECEIPTS_ENV", raising=False)
    monkeypatch.setenv("AGENT_RECEIPTS_VERIFIER_RATE_LIMIT", "2")
    client = TestClient(vs.get_app())
    headers = {"Content-Type": scrapi.MEDIA_COSE}
    codes = [
        client.post("/entries", content=b"not-cose", headers=headers).status_code
        for _ in range(3)
    ]
    assert codes[-1] == 429
