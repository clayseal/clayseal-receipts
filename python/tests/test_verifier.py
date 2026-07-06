"""HTTP verifier service tests."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

pytest.importorskip("starlette")

from starlette.testclient import TestClient

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.authority_binding import AuthorityBinding
from agentauth.receipts.certificate import dev_certificate, sign_certificate
from agentauth.receipts.export import build_receipt_bundle
from agentauth.core.runtime import ActionDescriptor, SideEffectLevel
from agentauth.core.signing import generate_keypair, sign_bundle
from agentauth.receipts.verifier_auth import (
    VERIFIER_API_KEY_ENV,
    VERIFIER_REQUIRE_API_KEY_ENV,
)
from agentauth.receipts.verifier_server import get_app

ROOT = Path(__file__).resolve().parents[2]


def _trusted_certificate(monkeypatch: pytest.MonkeyPatch, policy: Policy):
    issuer = generate_keypair()
    cert = sign_certificate(dev_certificate(policy.commitment()), issuer)
    monkeypatch.setenv(
        "AGENT_RECEIPTS_TRUSTED_CERTIFICATE_ISSUER_PUBLIC_KEYS",
        issuer.public_key_hex,
    )
    return cert


def _sign_and_trust_bundle(monkeypatch: pytest.MonkeyPatch, bundle: dict):
    signer = generate_keypair()
    sign_bundle(bundle, signer, role="agent")
    monkeypatch.setenv(
        "AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS",
        signer.public_key_hex,
    )
    return bundle


@pytest.fixture
def client(monkeypatch):
    import agentauth.receipts.verifier_server as vs

    vs._app = None
    monkeypatch.delenv(VERIFIER_API_KEY_ENV, raising=False)
    monkeypatch.delenv(VERIFIER_REQUIRE_API_KEY_ENV, raising=False)
    monkeypatch.delenv("AGENT_RECEIPTS_VERIFIER_RATE_LIMIT", raising=False)
    return TestClient(get_app())


def test_health(client: TestClient):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_ready(client: TestClient):
    r = client.get("/ready")
    assert r.status_code in (200, 503)
    assert "ready" in r.json()


def test_version_lists_supported_schemas(client: TestClient):
    r = client.get("/v1/version")
    assert r.status_code == 200
    body = r.json()
    assert body["verifier_version"]
    assert isinstance(body["supported_schemas"], list) and body["supported_schemas"]


def test_verify_shadow_bundle_invalid_crypto(client: TestClient):
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
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    r = client.post("/v1/verify", json=bundle)
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is False
    assert body["proof_id"] == str(result.proof.proof_id)


@pytest.mark.skipif(
    not (ROOT / "target" / "release" / "agent-receipts").is_file(),
    reason="release CLI not built",
)
@pytest.mark.skipif(
    shutil.which("ezkl") is None and not os.environ.get("EZKL"),
    reason="ezkl not installed",
)
def test_verify_prove_bundle_valid(client: TestClient, monkeypatch):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = _trusted_certificate(monkeypatch, policy)
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="prove",
        prove_composed=False,
        prove_inference=True,
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t2", "amount": 500.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    _sign_and_trust_bundle(monkeypatch, bundle)
    r = client.post("/v1/verify", json=bundle)
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_verify_bad_json(client: TestClient):
    r = client.post("/v1/verify", content=b"not-json", headers={"content-type": "application/json"})
    assert r.status_code == 400


def test_verify_malformed_bundle_returns_structured_verdict(client: TestClient):
    r = client.post("/v1/verify", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is False
    assert any(issue["code"] == "schema_mismatch" for issue in body["issues"])


def test_verify_min_assurance_tier_query(client: TestClient):
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
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    r = client.post("/v1/verify?min_assurance_tier=signed", json=bundle)
    assert r.status_code == 200
    body = r.json()
    assert body["assurance"]["meets_minimum"] is False
    assert body["valid"] is False


def test_verify_invalid_min_assurance_tier_returns_400(client: TestClient):
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
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    r = client.post("/v1/verify?min_assurance_tier=definitely-not-a-tier", json=bundle)
    assert r.status_code == 400
    body = r.json()
    assert body["valid"] is False
    assert any("invalid min_assurance_tier" in reason for reason in body["reasons"])


def test_verify_returns_authority_block_for_agentauth_integration(client: TestClient):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    binding = AuthorityBinding.from_agentauth_credential(
        {
            "agent_id": "agent-123",
            "spiffe_id": "spiffe://agentauth.io/customer/acme/agent/researcher",
            "agent_type": "researcher",
            "owner": "alice@acme.ai",
            "scopes": ["db:read"],
            "selectors": ["k8s:sa:researcher"],
            "expires_at": "2026-06-20T00:00:00Z",
            "capabilities": [{"resource": "db", "action": "read"}],
            "biscuit": "cap-token",
            "bound_keyhash": "bound-hash",
        }
    )
    result = agent.run(
        {"transaction_id": "t-auth", "amount": 100.0},
        action=ActionDescriptor(
            action_name="read",
            action_category="data",
            resource_type="db",
            resource_ref="db://primary",
            side_effect_level=SideEffectLevel.READ_ONLY,
        ),
        session_id="sess-auth",
        authority_version=4,
        authority_binding=binding,
    )
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    r = client.post("/v1/verify", json=bundle)
    assert r.status_code == 200
    body = r.json()
    assert body["authority"]["tenant_id"] == "acme"
    assert (
        body["authority"]["workload_principal"]
        == "spiffe://agentauth.io/customer/acme/agent/researcher"
    )
    assert body["authority"]["presenter_key_hash"] == "bound-hash"
    assert body["session"]["session_id"] == "sess-auth"
