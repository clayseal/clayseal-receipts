"""The hosted service verifies receipt bundles, not just identity.

One FastAPI process now exposes both the identity router and the receipt
verifier, so these run against the same TestClient as the identity tests.
"""
from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from agentauth.backend.main import create_app
from agentauth.receipts import AgentWrapper, Policy, build_receipt_bundle
from agentauth.receipts.verifier_auth import (
    VERIFIER_API_KEY_ENV,
    VERIFIER_REQUIRE_API_KEY_ENV,
)

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "policies" / "fraud_decision.yaml"


def test_version_lists_supported_schemas(client):
    resp = client.get("/v1/version")
    assert resp.status_code == 200
    body = resp.json()
    assert body["verifier_version"]
    assert isinstance(body["supported_schemas"], list) and body["supported_schemas"]


def test_verify_endpoint_checks_a_bundle(client, tmp_path):
    wrapper = AgentWrapper(
        lambda inp: {"decision": "approve", "fraud_score": 0.1},
        Policy.from_yaml(POLICY),
        mode="shadow",
        audit_db=str(tmp_path / "audit.sqlite"),
    )
    result = wrapper.run({"transaction_id": "t1", "amount": 10.0})
    bundle = build_receipt_bundle(result, certificate=wrapper.certificate)

    resp = client.post("/v1/verify", json=bundle)
    assert resp.status_code == 200
    body = resp.json()
    # Shadow receipts are not cryptographically valid, but the endpoint returns
    # a structured verdict (not an error) — proving the verifier is mounted.
    assert body["valid"] is False
    assert body["schema"] == bundle["schema"]
    assert "verifier_version" in body


def test_verify_rejects_non_object_body(client):
    resp = client.post("/v1/verify", json=["not", "an", "object"])
    assert resp.status_code == 400
    assert resp.json()["valid"] is False


def test_verify_handles_malformed_bundle(client):
    resp = client.post("/v1/verify", json={})
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is False
    assert any(issue["code"] == "schema_mismatch" for issue in body["issues"])


def test_verify_rejects_oversized_body(client, monkeypatch):
    monkeypatch.setenv("AGENT_RECEIPTS_MAX_BODY_BYTES", "2")
    resp = client.post(
        "/v1/verify",
        content=b'{"schema":"too-large"}',
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    assert resp.json()["valid"] is False
    assert "exceeds 2 bytes" in resp.json()["reasons"][0]


def test_verify_route_is_rate_limited(monkeypatch):
    monkeypatch.setenv("AGENT_RECEIPTS_VERIFIER_RATE_LIMIT", "1")
    limited_client = TestClient(create_app())
    assert limited_client.post("/v1/verify", json=[]).status_code == 400
    resp = limited_client.post("/v1/verify", json=[])
    assert resp.status_code == 429
    assert resp.json()["error"] == "rate_limit_exceeded"


def test_verify_honors_verifier_api_key_env(monkeypatch):
    monkeypatch.setenv(VERIFIER_API_KEY_ENV, "test-secret-key")
    monkeypatch.delenv(VERIFIER_REQUIRE_API_KEY_ENV, raising=False)
    protected_client = TestClient(create_app())

    denied = protected_client.post("/v1/verify", json={})
    assert denied.status_code == 401

    allowed = protected_client.post(
        "/v1/verify",
        json={},
        headers={"X-API-Key": "test-secret-key"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["valid"] is False


def test_verify_require_api_key_flag_applies_to_unified_backend(monkeypatch):
    monkeypatch.delenv(VERIFIER_API_KEY_ENV, raising=False)
    monkeypatch.setenv(VERIFIER_REQUIRE_API_KEY_ENV, "1")
    protected_client = TestClient(create_app())

    resp = protected_client.post("/v1/verify", json={})
    assert resp.status_code == 503
    assert resp.json()["error"] == "misconfigured"


def test_verifier_api_key_does_not_replace_identity_auth(monkeypatch):
    monkeypatch.setenv(VERIFIER_API_KEY_ENV, "test-secret-key")
    protected_client = TestClient(create_app())

    resp = protected_client.get("/v1/agents")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "invalid_api_key"
