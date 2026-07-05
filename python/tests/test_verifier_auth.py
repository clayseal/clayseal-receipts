from pathlib import Path

import pytest

pytest.importorskip("starlette")

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.export import build_receipt_bundle
from agentauth.receipts.verifier_auth import (
    VERIFIER_API_KEY_ENV,
    VERIFIER_REQUIRE_API_KEY_ENV,
    ApiKeyMiddleware,
    validate_verifier_bind,
)

ROOT = Path(__file__).resolve().parents[2]


def _reset_app(monkeypatch):
    import agentauth.receipts.verifier_server as vs

    vs._app = None
    monkeypatch.delenv(VERIFIER_API_KEY_ENV, raising=False)
    monkeypatch.delenv(VERIFIER_REQUIRE_API_KEY_ENV, raising=False)


@pytest.fixture
def client(monkeypatch):
    _reset_app(monkeypatch)
    monkeypatch.setenv(VERIFIER_API_KEY_ENV, "test-secret-key")
    from agentauth.receipts.verifier_server import get_app

    return TestClient(get_app())


def test_verify_requires_api_key(client: TestClient):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"amount": 1.0})
    bundle = build_receipt_bundle(result, certificate=cert)

    assert client.post("/v1/verify", json=bundle).status_code == 401

    r = client.post(
        "/v1/verify",
        json=bundle,
        headers={"X-API-Key": "test-secret-key"},
    )
    assert r.status_code == 200


def test_health_public_without_key(client: TestClient):
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code in (200, 503)


def test_validate_verifier_bind_refuses_public_host_without_key():
    with pytest.raises(SystemExit) as exc:
        validate_verifier_bind("0.0.0.0")
    assert exc.value.code == 2


def test_validate_verifier_bind_allows_localhost_without_key():
    validate_verifier_bind("127.0.0.1")


def test_verify_returns_503_when_require_flag_without_key(monkeypatch):
    _reset_app(monkeypatch)
    monkeypatch.setenv(VERIFIER_REQUIRE_API_KEY_ENV, "1")
    from agentauth.receipts.verifier_server import get_app

    client = TestClient(get_app())
    assert client.post("/v1/verify", json={}).status_code == 503
    assert client.get("/health").status_code == 200


async def _ok_response(_request):
    return JSONResponse({"ok": True})


def test_api_key_middleware_can_scope_to_verify_only(monkeypatch):
    monkeypatch.setenv(VERIFIER_API_KEY_ENV, "test-secret-key")
    app = Starlette(
        routes=[
            Route("/v1/verify", _ok_response, methods=["POST"]),
            Route("/v1/agents", _ok_response, methods=["GET"]),
        ]
    )
    app.add_middleware(ApiKeyMiddleware, protected_paths={"/v1/verify"})
    client = TestClient(app)

    assert client.get("/v1/agents").status_code == 200
    assert client.post("/v1/verify").status_code == 401
    assert (
        client.post("/v1/verify", headers={"X-API-Key": "test-secret-key"}).status_code
        == 200
    )


def test_api_key_middleware_require_flag_stays_scoped(monkeypatch):
    monkeypatch.delenv(VERIFIER_API_KEY_ENV, raising=False)
    monkeypatch.setenv(VERIFIER_REQUIRE_API_KEY_ENV, "1")
    app = Starlette(
        routes=[
            Route("/v1/verify", _ok_response, methods=["POST"]),
            Route("/v1/agents", _ok_response, methods=["GET"]),
        ]
    )
    app.add_middleware(ApiKeyMiddleware, protected_paths={"/v1/verify"})
    client = TestClient(app)

    assert client.get("/v1/agents").status_code == 200
    assert client.post("/v1/verify").status_code == 503


def test_rate_limit_buckets_by_api_key(monkeypatch):
    _reset_app(monkeypatch)
    monkeypatch.setenv("AGENT_RECEIPTS_VERIFIER_RATE_LIMIT", "2")
    from agentauth.receipts.verifier_server import get_app

    client = TestClient(get_app())
    headers_a = {"X-API-Key": "client-a", "content-type": "application/json"}
    headers_b = {"X-API-Key": "client-b", "content-type": "application/json"}

    assert client.post("/v1/verify", content=b"x", headers=headers_a).status_code == 400
    assert client.post("/v1/verify", content=b"x", headers=headers_a).status_code == 400
    assert client.post("/v1/verify", content=b"x", headers=headers_a).status_code == 429
    assert client.post("/v1/verify", content=b"x", headers=headers_b).status_code == 400
