"""Receipt exporters: plugin discovery + delivery flows (Phase 3 BYO audit)."""

from __future__ import annotations

from pathlib import Path

import pytest
from agentauth.core import plugins
from agentauth.core.runtime import ActionDescriptor, SideEffectLevel
from agentauth.core.signing import generate_keypair

from agentauth.receipts import AgentWrapper, Policy, scitt
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.export import build_receipt_bundle
from agentauth.receipts.exporters import (
    DrataExporter,
    OtelGenAiExporter,
    ScittExporter,
    VantaExporter,
    receipt_evidence_record,
)
from agentauth.receipts.otel import GEN_AI_SEMCONV_VERSION, OTEL_SCHEMA_URL

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def bundle() -> dict:
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run(
        {"transaction_id": "t1", "amount": 10.0},
        action=ActionDescriptor(
            action_name="payments.refund",
            action_category="payments",
            resource_type="transaction",
            resource_ref="txn-1",
            side_effect_level=SideEffectLevel.BOUNDED_WRITE,
        ),
        session_id="sess-1",
    )
    return build_receipt_bundle(result, certificate=cert, policy=policy)


class _Response:
    def __init__(self, status_code: int = 200, json_body: dict | None = None):
        self.status_code = status_code
        self._json = json_body or {}
        self.content = b""
        self.headers: dict[str, str] = {}

    def json(self) -> dict:
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _CapturingClient:
    def __init__(self, responses: dict[str, _Response] | None = None):
        self.calls: list[dict] = []
        self.responses = responses or {}

    def _record(self, method: str, url: str, **kwargs) -> _Response:
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.responses.get(url, _Response())

    def post(self, url, **kwargs):
        return self._record("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self._record("PUT", url, **kwargs)


# --- plugin discovery ------------------------------------------------------- #


def test_exporters_discoverable_via_entry_points():
    names = set(plugins.list_plugins("receipt_exporters"))
    assert {"otel_genai", "ocsf_ai_operation", "scitt", "vanta", "drata"} <= names
    exporter = plugins.get_plugin("receipt_exporters", "otel_genai")
    assert exporter.name == "otel_genai"
    assert callable(exporter.export)


def test_attestation_verifiers_discoverable_via_entry_points():
    names = set(plugins.list_plugins("attestation_verifiers"))
    assert {"nitro", "eat_jwt"} <= names


# --- OTel gen_ai exporter --------------------------------------------------- #


def test_otel_exporter_returns_pinned_payload_without_endpoint(bundle):
    result = OtelGenAiExporter(endpoint="").export(bundle)
    assert result["delivered"] is False
    assert result["semconv_version"] == GEN_AI_SEMCONV_VERSION
    resource_logs = result["payload"]["resourceLogs"][0]
    assert resource_logs["schemaUrl"] == OTEL_SCHEMA_URL
    assert resource_logs["scopeLogs"][0]["schemaUrl"] == OTEL_SCHEMA_URL
    records = resource_logs["scopeLogs"][0]["logRecords"]
    keys = {attr["key"] for attr in records[0]["attributes"]}
    assert "gen_ai.tool.name" in keys


def test_otel_exporter_posts_to_endpoint(bundle):
    client = _CapturingClient()
    result = OtelGenAiExporter(
        endpoint="https://collector.example/v1/logs",
        headers={"x-api-key": "k"},
        client=client,
    ).export(bundle)
    assert result["delivered"] is True
    assert client.calls[0]["url"] == "https://collector.example/v1/logs"
    assert client.calls[0]["headers"]["x-api-key"] == "k"
    assert "resourceLogs" in client.calls[0]["json"]


def test_otel_exporter_delivers_over_real_http(bundle):
    """OTLP smoke: real httpx POST against a local collector stand-in."""
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    received: list[dict] = []

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append(json.loads(body))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/v1/logs"
        result = OtelGenAiExporter(endpoint=endpoint).export(bundle)
    finally:
        server.shutdown()
        thread.join(timeout=5)
    assert result["delivered"] is True and result["status_code"] == 200
    log_records = received[0]["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    assert log_records[0]["body"] == {"stringValue": "agent.receipt"}


# --- SCITT exporter over SCRAPI --------------------------------------------- #


def test_scitt_exporter_publishes_and_returns_transparent_statement(bundle):
    pytest.importorskip("starlette")
    from starlette.testclient import TestClient

    from agentauth.receipts.verifier_server import (
        _reset_transparency_service,
        create_app,
        get_transparency_service,
    )

    _reset_transparency_service()
    client = TestClient(create_app())
    key = generate_keypair()
    result = ScittExporter(base_url="http://testserver", signing_key=key).export(
        bundle, client=client
    )
    assert result["delivered"] is True
    service_key = get_transparency_service().public_key
    statement = bytes.fromhex(result["signed_statement"])
    receipt = bytes.fromhex(result["receipt"])
    assert scitt.verify_statement(statement, key.public_key) is not None
    assert scitt.verify_receipt(statement, receipt, service_key)
    transparent = bytes.fromhex(result["transparent_statement"])
    assert scitt.verify_transparent_statement(transparent, service_key)


def test_scitt_exporter_without_base_url_still_signs(bundle):
    key = generate_keypair()
    result = ScittExporter(base_url="", signing_key=key).export(bundle)
    assert result["delivered"] is False
    assert scitt.verify_statement(bytes.fromhex(result["signed_statement"]), key.public_key)


def test_scitt_exporter_requires_signing_key(bundle, monkeypatch):
    monkeypatch.delenv("AGENTAUTH_SCITT_STATEMENT_KEY_HEX", raising=False)
    with pytest.raises(RuntimeError, match="signing key"):
        ScittExporter(base_url="").export(bundle)


# --- evidence record + compliance exporters ---------------------------------- #


def test_receipt_evidence_record_embeds_verification_verdict(bundle):
    record = receipt_evidence_record(bundle)
    assert record["action"] == "payments.refund"
    assert record["outcome"] == "allow"
    assert record["policy_commitment"]
    assert isinstance(record["verification"]["valid"], bool)
    assert isinstance(record["verification"]["reasons"], list)


def test_vanta_exporter_full_state_sync(bundle):
    client = _CapturingClient(
        responses={
            "https://api.vanta.com/oauth/token": _Response(json_body={"access_token": "tok"})
        }
    )
    result = VantaExporter(
        resources_url="https://api.vanta.com/v1/custom-resources/sync",
        client_id="cid",
        client_secret="sec",
        client=client,
    ).export(bundle, verify=False)
    assert result["delivered"] is True
    token_call, put_call = client.calls
    assert token_call["json"]["grant_type"] == "client_credentials"
    assert put_call["method"] == "PUT"
    assert put_call["headers"]["Authorization"] == "Bearer tok"
    assert put_call["json"]["resourceType"] == "AgentReceipt"
    assert put_call["json"]["resources"][0]["resourceId"] == result["resource_id"]


def test_vanta_exporter_unconfigured_raises(bundle, monkeypatch):
    for env in (
        "AGENTAUTH_VANTA_RESOURCES_URL",
        "AGENTAUTH_VANTA_CLIENT_ID",
        "AGENTAUTH_VANTA_CLIENT_SECRET",
    ):
        monkeypatch.delenv(env, raising=False)
    with pytest.raises(RuntimeError, match="unconfigured"):
        VantaExporter().export(bundle)


def test_drata_exporter_posts_record(bundle):
    client = _CapturingClient()
    result = DrataExporter(
        api_key="key", connection_id="conn1", resource_id="res1", client=client
    ).export(bundle, verify=False)
    assert result["delivered"] is True
    call = client.calls[0]
    assert call["url"] == (
        "https://public-api.drata.com/public/custom-connections/conn1/resources/res1/records"
    )
    assert call["headers"]["Authorization"] == "Bearer key"
    assert call["json"]["data"]["action"] == "payments.refund"


def test_drata_exporter_unconfigured_raises(bundle, monkeypatch):
    for env in (
        "AGENTAUTH_DRATA_API_KEY",
        "AGENTAUTH_DRATA_CONNECTION_ID",
        "AGENTAUTH_DRATA_RESOURCE_ID",
    ):
        monkeypatch.delenv(env, raising=False)
    with pytest.raises(RuntimeError, match="unconfigured"):
        DrataExporter().export(bundle)
