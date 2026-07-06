"""MCP Protected Resource Metadata (RFC 9728) on the MCP HTTP surface."""

from __future__ import annotations

import pytest

pytest.importorskip("starlette")

from starlette.applications import Starlette  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from agentauth.receipts.mcp_server import (  # noqa: E402
    MCP_API_KEY_ENV,
    MCP_AUTHORIZATION_SERVERS_ENV,
    MCP_RESOURCE_URL_ENV,
    MCP_SCOPES_ENV,
    PRM_PATH,
    wrap_http_app,
)


@pytest.fixture
def client(monkeypatch) -> TestClient:
    monkeypatch.delenv(MCP_API_KEY_ENV, raising=False)
    return TestClient(wrap_http_app(Starlette()))


def test_metadata_defaults_resource_to_base_url(client, monkeypatch):
    monkeypatch.delenv(MCP_RESOURCE_URL_ENV, raising=False)
    monkeypatch.delenv(MCP_AUTHORIZATION_SERVERS_ENV, raising=False)
    doc = client.get(PRM_PATH).json()
    assert doc["resource"] == "http://testserver"
    assert doc["authorization_servers"] == []
    assert doc["bearer_methods_supported"] == ["header"]


def test_metadata_honors_configuration(client, monkeypatch):
    monkeypatch.setenv(MCP_RESOURCE_URL_ENV, "https://mcp.example/fraud")
    monkeypatch.setenv(
        MCP_AUTHORIZATION_SERVERS_ENV,
        "https://auth.example/t/tenant1, https://other-as.example",
    )
    monkeypatch.setenv(MCP_SCOPES_ENV, "fraud:score,fraud:read")
    doc = client.get(PRM_PATH).json()
    assert doc["resource"] == "https://mcp.example/fraud"
    assert doc["authorization_servers"] == [
        "https://auth.example/t/tenant1",
        "https://other-as.example",
    ]
    assert doc["scopes_supported"] == ["fraud:score", "fraud:read"]


def test_metadata_stays_public_when_api_key_gates_the_server(monkeypatch):
    """RFC 9728 discovery happens BEFORE the client has credentials."""
    monkeypatch.setenv(MCP_API_KEY_ENV, "sekrit")
    client = TestClient(wrap_http_app(Starlette()))
    assert client.get(PRM_PATH).status_code == 200
