"""Reference fraud MCP server HTTP auth (P2-25)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import anyio
import pytest

pytest.importorskip("starlette")
from starlette.testclient import TestClient

from agentauth.receipts import mcp_server
from agentauth.receipts.mcp_client import McpConnectionSpec
from agentauth.receipts.mcp_server import (
    MCP_API_KEY_ENV,
    build_fraud_mcp,
    http_starlette_app,
    mcp_api_key,
    run_fraud_mcp,
    validate_http_bind,
    wrap_http_app,
)


def test_mcp_api_key_strips_blank_values(monkeypatch):
    monkeypatch.setenv(MCP_API_KEY_ENV, "  ")
    assert mcp_api_key() is None

    monkeypatch.setenv(MCP_API_KEY_ENV, "  secret  ")
    assert mcp_api_key() == "secret"


def test_validate_http_bind_allows_localhost_without_key():
    validate_http_bind("127.0.0.1")


def test_validate_http_bind_rejects_public_bind_without_key(monkeypatch):
    monkeypatch.delenv(MCP_API_KEY_ENV, raising=False)
    with pytest.raises(SystemExit):
        validate_http_bind("0.0.0.0")


def test_validate_http_bind_allows_public_bind_with_key(monkeypatch):
    monkeypatch.setenv(MCP_API_KEY_ENV, "secret")
    validate_http_bind("0.0.0.0")


def test_http_app_requires_api_key_when_configured(monkeypatch):
    monkeypatch.setenv(MCP_API_KEY_ENV, "mcp-secret")
    app = build_fraud_mcp()
    client = TestClient(wrap_http_app(app.streamable_http_app()))

    denied = client.post("/mcp", json={})
    assert denied.status_code == 401


def test_http_starlette_app_selects_transport_without_api_key(monkeypatch):
    monkeypatch.delenv(MCP_API_KEY_ENV, raising=False)
    fake_app = SimpleNamespace(
        sse_app=MagicMock(return_value="sse-app"),
        streamable_http_app=MagicMock(return_value="http-app"),
    )

    assert http_starlette_app(fake_app, "sse") == "sse-app"
    assert http_starlette_app(fake_app, "streamable-http") == "http-app"
    fake_app.sse_app.assert_called_once()
    fake_app.streamable_http_app.assert_called_once()


def test_run_fraud_mcp_dispatches_stdio():
    app = SimpleNamespace(run=MagicMock(), settings=SimpleNamespace(host="127.0.0.1"))

    run_fraud_mcp(app, "stdio")

    app.run.assert_called_once_with(transport="stdio")


def test_run_fraud_mcp_rejects_unknown_transport():
    app = SimpleNamespace(run=MagicMock(), settings=SimpleNamespace(host="127.0.0.1"))

    with pytest.raises(ValueError, match="unknown transport"):
        run_fraud_mcp(app, "websocket")


def test_run_fraud_mcp_dispatches_http_transport(monkeypatch):
    app = SimpleNamespace(run=MagicMock(), settings=SimpleNamespace(host="127.0.0.1"))
    called = {}

    def fake_anyio_run(factory):
        called["factory"] = factory

    monkeypatch.setattr(anyio, "run", fake_anyio_run)

    run_fraud_mcp(app, "sse")

    assert callable(called["factory"])
    app.run.assert_not_called()


def test_main_builds_app_and_dispatches_transport(monkeypatch):
    built = SimpleNamespace(settings=SimpleNamespace(host="127.0.0.1", port=9123))
    build = MagicMock(return_value=built)
    run = MagicMock()
    monkeypatch.setattr(mcp_server, "build_fraud_mcp", build)
    monkeypatch.setattr(mcp_server, "run_fraud_mcp", run)

    mcp_server.main(["--transport", "sse", "--host", "localhost", "--port", "9123"])

    build.assert_called_once_with(host="localhost", port=9123)
    run.assert_called_once_with(built, "sse")


def test_mcp_connection_spec_forwards_api_key_header(monkeypatch):
    monkeypatch.setenv(MCP_API_KEY_ENV, "from-env")
    assert McpConnectionSpec(transport="sse").http_headers() == {
        "X-API-Key": "from-env"
    }
    assert McpConnectionSpec(transport="sse", api_key="explicit").http_headers() == {
        "X-API-Key": "explicit"
    }
