"""Tests for CORS support (the browser dashboard is a separate origin)."""
from __future__ import annotations

from tests.attest import (
    ensure_node_attestor,
    register_entry,
    sign_attestation,
    workload_for,
)


def test_preflight_allows_dashboard_origin(client):
    resp = client.options(
        "/v1/identify",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-API-Key, Content-Type",
        },
    )
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "http://localhost:5173"
    allow_headers = resp.headers.get("access-control-allow-headers", "").lower()
    assert "x-api-key" in allow_headers


def test_actual_request_carries_cors_origin(client, customer):
    h = customer["headers"]
    ensure_node_attestor(client, h)
    register_entry(client, h, agent_type="researcher", scopes=["db:read"])
    document = sign_attestation(
        workload=workload_for("researcher"), aud=customer["customer_id"]
    )
    resp = client.post(
        "/v1/identify",
        json={"attestation_document": document, "owner": "a@b.c"},
        headers={**h, "Origin": "http://localhost:5173"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["access-control-allow-origin"] == "http://localhost:5173"
