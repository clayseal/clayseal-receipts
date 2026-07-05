"""Tests for registration entry overlap lint."""
from __future__ import annotations

from tests.attest import ensure_node_attestor, register_entry


def test_registration_lint_ok_for_distinct_specificity(client, customer):
    h = customer["headers"]
    ensure_node_attestor(client, h)
    register_entry(client, h, agent_type="researcher", scopes=["db:read"])
    client.post(
        "/v1/registration-entries",
        json={
            "agent_type": "finance",
            "selectors": [
                "k8s:ns:customer-acme",
                "k8s:sa:finance",
            ],
            "scopes": ["pay:send"],
        },
        headers=h,
    )
    resp = client.get("/v1/registration-entries/lint", headers=h)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["conflicts"] == []


def test_registration_lint_flags_equal_specificity_overlap(client, customer):
    h = customer["headers"]
    selectors = [
        "k8s:ns:customer-acme",
        "k8s:sa:researcher",
        "k8s:pod-label:agentauth.io/agent-type:researcher",
    ]
    client.post(
        "/v1/registration-entries",
        json={"agent_type": "researcher", "selectors": selectors, "scopes": ["db:read"]},
        headers=h,
    )
    client.post(
        "/v1/registration-entries",
        json={
            "agent_type": "researcher-shadow",
            "selectors": selectors,
            "scopes": ["web:read"],
        },
        headers=h,
    )
    resp = client.get("/v1/registration-entries/lint", headers=h)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is False
    assert len(body["conflicts"]) == 1
    conflict = body["conflicts"][0]
    assert conflict["selector_count"] == 3
    assert len(conflict["entry_ids"]) == 2
