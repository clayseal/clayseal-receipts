"""Capability-constraint safety tests."""
from __future__ import annotations

import pytest
from agentauth.backend import capabilities as cap_service
from agentauth.backend.errors import RegistrationEntryError
from agentauth.backend.models import utcnow


def test_normalize_capabilities_rejects_constraints():
    with pytest.raises(RegistrationEntryError, match="constraints"):
        cap_service.normalize_capabilities(
            [{"resource": "db", "action": "read", "constraints": {"rows": 1}}]
        )


def test_mint_biscuit_rejects_constraints():
    with pytest.raises(RegistrationEntryError, match="constraints"):
        cap_service.mint_biscuit(
            root_private_hex="00" * 64,
            spiffe_id="spiffe://example/agent",
            agent_id="agent-1",
            capabilities=[{"resource": "db", "action": "read", "constraints": {"rows": 1}}],
            bound_keyhash="abc",
            expires_at=utcnow(),
        )


def test_registration_entry_rejects_unsupported_capability_constraints(client, customer):
    resp = client.post(
        "/v1/registration-entries",
        json={
            "agent_type": "researcher",
            "selectors": [
                "k8s:ns:customer-acme",
                "k8s:sa:researcher",
                "k8s:pod-label:agentauth.io/agent-type:researcher",
            ],
            "capabilities": [
                {
                    "resource": "db",
                    "action": "read",
                    "constraints": {"rows": 1},
                }
            ],
        },
        headers=customer["headers"],
    )
    assert resp.status_code == 422, resp.text
    body = resp.json()
    detail = body.get("detail") or body.get("error", {}).get("message", "")
    if isinstance(detail, list):
        detail = " ".join(str(item) for item in detail)
    assert "constraints" in str(detail).lower()
