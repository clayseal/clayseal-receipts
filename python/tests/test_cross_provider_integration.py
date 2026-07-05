"""Receipt e2e with pluggable identity + capability layers."""
from __future__ import annotations

from pathlib import Path

import pytest

from agentauth.capabilities.identity_adapters import get_identity_provider
from agentauth.receipts.integration import wrap_with_identity_session

ROOT = Path(__file__).resolve().parents[2]


def test_wrap_with_spiffe_identity_session():
    pytest.importorskip("agentauth.receipts")
    from agentauth.receipts import Policy

    raw = {
        "sub": "spiffe://example.org/customer/ten_demo/agent/bot/e2e",
        "iss": "spiffe://example.org",
        "scope": "db:read",
    }
    session = get_identity_provider("spiffe_jwt").build_session(raw)
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    wrapper = wrap_with_identity_session(
        lambda inp: {"ok": True, **inp},
        policy,
        session,
        mode="shadow",
        audit_db=":memory:",
    )
    result = wrapper.run({"transaction_id": "t-cross-provider"})
    assert result.output.get("ok") is True
