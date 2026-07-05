"""Tests for partner integration helper modules."""
from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentauth.receipts import fraud_tools
from agentauth.receipts.logging_config import setup_logging
from agentauth.receipts.mcp_bridge import receipted_call_tool, wrap_mcp_session
from agentauth.receipts.partner_config import PartnerConfig
from agentauth.receipts.partner_factory import build_agent_from_config

ROOT = Path(__file__).resolve().parents[2]


def test_setup_logging_configures_once_and_honors_level(monkeypatch):
    logger_name = "agent_receipts_test_helpers"
    logger = logging.getLogger(logger_name)
    logger.handlers.clear()
    monkeypatch.setenv("AGENT_RECEIPTS_LOG_LEVEL", "DEBUG")

    first = setup_logging(logger_name)
    second = setup_logging(logger_name)

    assert first is second
    assert first.level == logging.DEBUG
    assert len(first.handlers) == 1
    assert "%(asctime)s" in first.handlers[0].formatter._fmt


@pytest.mark.parametrize(
    ("amount", "decision", "score"),
    [
        (100, "approve", 0.01),
        (5000, "review", 0.5),
        (9000, "deny", 0.9),
        (20000, "deny", 1.0),
    ],
)
def test_fraud_tool_scores_thresholds(amount, decision, score):
    result = fraud_tools.score_fraud_model({"transaction_id": "txn-1", "amount": amount})

    assert result == {
        "transaction_id": "txn-1",
        "decision": decision,
        "fraud_score": score,
    }


def test_fraud_tool_metadata_helpers():
    assert fraud_tools.score_transaction({"transaction_id": "txn-2"}) == {
        "transaction_id": "txn-2",
        "scored": True,
    }
    assert fraud_tools.fetch_customer_profile({"customer_id": "cust-1"}) == {
        "customer_id": "cust-1",
        "tier": "gold",
    }


@pytest.mark.asyncio
async def test_receipted_call_tool_returns_result_payload():
    class FakeClient:
        async def call_tool(self, name, arguments):
            assert name == "score_fraud_model"
            assert arguments == {"amount": 100}
            return SimpleNamespace(blocked=False, output={"result": {"ok": True}})

    assert await receipted_call_tool(
        FakeClient(), "score_fraud_model", {"amount": 100}
    ) == {"ok": True}


@pytest.mark.asyncio
async def test_receipted_call_tool_raises_on_policy_block():
    class FakeClient:
        async def call_tool(self, name, arguments):
            return SimpleNamespace(
                blocked=True,
                policy_violations=["tool not allowed"],
                output={"status": "blocked"},
            )

    with pytest.raises(PermissionError, match="tool not allowed"):
        await receipted_call_tool(FakeClient(), "delete_everything", {})


def test_wrap_mcp_session_reuses_gateway_policy():
    pytest.importorskip("mcp")
    gateway = SimpleNamespace(agent=object(), server_name="risk-mcp")
    session = object()

    client = wrap_mcp_session(session, gateway)

    assert client.session is session
    assert client.server_name == "risk-mcp"
    assert client._policy is gateway


def test_build_agent_from_partner_config_uses_policy_and_certificate_settings(tmp_path):
    cfg_path = tmp_path / "partner.yaml"
    cfg_path.write_text(
        f"""
policy_path: {ROOT / "policies" / "fraud_decision.yaml"}
audit_db: {tmp_path / "audit.sqlite"}
mode: shadow
model_provenance_hash: sha256:factory-model-v1
organization: risk-prod
principal_id: risk-agent
"""
    )
    cfg = PartnerConfig.from_yaml(cfg_path)

    wrapper = build_agent_from_config(
        cfg,
        lambda _inp: {"decision": "approve", "fraud_score": 0.0},
    )

    assert wrapper.mode == "shadow"
    assert wrapper.model_provenance_hash == "sha256:factory-model-v1"
    assert wrapper.certificate.model_provenance_hash == "sha256:factory-model-v1"
    assert wrapper.certificate.principal.organization == "risk-prod"
    assert wrapper.certificate.principal.principal_id == "risk-agent"
