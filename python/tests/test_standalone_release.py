"""Standalone release smoke tests that do not require private Clay Seal layers."""

from __future__ import annotations

import importlib.util

import pytest

import agentauth.core
import agentauth.receipts as receipts
from agentauth.receipts import AgentWrapper, Policy, ReceiptedMcpGateway
from agentauth.receipts.certificate import dev_certificate


def _policy() -> Policy:
    return Policy.from_dict(
        {
            "version": 1,
            "name": "standalone-release",
            "tier": "structural",
            "capability": "operator_attested",
        }
    )


def test_standalone_imports_core_from_receipts_distribution() -> None:
    assert agentauth.core is not None
    assert receipts.__version__ == "0.5.1"


def test_standalone_wrapper_builds_and_verifies_receipt() -> None:
    wrapper = AgentWrapper(
        lambda item: {"decision": "approve", "fraud_score": 0.1},
        _policy(),
        mode="shadow",
        audit_db=":memory:",
    )

    result = wrapper.run({"transaction_id": "standalone-1", "amount": 1.0})
    bundle = receipts.build_receipt_bundle(result, certificate=wrapper.certificate)
    assert isinstance(receipts.verify_receipt_bundle(bundle), dict)


def test_standalone_mcp_gateway_records_plain_tool_call() -> None:
    policy = _policy()
    wrapper = AgentWrapper(
        lambda item: {"decision": "approve", "fraud_score": 0.1},
        policy,
        certificate=dev_certificate(policy.commitment(), scope=["score_transaction"]),
        mode="shadow",
        audit_db=":memory:",
    )
    gateway = ReceiptedMcpGateway(wrapper, server_name="standalone")
    gateway.register_tool("score_transaction", lambda args: {"score": 0.1})

    result = gateway.call_tool("score_transaction", {"transaction_id": "t1"})

    assert result.blocked is False
    assert result.output["result"] == {"score": 0.1}


def test_missing_capabilities_extra_is_actionable() -> None:
    if importlib.util.find_spec("agentauth.capabilities") is not None:
        pytest.skip("capabilities package is installed in this environment")

    with pytest.raises(ImportError, match=r"clayseal-receipts\[scoping\]"):
        receipts.GoalSpec
