from uuid import uuid4

import pytest

from agentauth.receipts import (
    issue_delegation,
    mcp_tool_capability,
    sign_delegation,
    verify_delegation_chain,
    verify_delegation_envelope,
)
from agentauth.core.signing import generate_keypair


def test_delegation_scope_must_shrink():
    parent = issue_delegation(
        None,
        delegate_agent_id=uuid4(),
        capabilities=[
            mcp_tool_capability("score_transaction"),
            mcp_tool_capability("fetch_customer_profile"),
        ],
    )
    child = issue_delegation(
        parent,
        delegate_agent_id=uuid4(),
        capabilities=[mcp_tool_capability("score_transaction")],
    )
    assert child.depth == 1
    assert verify_delegation_chain(child, tool_name="score_transaction") == []

    with pytest.raises(ValueError, match="exceed parent"):
        issue_delegation(
            parent,
            delegate_agent_id=uuid4(),
            capabilities=[
                mcp_tool_capability("score_transaction"),
                mcp_tool_capability("transfer_funds"),
            ],
        )


def test_delegation_denies_tool_outside_scope():
    token = issue_delegation(
        None,
        delegate_agent_id=uuid4(),
        capabilities=[mcp_tool_capability("score_transaction")],
    )
    violations = verify_delegation_chain(token, tool_name="fetch_customer_profile")
    assert any("delegation capabilities" in v for v in violations)


def test_signed_delegation_roundtrip():
    key = generate_keypair()
    token = issue_delegation(
        None,
        delegate_agent_id=uuid4(),
        capabilities=[mcp_tool_capability("score_transaction")],
    )
    envelope = sign_delegation(token, key)
    assert verify_delegation_envelope(envelope) == []
    assert (
        verify_delegation_chain(
            token,
            tool_name="score_transaction",
            signed_envelope=envelope,
            require_signature=True,
        )
        == []
    )


def test_unsigned_delegation_rejected_when_signature_required():
    token = issue_delegation(
        None,
        delegate_agent_id=uuid4(),
        capabilities=[mcp_tool_capability("score_transaction")],
    )
    violations = verify_delegation_chain(token, require_signature=True)
    assert any("not cryptographically signed" in item for item in violations)
