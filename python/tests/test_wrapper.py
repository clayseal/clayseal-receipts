from pathlib import Path

import pytest

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.authority_binding import AuthorityBinding
from agentauth.core.hash_util import hash_canonical_json
from agentauth.receipts.policy import NumericRange, PolicyCapability, PolicyTier
from agentauth.core.runtime import ActionDescriptor, SideEffectLevel

ROOT = Path(__file__).resolve().parents[2]


def test_shadow_run_appends_audit():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")

    def model(inp: dict) -> dict:
        return {"decision": "approve", "fraud_score": 0.01}

    agent = AgentWrapper(
        model=model,
        policy=policy,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "x"})
    assert result.output["decision"] == "approve"
    assert result.decision_outcome.value == "allow"
    assert result.authority_version == 1
    assert result.session_id is None
    assert result.proof.verify()["valid"] is False  # shadow
    assert len(agent.audit) == 1
    agent.audit.verify_chain()


def test_structured_action_is_captured_in_execution_context():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.25},
        policy=policy,
        mode="shadow",
        audit_db=":memory:",
    )
    action = ActionDescriptor(
        action_name="cloud.deploy",
        action_category="deployment",
        resource_type="service",
        resource_ref="payments-api",
        side_effect_level=SideEffectLevel.PRIVILEGED_MUTATION,
    )
    result = agent.run({"release_id": "r1"}, action=action, session_id="sess-structured")
    assert result.execution_context.action.action_name == "cloud.deploy"
    assert result.execution_context.action.action_category == "deployment"
    assert result.execution_context.authority.session_id == "sess-structured"
    assert result.audit_record.action == "cloud.deploy"


def test_wrapper_accepts_authority_binding_directly():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.15},
        policy=policy,
        mode="shadow",
        audit_db=":memory:",
    )
    binding = AuthorityBinding.from_agentauth_credential(
        {
            "agent_id": "agent-123",
            "spiffe_id": "spiffe://agentauth.io/customer/acme/agent/researcher",
            "agent_type": "researcher",
            "owner": "alice@acme.ai",
            "scopes": ["db:read", "web:*"],
            "selectors": ["k8s:ns:customer-acme", "k8s:sa:researcher"],
            "expires_at": "2026-06-20T00:00:00Z",
            "capabilities": [
                {"resource": "db", "action": "read"},
                {"resource": "web", "action": "*"},
            ],
            "biscuit": "cap-token",
            "bound_keyhash": "bound-hash",
        }
    )

    result = agent.run(
        {"transaction_id": "t-auth", "amount": 10.0},
        action=ActionDescriptor(
            action_name="read",
            action_category="data",
            resource_type="db",
            resource_ref="db://primary",
            side_effect_level=SideEffectLevel.READ_ONLY,
        ),
        session_id="sess-auth",
        authority_version=4,
        authority_binding=binding,
    )

    authority = result.execution_context.authority
    assert authority.authority_id == "agent-123"
    assert authority.subject_id == "spiffe://agentauth.io/customer/acme/agent/researcher"
    assert authority.tenant_id == "acme"
    assert authority.owner_ref == "alice@acme.ai"
    assert authority.capabilities == ["db:read", "web:*"]
    assert authority.capability_rules == [
        {"resource": "db", "action": "read"},
        {"resource": "web", "action": "*"},
    ]
    assert authority.proof_of_possession is True
    assert authority.trust_tier == "sender_constrained"
    assert authority.session_id == "sess-auth"
    assert authority.authority_version == 4


def test_non_shadow_mode_requires_explicit_certificate():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    with pytest.raises(ValueError, match="non-shadow operating modes require an explicit"):
        AgentWrapper(
            model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
            policy=policy,
            mode="prove",
            audit_db=":memory:",
        )


def test_wrapper_passes_recursive_flag_to_prove_composed(monkeypatch):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    from agentauth.receipts.certificate import dev_certificate

    cert = dev_certificate(policy.commitment())
    captured: dict[str, bool] = {}

    def fake_prove_composed(**kwargs):
        captured["recursive"] = kwargs.get("recursive", False)
        return b'{"composition_id":"test"}'

    monkeypatch.setattr("agentauth.receipts.compose.prove_composed", fake_prove_composed)

    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1, "amount": 50.0},
        policy=policy,
        certificate=cert,
        mode="prove",
        prove_composed=True,
        prove_recursive=True,
        audit_db=":memory:",
    )
    agent.run({"transaction_id": "t1", "amount": 50.0})
    assert captured.get("recursive") is True


def test_wrapper_passes_inference_backend(monkeypatch):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    from agentauth.receipts.certificate import dev_certificate

    cert = dev_certificate(policy.commitment())
    captured: dict[str, str] = {}

    def fake_prove_inference(**kwargs):
        captured["backend"] = kwargs.get("backend", "ezkl")
        return b'{"backend":"risc0"}'

    monkeypatch.setattr("agentauth.receipts.wrapper.prove_structural_policy", lambda **_: b"{}")
    monkeypatch.setattr("agentauth.receipts.inference.prove_inference", fake_prove_inference)

    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1, "amount": 50.0},
        policy=policy,
        certificate=cert,
        mode="prove",
        prove_composed=False,
        prove_policy=True,
        prove_inference=True,
        inference_backend="risc0",
        audit_db=":memory:",
    )
    agent.run({"transaction_id": "t1", "amount": 50.0})
    assert captured.get("backend") == "risc0"


def test_bounded_auto_blocks_arbitrary_output_schema():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    from agentauth.receipts.certificate import dev_certificate

    cert = dev_certificate(policy.commitment())
    original = {"tool_result": "wire-transfer-started", "fraud_score": 2.0}
    agent = AgentWrapper(
        model=lambda inp: dict(original),
        policy=policy,
        certificate=cert,
        mode="bounded_auto",
        audit_db=":memory:",
    )

    result = agent.run({"transaction_id": "t1", "amount": 50.0})

    assert result.decision_outcome.value == "deny"
    assert result.output == {
        "decision": "abstain",
        "abstain_reason": "policy_violation",
        "blocked": True,
        "original_output_hash": hash_canonical_json(original),
    }


def test_caller_declared_high_trust_tier_does_not_satisfy_policy():
    policy = Policy(
        version=1,
        name="requires_verified_trust",
        tier=PolicyTier.STRUCTURAL,
        capability=PolicyCapability.FULLY_PROVEN,
        min_trust_tier="zk_execution_proved",
    )
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve"},
        policy=policy,
        mode="shadow",
        audit_db=":memory:",
    )

    result = agent.record(
        action="agent.run",
        context={
            "input": {"transaction_id": "t1"},
            "authority": {
                "authority_id": "caller-controlled",
                "trust_tier": "zk_execution_proved",
                "evidence_verified": True,
            },
        },
        output={"decision": "approve"},
    )

    assert result.policy_satisfied is False
    assert any(
        "not backed by verified identity evidence" in item for item in result.policy_violations
    )


def test_verified_agentauth_binding_satisfies_sender_constrained_policy():
    policy = Policy(
        version=1,
        name="requires_sender_constrained",
        tier=PolicyTier.STRUCTURAL,
        capability=PolicyCapability.FULLY_PROVEN,
        min_trust_tier="sender_constrained",
    )
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve"},
        policy=policy,
        mode="shadow",
        audit_db=":memory:",
    )
    binding = AuthorityBinding.from_agentauth_credential(
        {
            "agent_id": "agent-123",
            "spiffe_id": "spiffe://agentauth.io/customer/acme/agent/researcher",
            "scopes": ["db:read"],
            "capabilities": [{"resource": "db", "action": "read"}],
            "biscuit": "cap-token",
            "bound_keyhash": "bound-hash",
        }
    )

    result = agent.record(
        action=ActionDescriptor(
            action_name="read",
            action_category="data",
            resource_type="db",
            side_effect_level=SideEffectLevel.READ_ONLY,
        ),
        context={"input": {"transaction_id": "t1"}},
        output={"decision": "approve"},
        authority_binding=binding,
    )

    assert result.policy_satisfied is True


def test_prove_mode_raises_when_requested_policy_proof_is_missing(monkeypatch):
    policy = Policy(
        version=1,
        name="requires_policy_proof",
        tier=PolicyTier.STRUCTURAL,
        capability=PolicyCapability.FULLY_PROVEN,
        numeric_ranges=[NumericRange(field="fraud_score", min=0.0, max=1.0)],
    )
    from agentauth.receipts.certificate import dev_certificate

    cert = dev_certificate(policy.commitment())
    monkeypatch.setattr("agentauth.receipts.wrapper.prove_structural_policy", lambda **_: None)
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.1},
        policy=policy,
        certificate=cert,
        mode="prove",
        prove_composed=False,
        prove_policy=True,
        prove_inference=False,
        audit_db=":memory:",
    )

    with pytest.raises(RuntimeError, match="no policy proof was produced"):
        agent.run({"transaction_id": "t1", "amount": 50.0})
