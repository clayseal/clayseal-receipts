"""End-to-end prove mode when CLI is built into ./target/release."""

from pathlib import Path

import pytest

from agentauth.receipts import AgentWrapper, Policy, locate_cli
from agentauth.receipts.certificate import dev_certificate

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "target" / "release" / "agent-receipts"


@pytest.mark.skipif(not CLI.is_file(), reason="release CLI not built in ./target")
def test_prove_mode_execution_proof_records_dev_stub_as_shadow(allow_stub_proofs):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")

    def model(inp: dict) -> dict:
        return {"decision": "approve", "fraud_score": 0.25}

    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=model,
        policy=policy,
        certificate=cert,
        mode="prove",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 2500.0})
    assert result.proof.bundle.composed_proof or result.proof.bundle.policy_proof
    verification = result.proof.verify()
    if result.proof.attestation_path.value == "shadow":
        assert verification["valid"] is False
        assert any("shadow mode" in reason for reason in verification["reasons"])
    else:
        assert verification["valid"] is True, verification


@pytest.mark.skipif(not CLI.is_file(), reason="release CLI not built in ./target")
def test_prove_mode_policy_only_when_composed_disabled(allow_stub_proofs):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")

    def model(inp: dict) -> dict:
        return {"decision": "approve", "fraud_score": 0.1}

    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=model,
        policy=policy,
        certificate=cert,
        mode="prove",
        prove_composed=False,
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 50.0})
    assert result.proof.bundle.policy_proof
    verification = result.proof.verify()
    assert verification["valid"] is False
    assert any(
        "inference_proof" in reason or "composed_proof" in reason
        for reason in verification["reasons"]
    )


@pytest.mark.skipif(not CLI.is_file(), reason="release CLI not built in ./target")
def test_locate_cli_prefers_project_target():
    status = locate_cli()
    assert status.available
    assert status.binary is not None
    assert "agent-receipts/target" in status.binary or status.binary.endswith("agent-receipts")
