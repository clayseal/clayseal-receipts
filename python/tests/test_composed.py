import json
from pathlib import Path

import pytest
from agentauth.receipts import Policy
from agentauth.receipts.compose import (
    ComposedBindings,
    compose_from_parts,
    prove_composed,
    verify_composed,
)
from agentauth.receipts.prover import locate_cli, prove_structural_policy

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(not locate_cli().available, reason="agent-receipts CLI not built")
def test_prove_composed_stub_roundtrip():
    output_hash = "out-composed-1"
    policy_commitment = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml").commitment()
    blob = prove_composed(
        amount=2500.0,
        fraud_score=0.25,
        policy_commitment=policy_commitment,
        model_provenance_hash="sha256:test-model",
        output_hash=output_hash,
        context_hash="ctx-1",
        allow_stub=True,
    )
    assert blob is not None
    result = verify_composed(blob, allow_stub=True)
    assert result["valid"] is True, result


@pytest.mark.skipif(not locate_cli().available, reason="agent-receipts CLI not built")
def test_prove_composed_recursive_roundtrip():
    output_hash = "out-recursive-1"
    policy_commitment = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml").commitment()
    blob = prove_composed(
        amount=2500.0,
        fraud_score=0.25,
        policy_commitment=policy_commitment,
        model_provenance_hash="sha256:test-model",
        output_hash=output_hash,
        context_hash="ctx-1",
        allow_stub=True,
        recursive=True,
    )
    assert blob is not None
    data = json.loads(blob)
    assert data["composition_id"] == "inference_and_policy_recursive_v1"
    assert data.get("recursive") is not None
    result = verify_composed(blob, allow_stub=True)
    assert result["valid"] is True, result


@pytest.mark.skipif(not locate_cli().available, reason="agent-receipts CLI not built")
def test_compose_from_policy_and_inference_parts():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    output_hash = "parts-hash"
    policy_blob = prove_structural_policy(
        policy=policy,
        output={"decision": "approve", "fraud_score": 0.1},
        policy_commitment=policy.commitment(),
        output_hash=output_hash,
    )
    assert policy_blob is not None

    from agentauth.receipts.inference import prove_inference

    inf_blob = prove_inference(
        amount=1000.0,
        model_provenance_hash="sha256:m",
        output_hash=output_hash,
        allow_stub=True,
    )
    assert inf_blob is not None

    composed = compose_from_parts(
        policy_proof=policy_blob,
        inference_proof=inf_blob,
        bindings=ComposedBindings(
            output_hash=output_hash,
            policy_commitment=policy.commitment(),
            model_provenance_hash="sha256:m",
            context_hash="ctx",
            public_score=0.1,
        ),
    )
    assert composed is not None
    data = json.loads(composed)
    assert data["composition_id"] == "inference_and_policy_v1"


def test_tee_hybrid_with_composed_proof_still_requires_tee_quote():
    from agentauth.receipts.certificate import dev_certificate
    from agentauth.receipts.compose import prove_composed
    from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof

    output_hash = "out-tee-composed"
    proof = ExecutionProof.from_action(
        dev_certificate("pol"),
        {"input": {}},
        {"decision": "approve", "fraud_score": 0.1},
        policy_satisfied=True,
        path=AttestationPath.TEE_HYBRID,
        decision_outcome=DecisionOutcome.ALLOW,
    )
    if locate_cli().available:
        composed = prove_composed(
            amount=1000.0,
            fraud_score=0.1,
            policy_commitment="pol",
            model_provenance_hash="model",
            output_hash=output_hash,
            context_hash="ctx",
            allow_stub=True,
        )
        if composed is not None:
            proof.bundle.composed_proof = composed
    else:
        proof.bundle.composed_proof = b"{}"

    result = proof.verify()
    assert result["valid"] is False
    assert any("no tee_quote" in reason for reason in result["reasons"])


def test_prove_composed_requires_policy_numeric_range():
    from agentauth.receipts.policy import NumericRange, Policy, PolicyCapability, PolicyTier

    policy = Policy(
        version=1,
        name="no-range",
        tier=PolicyTier.STRUCTURAL,
        capability=PolicyCapability.FULLY_PROVEN,
        numeric_ranges=[],
        output_schema_required=["decision", "fraud_score"],
    )
    with pytest.raises(ValueError, match="numeric_ranges"):
        prove_composed(
            amount=1000.0,
            fraud_score=0.5,
            policy_commitment=policy.commitment(),
            model_provenance_hash="sha256:m",
            output_hash="out",
            context_hash="ctx",
            policy=policy,
            allow_stub=True,
        )


@pytest.mark.skipif(not locate_cli().available, reason="agent-receipts CLI not built")
def test_prove_composed_uses_policy_numeric_range():
    from agentauth.receipts.policy import NumericRange, Policy, PolicyCapability, PolicyTier

    policy = Policy(
        version=1,
        name="narrow-range",
        tier=PolicyTier.STRUCTURAL,
        capability=PolicyCapability.FULLY_PROVEN,
        numeric_ranges=[NumericRange(field="fraud_score", min=0.2, max=0.8)],
        output_schema_required=["decision", "fraud_score"],
    )
    blob = prove_composed(
        amount=1000.0,
        fraud_score=0.5,
        policy_commitment=policy.commitment(),
        model_provenance_hash="sha256:m",
        output_hash="out-range",
        context_hash="ctx",
        policy=policy,
        allow_stub=True,
    )
    assert blob is not None
    data = json.loads(blob)
    min_scaled = int(data["policy"]["public_inputs"][1])
    max_plus_one = int(data["policy"]["public_inputs"][2])
    assert min_scaled == 200_000
    assert max_plus_one == 800_001
