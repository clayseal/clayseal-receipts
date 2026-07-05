use agent_receipts_policy_circuit::{
    envelope_from_json as policy_from_json, verify_policy_range, PolicyProofEnvelope,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::inference::{
    verify_inference_envelope, InferenceProofEnvelope, InferenceProofError,
};

#[derive(Debug, Error)]
pub enum ComposedProofError {
    #[error("policy: {0}")]
    Policy(String),
    #[error("inference: {0}")]
    Inference(#[from] InferenceProofError),
    #[error("binding: {0}")]
    Binding(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ComposedBindings {
    pub output_hash: String,
    pub policy_commitment: String,
    pub model_provenance_hash: String,
    pub context_hash: String,
    /// Expected fraud_score in agent output (binds inference public score to policy check).
    pub public_score: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ComposedProofEnvelope {
    pub version: u32,
    pub composition_id: String,
    pub bindings: ComposedBindings,
    pub policy: PolicyProofEnvelope,
    pub inference: InferenceProofEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recursive: Option<crate::recursive::RecursiveCompositionProof>,
}

impl ComposedProofEnvelope {
    pub const COMPOSITION_ID: &'static str = "inference_and_policy_v1";
}

pub fn compose_proofs(
    policy: PolicyProofEnvelope,
    inference: InferenceProofEnvelope,
    bindings: ComposedBindings,
) -> ComposedProofEnvelope {
    ComposedProofEnvelope {
        version: 1,
        composition_id: ComposedProofEnvelope::COMPOSITION_ID.to_string(),
        bindings,
        policy,
        inference,
        recursive: None,
    }
}

pub fn verify_composed(
    envelope: &ComposedProofEnvelope,
    allow_stub_inference: bool,
) -> Result<bool, ComposedProofError> {
    if envelope.composition_id == crate::recursive::COMPOSITION_ID_RECURSIVE {
        let recursive = envelope.recursive.as_ref().ok_or_else(|| {
            ComposedProofError::Binding("recursive composition missing recursive proof".into())
        })?;
        return crate::recursive::verify_recursive_composition(
            envelope,
            recursive,
            allow_stub_inference,
        );
    }

    if envelope.composition_id != ComposedProofEnvelope::COMPOSITION_ID {
        return Err(ComposedProofError::Binding(format!(
            "unknown composition_id {}",
            envelope.composition_id
        )));
    }
    if envelope.recursive.is_some() {
        return Err(ComposedProofError::Binding(
            "logical composition_id must not include recursive proof".into(),
        ));
    }

    verify_bindings(envelope)?;
    verify_policy_range(&envelope.policy).map_err(|e| ComposedProofError::Policy(e.to_string()))?;
    verify_inference_envelope(&envelope.inference, allow_stub_inference)?;

    Ok(true)
}

pub(crate) fn verify_bindings(envelope: &ComposedProofEnvelope) -> Result<(), ComposedProofError> {
    let b = &envelope.bindings;
    if envelope.policy.output_hash != b.output_hash {
        return Err(ComposedProofError::Binding(
            "policy.output_hash != bindings.output_hash".into(),
        ));
    }
    if envelope.inference.output_hash != b.output_hash {
        return Err(ComposedProofError::Binding(
            "inference.output_hash != bindings.output_hash".into(),
        ));
    }
    if envelope.policy.policy_commitment != b.policy_commitment {
        return Err(ComposedProofError::Binding(
            "policy.policy_commitment != bindings.policy_commitment".into(),
        ));
    }
    if envelope.inference.model_provenance_hash != b.model_provenance_hash {
        return Err(ComposedProofError::Binding(
            "inference.model_provenance_hash != bindings.model_provenance_hash".into(),
        ));
    }
    let score_diff = (envelope.inference.public_score - b.public_score).abs();
    if score_diff > 1e-6 {
        return Err(ComposedProofError::Binding(format!(
            "inference.public_score {} != bindings.public_score {}",
            envelope.inference.public_score, b.public_score
        )));
    }
    let policy_scaled: u64 = envelope
        .policy
        .public_inputs
        .first()
        .ok_or_else(|| ComposedProofError::Binding("policy missing public score".into()))?
        .parse()
        .map_err(|_| ComposedProofError::Binding("policy scaled score parse error".into()))?;
    let scaled = (b.public_score * 1_000_000.0).round() as u64;
    if scaled != policy_scaled {
        return Err(ComposedProofError::Binding(format!(
            "policy scaled score {policy_scaled} != inference scaled {scaled}"
        )));
    }
    Ok(())
}

pub fn verify_execution_bindings(
    envelope: &ComposedProofEnvelope,
    expected_context_hash: &str,
) -> Result<(), ComposedProofError> {
    verify_bindings(envelope)?;
    if envelope.bindings.context_hash != expected_context_hash {
        return Err(ComposedProofError::Binding(
            "bindings.context_hash != expected execution context hash".into(),
        ));
    }
    Ok(())
}

pub fn composed_to_json(envelope: &ComposedProofEnvelope) -> Result<String, serde_json::Error> {
    serde_json::to_string(envelope)
}

pub fn composed_from_json(json: &str) -> Result<ComposedProofEnvelope, serde_json::Error> {
    serde_json::from_str(json)
}

pub fn compose_from_json_parts(
    policy_json: &str,
    inference_json: &str,
    bindings: ComposedBindings,
) -> Result<ComposedProofEnvelope, ComposedProofError> {
    let policy: PolicyProofEnvelope = policy_from_json(policy_json)?;
    let inference: InferenceProofEnvelope = serde_json::from_str(inference_json)?;
    Ok(compose_proofs(policy, inference, bindings))
}

#[cfg(test)]
mod tests {
    use agent_receipts_policy_circuit::prove_policy_range;
    use serde_json::json;

    use super::*;
    use crate::inference::{prove_inference_ezkl, InferenceAttestation};

    fn sample_output(score: f64) -> serde_json::Value {
        json!({"decision": "approve", "fraud_score": score})
    }

    #[test]
    fn bindings_reject_mismatched_context_hash() {
        let out = sample_output(0.25);
        let policy = prove_policy_range(0.25, 0.0, 1.0, "pol", "out-a", &[], &out).unwrap();
        let inference = prove_inference_ezkl(2500.0, "model", "out-a", true).unwrap();
        let bindings = ComposedBindings {
            output_hash: "out-a".into(),
            policy_commitment: "pol".into(),
            model_provenance_hash: "model".into(),
            context_hash: "ctx-wrong".into(),
            public_score: inference.public_score,
        };
        let composed = compose_proofs(policy, inference, bindings);
        assert!(verify_composed(&composed, true).is_ok());
        assert!(verify_execution_bindings(&composed, "ctx-expected").is_err());
    }

    #[test]
    fn bindings_reject_mismatched_output_hash() {
        let out = sample_output(0.25);
        let policy = prove_policy_range(0.25, 0.0, 1.0, "pol", "out-a", &[], &out).unwrap();
        let inference = prove_inference_ezkl(2500.0, "model", "out-b", true).unwrap();
        let bindings = ComposedBindings {
            output_hash: "out-a".into(),
            policy_commitment: "pol".into(),
            model_provenance_hash: "model".into(),
            context_hash: "ctx".into(),
            public_score: inference.public_score,
        };
        let composed = compose_proofs(policy, inference, bindings);
        assert!(verify_composed(&composed, true).is_err());
    }

    #[test]
    fn composed_accepts_stub_inference_and_policy() {
        let output_hash = "deadbeef";
        let out = sample_output(0.25);
        let required = vec!["decision".into(), "fraud_score".into()];
        let policy = prove_policy_range(
            0.25,
            0.0,
            1.0,
            "pol",
            output_hash,
            &required,
            &out,
        )
        .unwrap();
        let inference = prove_inference_ezkl(2500.0, "model", output_hash, true).unwrap();
        assert_eq!(inference.attestation, InferenceAttestation::Stub);
        let bindings = ComposedBindings {
            output_hash: output_hash.into(),
            policy_commitment: "pol".into(),
            model_provenance_hash: "model".into(),
            context_hash: "ctx".into(),
            public_score: 0.25,
        };
        let composed = compose_proofs(policy, inference, bindings);
        assert!(verify_composed(&composed, true).unwrap());
    }
}
