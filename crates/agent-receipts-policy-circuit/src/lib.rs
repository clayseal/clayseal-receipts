//! Halo2 policy-range circuit (v3): proves `min <= score < max` on fixed-point scalars,
//! binds the committed output and policy as public inputs, and proves required-field presence.

pub mod circuit;
pub mod confidential;
pub mod keys;

use ff::{Field, FromUniformBytes};
use halo2_proofs::{
    plonk::{create_proof, verify_proof, SingleVerifier},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{pallas::Base as Fp, EqAffine};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Derive a field-element commitment from an arbitrary string (sha256 → uniform field).
///
/// Used to bind `output_hash` and `policy_commitment` into the policy proof's public
/// inputs. The verifier recomputes this from the envelope, so editing either metadata
/// field after proving breaks the instance match.
pub fn commitment_to_field(value: &str) -> Fp {
    let digest = Sha256::digest(value.as_bytes());
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&digest);
    Fp::from_uniform_bytes(&wide)
}

pub use circuit::{scale_f64, PolicyRangeCircuit, K, MAX_REQUIRED_FIELDS, NUM_BITS, SCALE};
pub use confidential::{
    field_from_hex, field_to_hex, score_commitment, ConfidentialPolicyCircuit, CONF_K,
};
pub use keys::{
    keys_path, load_or_setup, load_or_setup_confidential, setup_policy_range_keys,
    ConfidentialKeys, PolicyRangeKeys,
};

#[derive(Debug, Error)]
pub enum PolicyProofError {
    #[error("proving failed: {0}")]
    Prove(String),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("invalid envelope: {0}")]
    Envelope(String),
    #[error("range check failed: {0}")]
    Range(String),
}

/// Serialized proof artifact exchanged with the Python SDK.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyProofEnvelope {
    pub version: u32,
    pub circuit_id: String,
    pub policy_commitment: String,
    pub output_hash: String,
    /// [score_scaled, min_scaled, max_plus_one, required_presence_mask]
    pub public_inputs: Vec<String>,
    #[serde(default)]
    pub required_fields: Vec<String>,
    pub proof_hex: String,
}

impl PolicyProofEnvelope {
    pub const CIRCUIT_ID: &'static str = "policy_range_v3";
}

pub fn check_range(score: f64, min: f64, max: f64) -> Result<(), PolicyProofError> {
    if score < min || score > max {
        return Err(PolicyProofError::Range(format!(
            "score {score} not in [{min}, {max}]"
        )));
    }
    let score_s = scale_f64(score);
    let min_s = scale_f64(min);
    let max_s = scale_f64(max);
    if score_s < min_s || score_s > max_s {
        return Err(PolicyProofError::Range(format!(
            "scaled score {score_s} not in [{min_s}, {max_s}]"
        )));
    }
    Ok(())
}

/// Verify required fields are present in output and return the in-circuit presence mask.
pub fn required_presence_mask(
    required: &[String],
    output: &Value,
) -> Result<u64, PolicyProofError> {
    if required.len() > MAX_REQUIRED_FIELDS {
        return Err(PolicyProofError::Range(format!(
            "too many required fields (max {MAX_REQUIRED_FIELDS})"
        )));
    }
    let obj = output.as_object().ok_or_else(|| {
        PolicyProofError::Range("output must be a JSON object for required-field check".into())
    })?;
    for req in required {
        if !obj.contains_key(req) {
            return Err(PolicyProofError::Range(format!(
                "missing required field: {req}"
            )));
        }
    }
    Ok(if required.is_empty() {
        0
    } else {
        (1u64 << required.len()) - 1
    })
}

pub fn prove_policy_range(
    score: f64,
    min: f64,
    max: f64,
    policy_commitment: &str,
    output_hash: &str,
    required_fields: &[String],
    output: &Value,
) -> Result<PolicyProofEnvelope, PolicyProofError> {
    check_range(score, min, max)?;
    let mask = required_presence_mask(required_fields, output)?;
    let keys = load_or_setup().map_err(PolicyProofError::Prove)?;
    let circuit = PolicyRangeCircuit::from_range(score, min, max)
        .bind(
            commitment_to_field(output_hash),
            commitment_to_field(policy_commitment),
        )
        .with_required_fields(required_fields.len() as u8, mask);
    let public_inputs = circuit.public_inputs();
    let public_input_strings = vec![
        circuit.score.to_string(),
        circuit.min_scaled.to_string(),
        circuit.max_plus_one.to_string(),
        mask.to_string(),
    ];
    let instance_refs: Vec<&[Fp]> = public_inputs.iter().map(|col| col.as_slice()).collect();

    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof(
        &keys.params,
        &keys.pk,
        &[circuit],
        &[&instance_refs],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| PolicyProofError::Prove(format!("{e:?}")))?;

    Ok(PolicyProofEnvelope {
        version: 1,
        circuit_id: PolicyProofEnvelope::CIRCUIT_ID.to_string(),
        policy_commitment: policy_commitment.to_string(),
        output_hash: output_hash.to_string(),
        public_inputs: public_input_strings,
        required_fields: required_fields.to_vec(),
        proof_hex: hex::encode(transcript.finalize()),
    })
}

pub fn verify_policy_range(envelope: &PolicyProofEnvelope) -> Result<bool, PolicyProofError> {
    if envelope.circuit_id != PolicyProofEnvelope::CIRCUIT_ID {
        return Err(PolicyProofError::Envelope(format!(
            "unknown circuit_id {}",
            envelope.circuit_id
        )));
    }
    if envelope.public_inputs.len() != 4 {
        return Err(PolicyProofError::Envelope(
            "expected four public inputs (score, min, max_plus_one, required_presence_mask)".into(),
        ));
    }
    let score_scaled: u64 = envelope.public_inputs[0]
        .parse()
        .map_err(|e: std::num::ParseIntError| PolicyProofError::Envelope(e.to_string()))?;
    let min_scaled: u64 = envelope.public_inputs[1]
        .parse()
        .map_err(|e: std::num::ParseIntError| PolicyProofError::Envelope(e.to_string()))?;
    let max_plus_one: u64 = envelope.public_inputs[2]
        .parse()
        .map_err(|e: std::num::ParseIntError| PolicyProofError::Envelope(e.to_string()))?;
    let required_presence_mask: u64 = envelope.public_inputs[3]
        .parse()
        .map_err(|e: std::num::ParseIntError| PolicyProofError::Envelope(e.to_string()))?;

    if score_scaled < min_scaled || score_scaled > max_plus_one.saturating_sub(1) {
        return Err(PolicyProofError::Range(format!(
            "public inputs violate range: score={score_scaled}, min={min_scaled}, max_exclusive={}",
            max_plus_one.saturating_sub(1)
        )));
    }
    if max_plus_one <= min_scaled {
        return Err(PolicyProofError::Range(
            "max_plus_one must be greater than min_scaled".into(),
        ));
    }

    let expected_count = envelope.required_fields.len();
    if expected_count > MAX_REQUIRED_FIELDS {
        return Err(PolicyProofError::Envelope(format!(
            "too many required_fields (max {MAX_REQUIRED_FIELDS})"
        )));
    }
    let expected_mask = if expected_count == 0 {
        0
    } else {
        (1u64 << expected_count) - 1
    };
    if required_presence_mask != expected_mask {
        return Err(PolicyProofError::Range(format!(
            "required_presence_mask {required_presence_mask} != expected {expected_mask} for {} fields",
            expected_count
        )));
    }

    let keys = load_or_setup().map_err(PolicyProofError::Verify)?;
    let public_inputs = vec![
        vec![Fp::from(score_scaled)],
        vec![Fp::from(min_scaled)],
        vec![Fp::from(max_plus_one)],
        vec![commitment_to_field(&envelope.output_hash)],
        vec![commitment_to_field(&envelope.policy_commitment)],
        vec![Fp::from(required_presence_mask)],
    ];
    let instance_refs: Vec<&[Fp]> = public_inputs.iter().map(|col| col.as_slice()).collect();

    let proof_bytes =
        hex::decode(&envelope.proof_hex).map_err(|e| PolicyProofError::Envelope(e.to_string()))?;

    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof_bytes.as_slice());
    let strategy = SingleVerifier::new(&keys.params);
    verify_proof(
        &keys.params,
        &keys.vk,
        strategy,
        &[&instance_refs],
        &mut transcript,
    )
    .map_err(|e| PolicyProofError::Verify(format!("{e:?}")))?;
    Ok(true)
}

/// Confidential policy proof: proves `min <= score < max` over a **hidden** score,
/// revealing only a Poseidon commitment to it (SOTA-9).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ConfidentialPolicyProofEnvelope {
    pub version: u32,
    pub circuit_id: String,
    pub policy_commitment: String,
    pub output_hash: String,
    /// Poseidon commitment to the hidden scaled score (hex field element).
    pub score_commitment: String,
    pub min_scaled: u64,
    pub max_plus_one: u64,
    pub proof_hex: String,
}

impl ConfidentialPolicyProofEnvelope {
    pub const CIRCUIT_ID: &'static str = "policy_range_confidential_v1";
}

/// Prove a range policy over a private score. `blinding` defaults to a fresh random value
/// (hiding); pass `Some(_)` only for deterministic tests or when re-deriving a commitment.
pub fn prove_policy_range_confidential(
    score: f64,
    min: f64,
    max: f64,
    policy_commitment: &str,
    output_hash: &str,
    blinding: Option<Fp>,
) -> Result<ConfidentialPolicyProofEnvelope, PolicyProofError> {
    check_range(score, min, max)?;
    let blinding = blinding.unwrap_or_else(|| Fp::random(OsRng));
    let circuit = ConfidentialPolicyCircuit::new(
        score,
        min,
        max,
        blinding,
        commitment_to_field(output_hash),
        commitment_to_field(policy_commitment),
    );
    let commitment = score_commitment(circuit.score, blinding);
    let min_scaled = circuit.min_scaled;
    let max_plus_one = circuit.max_plus_one;

    let keys = load_or_setup_confidential().map_err(PolicyProofError::Prove)?;
    let public = circuit.public_inputs();
    let instance_refs: Vec<&[Fp]> = public.iter().map(|col| col.as_slice()).collect();

    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof(
        &keys.params,
        &keys.pk,
        &[circuit],
        &[&instance_refs],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| PolicyProofError::Prove(format!("{e:?}")))?;

    Ok(ConfidentialPolicyProofEnvelope {
        version: 1,
        circuit_id: ConfidentialPolicyProofEnvelope::CIRCUIT_ID.to_string(),
        policy_commitment: policy_commitment.to_string(),
        output_hash: output_hash.to_string(),
        score_commitment: field_to_hex(commitment),
        min_scaled,
        max_plus_one,
        proof_hex: hex::encode(transcript.finalize()),
    })
}

/// Verify a confidential policy proof. The verifier never learns the score — only that the
/// hidden value committed in `score_commitment` lies in `[min_scaled, max_plus_one)`.
pub fn verify_policy_range_confidential(
    envelope: &ConfidentialPolicyProofEnvelope,
) -> Result<bool, PolicyProofError> {
    if envelope.circuit_id != ConfidentialPolicyProofEnvelope::CIRCUIT_ID {
        return Err(PolicyProofError::Envelope(format!(
            "unknown circuit_id {}",
            envelope.circuit_id
        )));
    }
    if envelope.max_plus_one <= envelope.min_scaled {
        return Err(PolicyProofError::Range(
            "max_plus_one must be greater than min_scaled".into(),
        ));
    }
    let commitment =
        field_from_hex(&envelope.score_commitment).map_err(PolicyProofError::Envelope)?;
    let keys = load_or_setup_confidential().map_err(PolicyProofError::Verify)?;
    let public = vec![
        vec![commitment],
        vec![Fp::from(envelope.min_scaled)],
        vec![Fp::from(envelope.max_plus_one)],
        vec![commitment_to_field(&envelope.output_hash)],
        vec![commitment_to_field(&envelope.policy_commitment)],
    ];
    let instance_refs: Vec<&[Fp]> = public.iter().map(|col| col.as_slice()).collect();

    let proof_bytes =
        hex::decode(&envelope.proof_hex).map_err(|e| PolicyProofError::Envelope(e.to_string()))?;
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof_bytes.as_slice());
    let strategy = SingleVerifier::new(&keys.params);
    verify_proof(
        &keys.params,
        &keys.vk,
        strategy,
        &[&instance_refs],
        &mut transcript,
    )
    .map_err(|e| PolicyProofError::Verify(format!("{e:?}")))?;
    Ok(true)
}

pub fn envelope_to_json(envelope: &PolicyProofEnvelope) -> Result<String, serde_json::Error> {
    serde_json::to_string(envelope)
}

pub fn envelope_from_json(json: &str) -> Result<PolicyProofEnvelope, serde_json::Error> {
    serde_json::from_str(json)
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;
    use serde_json::json;

    use super::*;

    #[test]
    fn mock_prover_accepts_in_range_score() {
        let circuit = PolicyRangeCircuit::from_range(0.42, 0.0, 1.0);
        let public = circuit.public_inputs();
        let prover = MockProver::run(K, &circuit, public).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn mock_prover_accepts_required_field_mask() {
        let circuit = PolicyRangeCircuit::from_range(0.42, 0.0, 1.0).with_required_fields(2, 0b11);
        let public = circuit.public_inputs();
        let prover = MockProver::run(K, &circuit, public).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn mock_prover_rejects_incomplete_required_field_mask() {
        let circuit = PolicyRangeCircuit::from_range(0.42, 0.0, 1.0).with_required_fields(2, 0b01);
        let public = circuit.public_inputs();
        let prover = MockProver::run(K, &circuit, public).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn mock_prover_rejects_out_of_range_score() {
        let circuit = PolicyRangeCircuit::from_range(1.0, 0.0, 0.5);
        let public = circuit.public_inputs();
        let prover = MockProver::run(K, &circuit, public).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn prove_rejects_out_of_range_before_proving() {
        let out = json!({"decision": "approve", "fraud_score": 0.2});
        let err = prove_policy_range(1.5, 0.0, 1.0, "p", "o", &[], &out).unwrap_err();
        assert!(matches!(err, PolicyProofError::Range(_)));
    }

    #[test]
    fn prove_rejects_missing_required_field() {
        let out = json!({"decision": "approve"});
        let required = vec!["decision".into(), "fraud_score".into()];
        let err = prove_policy_range(0.42, 0.0, 1.0, "p", "o", &required, &out).unwrap_err();
        assert!(matches!(err, PolicyProofError::Range(_)));
    }

    #[test]
    #[ignore = "expensive Halo2 proof generation; run with `cargo test -p agent-receipts-policy-circuit -- --ignored`"]
    fn prove_verify_roundtrip() {
        let out = json!({"decision": "approve", "fraud_score": 0.42});
        let required = vec!["decision".into(), "fraud_score".into()];
        let env = prove_policy_range(0.42, 0.0, 1.0, "pol", "out", &required, &out).unwrap();
        assert!(verify_policy_range(&env).unwrap());
        assert_eq!(env.public_inputs[3], "3");
    }

    #[test]
    #[ignore = "expensive Halo2 proof generation; run with `cargo test -p agent-receipts-policy-circuit -- --ignored`"]
    fn confidential_prove_verify_roundtrip_hides_score() {
        let env = prove_policy_range_confidential(0.42, 0.0, 1.0, "pol", "out", None).unwrap();
        assert!(verify_policy_range_confidential(&env).unwrap());
        // The score appears nowhere in the envelope — only its commitment.
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("score_commitment"));
        assert!(!json.contains("\"420000\""));
        assert!(!json.contains("score_scaled"));
    }

    #[test]
    #[ignore = "expensive Halo2 proof generation; run with `cargo test -p agent-receipts-policy-circuit -- --ignored`"]
    fn confidential_verify_rejects_tampered_commitment() {
        let mut env = prove_policy_range_confidential(0.42, 0.0, 1.0, "pol", "out", None).unwrap();
        // Swap in a commitment to a different score: proof no longer matches.
        env.score_commitment = field_to_hex(score_commitment(900_000, Fp::from(1u64)));
        assert!(verify_policy_range_confidential(&env).is_err());
    }

    #[test]
    #[ignore = "expensive Halo2 proof generation; run with `cargo test -p agent-receipts-policy-circuit -- --ignored`"]
    fn confidential_verify_rejects_swapped_bindings() {
        let base = prove_policy_range_confidential(0.42, 0.0, 1.0, "pol", "out", None).unwrap();
        let mut tampered = base.clone();
        tampered.output_hash = "other-output".into();
        assert!(verify_policy_range_confidential(&tampered).is_err());
        let mut tampered2 = base;
        tampered2.policy_commitment = "other-policy".into();
        assert!(verify_policy_range_confidential(&tampered2).is_err());
    }

    #[test]
    fn confidential_prove_rejects_out_of_range_before_proving() {
        let err = prove_policy_range_confidential(1.5, 0.0, 1.0, "p", "o", None).unwrap_err();
        assert!(matches!(err, PolicyProofError::Range(_)));
    }

    #[test]
    #[ignore = "expensive Halo2 proof generation; run with `cargo test -p agent-receipts-policy-circuit -- --ignored`"]
    fn verify_rejects_swapped_output_commitment() {
        let out = json!({"decision": "approve", "fraud_score": 0.42});
        let mut env = prove_policy_range(0.42, 0.0, 1.0, "pol", "out", &[], &out).unwrap();
        env.output_hash = "tampered-output".to_string();
        assert!(verify_policy_range(&env).is_err());
    }

    #[test]
    #[ignore = "expensive Halo2 proof generation; run with `cargo test -p agent-receipts-policy-circuit -- --ignored`"]
    fn verify_rejects_swapped_policy_commitment() {
        let out = json!({"decision": "approve", "fraud_score": 0.42});
        let mut env = prove_policy_range(0.42, 0.0, 1.0, "pol", "out", &[], &out).unwrap();
        env.policy_commitment = "tampered-policy".to_string();
        assert!(verify_policy_range(&env).is_err());
    }

    #[test]
    #[ignore = "expensive Halo2 proof generation; run with `cargo test -p agent-receipts-policy-circuit -- --ignored`"]
    fn verify_rejects_tampered_required_mask() {
        let out = json!({"decision": "approve", "fraud_score": 0.42});
        let required = vec!["decision".into(), "fraud_score".into()];
        let mut env = prove_policy_range(0.42, 0.0, 1.0, "pol", "out", &required, &out).unwrap();
        env.public_inputs[3] = "1".into();
        assert!(verify_policy_range(&env).is_err());
    }
}
