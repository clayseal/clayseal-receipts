//! Session proof envelope and action descriptors.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::SessionProofError;

pub const AGGREGATION_HALO2_BATCH: &str = "halo2_batch_v1";
pub const AGGREGATION_NOVA_FOLD: &str = "nova_fold_v1";

/// Inputs for proving one session action (mirrors a single policy_range_v3 statement).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionActionInput {
    pub score: f64,
    #[serde(default = "default_min")]
    pub min: f64,
    #[serde(default = "default_max")]
    pub max: f64,
    pub policy_commitment: String,
    pub output_hash: String,
    #[serde(default)]
    pub required_fields: Vec<String>,
    pub output: Value,
}

fn default_min() -> f64 {
    0.0
}

fn default_max() -> f64 {
    1.0
}

/// Stored per-action metadata inside a session envelope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionActionRef {
    pub output_hash: String,
    pub policy_commitment: String,
    pub score_scaled: String,
    pub min_scaled: String,
    pub max_plus_one: String,
    pub required_presence_mask: String,
    #[serde(default)]
    pub required_fields: Vec<String>,
}

/// Aggregate proof over N policy-range actions within one session.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionProofEnvelope {
    pub version: u32,
    pub aggregation_mode: String,
    pub session_id: String,
    pub policy_commitment: String,
    pub action_count: u32,
    pub actions: Vec<SessionActionRef>,
    pub session_digest: String,
    pub proof_hex: String,
}

impl SessionProofEnvelope {
    pub const VERSION: u32 = 1;
}

pub fn session_digest(session_id: &str, actions: &[SessionActionRef]) -> Result<String, SessionProofError> {
    let mut state = Sha256::digest(format!("session:{session_id}").as_bytes());
    for (index, action) in actions.iter().enumerate() {
        let step = serde_json::json!({
            "index": index,
            "output_hash": action.output_hash,
            "policy_commitment": action.policy_commitment,
            "score_scaled": action.score_scaled,
            "required_presence_mask": action.required_presence_mask,
        });
        let encoded = serde_json::to_string(&step).map_err(|e| {
            SessionProofError::Envelope(format!("session digest step json encode failed: {e}"))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(state);
        hasher.update(encoded.as_bytes());
        state = hasher.finalize().into();
    }
    Ok(hex::encode(state))
}

pub fn action_ref_from_input(
    input: &SessionActionInput,
) -> Result<SessionActionRef, SessionProofError> {
    use agent_receipts_policy_circuit::{
        required_presence_mask, PolicyRangeCircuit,
    };

    let mask = required_presence_mask(&input.required_fields, &input.output)?;
    let circuit = PolicyRangeCircuit::from_range(input.score, input.min, input.max);
    Ok(SessionActionRef {
        output_hash: input.output_hash.clone(),
        policy_commitment: input.policy_commitment.clone(),
        score_scaled: circuit.score.to_string(),
        min_scaled: circuit.min_scaled.to_string(),
        max_plus_one: circuit.max_plus_one.to_string(),
        required_presence_mask: mask.to_string(),
        required_fields: input.required_fields.clone(),
    })
}

pub fn validate_session_actions(actions: &[SessionActionInput]) -> Result<(), SessionProofError> {
    if actions.is_empty() {
        return Err(SessionProofError::Envelope(
            "session requires at least one action".into(),
        ));
    }
    let policy = &actions[0].policy_commitment;
    for (index, action) in actions.iter().enumerate() {
        if &action.policy_commitment != policy {
            return Err(SessionProofError::Envelope(format!(
                "action {index} policy_commitment mismatch"
            )));
        }
    }
    Ok(())
}

pub fn build_action_refs(
    actions: &[SessionActionInput],
) -> Result<Vec<SessionActionRef>, SessionProofError> {
    validate_session_actions(actions)?;
    actions.iter().map(action_ref_from_input).collect()
}

/// Structural checks on stored action metadata (range + required-field mask).
///
/// Used by both Halo2 batch verification and Nova fold verification. Nova fold
/// does not re-verify per-action Halo2 proofs inside the SNARK; callers that
/// need full cryptographic policy checks must use ``halo2_batch_v1`` or retain
/// the underlying batch proof bytes alongside a fold artifact.
pub fn validate_action_ref(action: &SessionActionRef) -> Result<(), SessionProofError> {
    let score_scaled: u64 = action
        .score_scaled
        .parse()
        .map_err(|e: std::num::ParseIntError| SessionProofError::Envelope(e.to_string()))?;
    let min_scaled: u64 = action
        .min_scaled
        .parse()
        .map_err(|e: std::num::ParseIntError| SessionProofError::Envelope(e.to_string()))?;
    let max_plus_one: u64 = action
        .max_plus_one
        .parse()
        .map_err(|e: std::num::ParseIntError| SessionProofError::Envelope(e.to_string()))?;
    let mask: u64 = action
        .required_presence_mask
        .parse()
        .map_err(|e: std::num::ParseIntError| SessionProofError::Envelope(e.to_string()))?;

    if score_scaled < min_scaled || score_scaled > max_plus_one.saturating_sub(1) {
        return Err(SessionProofError::Policy(format!(
            "action {} violates public range",
            action.output_hash
        )));
    }
    let expected_count = action.required_fields.len();
    let expected_mask = if expected_count == 0 {
        0
    } else {
        (1u64 << expected_count) - 1
    };
    if mask != expected_mask {
        return Err(SessionProofError::Policy(format!(
            "action {} required_presence_mask mismatch",
            action.output_hash
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn session_digest_is_stable() {
        let actions = vec![SessionActionRef {
            output_hash: "out-1".into(),
            policy_commitment: "pol".into(),
            score_scaled: "420000".into(),
            min_scaled: "0".into(),
            max_plus_one: "1000001".into(),
            required_presence_mask: "0".into(),
            required_fields: vec![],
        }];
        let d1 = session_digest("sess-a", &actions).unwrap();
        let d2 = session_digest("sess-a", &actions).unwrap();
        assert_eq!(d1, d2);
        assert_ne!(d1, session_digest("sess-b", &actions).unwrap());
    }

    #[test]
    fn action_ref_from_input_matches_policy_circuit() {
        let input = SessionActionInput {
            score: 0.42,
            min: 0.0,
            max: 1.0,
            policy_commitment: "pol".into(),
            output_hash: "out".into(),
            required_fields: vec!["decision".into(), "fraud_score".into()],
            output: json!({"decision": "approve", "fraud_score": 0.42}),
        };
        let action_ref = action_ref_from_input(&input).unwrap();
        assert_eq!(action_ref.required_presence_mask, "3");
    }

    #[test]
    fn validate_action_ref_rejects_out_of_range_score() {
        let action = SessionActionRef {
            output_hash: "out".into(),
            policy_commitment: "pol".into(),
            score_scaled: "2000000".into(),
            min_scaled: "0".into(),
            max_plus_one: "1000001".into(),
            required_presence_mask: "0".into(),
            required_fields: vec![],
        };
        assert!(validate_action_ref(&action).is_err());
    }
}
