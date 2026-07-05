//! Session-proof aggregation over multiple policy-range actions (SOTA-7).

pub mod batch;
pub mod envelope;

#[cfg(feature = "nova-fold")]
pub mod fold;

pub use batch::{prove_session_batch, verify_session_batch};
pub use envelope::{
    session_digest, SessionActionInput, SessionActionRef, SessionProofEnvelope,
};

#[cfg(feature = "nova-fold")]
pub use fold::{prove_session_fold, verify_session_fold};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionProofError {
    #[error("proving failed: {0}")]
    Prove(String),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("invalid envelope: {0}")]
    Envelope(String),
    #[error("policy check failed: {0}")]
    Policy(String),
}

impl From<agent_receipts_policy_circuit::PolicyProofError> for SessionProofError {
    fn from(value: agent_receipts_policy_circuit::PolicyProofError) -> Self {
        match value {
            agent_receipts_policy_circuit::PolicyProofError::Prove(msg) => {
                SessionProofError::Prove(msg)
            }
            agent_receipts_policy_circuit::PolicyProofError::Verify(msg) => {
                SessionProofError::Verify(msg)
            }
            agent_receipts_policy_circuit::PolicyProofError::Envelope(msg) => {
                SessionProofError::Envelope(msg)
            }
            agent_receipts_policy_circuit::PolicyProofError::Range(msg) => {
                SessionProofError::Policy(msg)
            }
        }
    }
}

pub fn prove_session(
    session_id: &str,
    actions: &[SessionActionInput],
    mode: &str,
) -> Result<SessionProofEnvelope, SessionProofError> {
    match mode {
        "halo2_batch_v1" => prove_session_batch(session_id, actions),
        #[cfg(feature = "nova-fold")]
        "nova_fold_v1" => prove_session_fold(session_id, actions),
        #[cfg(not(feature = "nova-fold"))]
        "nova_fold_v1" => Err(SessionProofError::Prove(
            "nova_fold_v1 requires agent-receipts-session built with feature nova-fold".into(),
        )),
        other => Err(SessionProofError::Envelope(format!(
            "unknown aggregation mode: {other}"
        ))),
    }
}

pub fn verify_session(envelope: &SessionProofEnvelope) -> Result<bool, SessionProofError> {
    match envelope.aggregation_mode.as_str() {
        "halo2_batch_v1" => verify_session_batch(envelope),
        #[cfg(feature = "nova-fold")]
        "nova_fold_v1" => verify_session_fold(envelope),
        #[cfg(not(feature = "nova-fold"))]
        "nova_fold_v1" => Err(SessionProofError::Verify(
            "nova_fold_v1 requires agent-receipts-session built with feature nova-fold".into(),
        )),
        other => Err(SessionProofError::Envelope(format!(
            "unknown aggregation mode: {other}"
        ))),
    }
}

pub fn session_to_json(envelope: &SessionProofEnvelope) -> Result<String, serde_json::Error> {
    serde_json::to_string(envelope)
}

pub fn session_from_json(json: &str) -> Result<SessionProofEnvelope, serde_json::Error> {
    serde_json::from_str(json)
}
