use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::certificate::AgentCertificate;
use crate::hash::Hash32;

/// How inference was attested for this execution.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationPath {
    FullZk,
    TeeHybrid,
    Shadow,
}

/// Placeholder proof bytes — replaced by Halo2 / EZKL artifacts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProofBundle {
    pub inference_proof: Option<Vec<u8>>,
    pub policy_proof: Option<Vec<u8>>,
    pub composed_proof: Option<Vec<u8>>,
    pub verification_key_id: Option<String>,
}

/// Cryptographic receipt for one consequential agent action.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ExecutionProof {
    pub proof_id: Uuid,
    pub agent_id: Uuid,
    pub certificate_ref: Hash32,
    pub policy_commitment: Hash32,
    pub context_hash: Hash32,
    pub output_hash: Hash32,
    pub attestation_path: AttestationPath,
    pub policy_satisfied: bool,
    pub created_at: DateTime<Utc>,
    pub bundle: ProofBundle,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationResult {
    pub valid: bool,
    pub reasons: Vec<String>,
}

impl ExecutionProof {
    pub fn verify(&self) -> VerificationResult {
        let mut reasons = Vec::new();

        if self.attestation_path == AttestationPath::Shadow {
            reasons.push("shadow mode: proofs are not cryptographically verified".into());
            return VerificationResult {
                valid: false,
                reasons,
            };
        }

        if !self.policy_satisfied {
            reasons.push("policy_satisfied is false".into());
        }

        let has_proof = self.bundle.composed_proof.is_some()
            || (self.bundle.inference_proof.is_some() && self.bundle.policy_proof.is_some());

        if !has_proof {
            reasons.push("no proof bytes attached (prover not wired)".into());
        }

        VerificationResult {
            valid: reasons.is_empty(),
            reasons,
        }
    }

    pub fn from_action(
        certificate: &AgentCertificate,
        context_hash: Hash32,
        output_hash: Hash32,
        policy_satisfied: bool,
        path: AttestationPath,
    ) -> Self {
        let certificate_ref =
            crate::hash::hash_json(certificate).expect("certificate must serialize");
        Self {
            proof_id: Uuid::new_v4(),
            agent_id: certificate.agent_id,
            certificate_ref,
            policy_commitment: certificate.policy_commitment,
            context_hash,
            output_hash,
            attestation_path: path,
            policy_satisfied,
            created_at: Utc::now(),
            bundle: ProofBundle::default(),
        }
    }
}
