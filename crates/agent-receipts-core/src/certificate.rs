use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::hash::Hash32;

/// Who authorized this agent in the trust hierarchy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalRef {
    pub principal_id: String,
    pub organization: String,
    pub scope: Vec<String>,
}

/// Deployment certificate binding agent identity to model + policy commitments.
///
/// X.509 encoding with custom OIDs is planned; this struct is the canonical semantic model.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentCertificate {
    pub agent_id: Uuid,
    pub model_provenance_hash: Hash32,
    pub policy_commitment: Hash32,
    pub principal: PrincipalRef,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// Placeholder for issuer signature bytes (PKI wiring in a later milestone).
    pub issuer_signature: Option<Vec<u8>>,
}

impl AgentCertificate {
    pub fn is_valid_at(&self, at: DateTime<Utc>) -> bool {
        at >= self.not_before && at < self.not_after
    }
}
