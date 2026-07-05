//! Core cryptographic objects and audit chain for [Agent Receipts](https://github.com/pberlizov/agent-receipts).
//!
//! ZK proving and TEE attestation are wired in later; this crate defines stable
//! envelopes and hash-chain integrity today.

pub mod audit;
pub mod certificate;
pub mod hash;
pub mod policy;
pub mod proof;

pub use audit::{AuditChain, AuditRecord, AuditStoreError};
pub use certificate::{AgentCertificate, PrincipalRef};
pub use hash::{hash_bytes, hash_json, Hash32};
pub use policy::{PolicyCapability, PolicyDocument, PolicyTier};
pub use proof::{AttestationPath, ExecutionProof, ProofBundle, VerificationResult};
