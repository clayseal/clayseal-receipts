//! Composed proof: EZKL inference attestation + Halo2 policy attestation with explicit bindings.
//!
//! Logical composition (`inference_and_policy_v1`) verifies both sub-proofs.
//! Recursive composition (`inference_and_policy_recursive_v1`, SOTA-10) folds policy ∪
//! inference bindings into one Nova compressed SNARK.

pub mod compose;
pub mod inference;
pub mod recursive;

pub use compose::{
    compose_from_json_parts, compose_proofs, composed_from_json, composed_to_json, verify_composed,
    ComposedBindings, ComposedProofEnvelope, ComposedProofError,
};
pub use inference::{
    fraud_head_dir, fraud_head_score, prove_inference_ezkl, prove_inference_risc0,
    prove_inference_sp1, verify_inference_envelope, InferenceAttestation, InferenceProofEnvelope,
};
pub use recursive::{
    compose_proofs_recursive, prove_recursive_composition, verify_recursive_composition,
    RecursiveCompositionProof, COMPOSITION_ID_RECURSIVE,
};
