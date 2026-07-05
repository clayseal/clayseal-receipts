//! Nova recursive composition: one compressed SNARK over policy ∪ inference bindings.

use ff::Field;
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use generic_array::typenum::U24;
use nova_snark::{
    frontend::{
        gadgets::poseidon::{
            Elt, IOPattern, Simplex, Sponge, SpongeAPI, SpongeCircuit, SpongeOp, SpongeTrait,
            Strength,
        },
        num::AllocatedNum,
        ConstraintSystem, SynthesisError,
    },
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine, Group, PrimeFieldExt},
};
use sha2::{Digest, Sha256};

use agent_receipts_policy_circuit::{verify_policy_range, PolicyProofEnvelope};

use crate::compose::{verify_bindings, ComposedBindings, ComposedProofEnvelope, ComposedProofError};
use crate::inference::{verify_inference_envelope, InferenceProofEnvelope};

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;
type C = BindingStepCircuit<<E1 as Engine>::GE>;
type RecursiveProverKey = nova_snark::nova::ProverKey<E1, E2, C, S1, S2>;
type RecursiveVerifierKey = nova_snark::nova::VerifierKey<E1, E2, C, S1, S2>;

pub const COMPOSITION_ID_RECURSIVE: &str = "inference_and_policy_recursive_v1";
const STEP_WIDTH: usize = 4;
const KEYS_DIR: &str = "keys/composition_recursive";
/// Version tag for on-disk Nova artifacts; bump when the step circuit changes.
const RECURSIVE_CIRCUIT_ID: &str = "binding_step_v1";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct RecursiveCompositionProof {
    pub proof_hex: String,
    pub composition_digest: String,
    pub step_count: u32,
}

#[derive(Clone, Debug)]
struct BindingStepCircuit<G: Group> {
    elements: [G::Scalar; STEP_WIDTH],
}

impl<G: Group> StepCircuit<G::Scalar> for BindingStepCircuit<G> {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<G::Scalar>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<G::Scalar>],
    ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
        assert_eq!(z_in.len(), 1);
        let mut m = z_in.to_vec();
        for (index, value) in self.elements.iter().enumerate() {
            m.push(AllocatedNum::alloc(cs.namespace(|| format!("elt_{index}")), || {
                Ok(*value)
            })?);
        }

        let elt = m
            .iter()
            .map(|x| Elt::Allocated(x.clone()))
            .collect::<Vec<_>>();

        let parameter = IOPattern(vec![
            SpongeOp::Absorb((STEP_WIDTH + 1) as u32),
            SpongeOp::Squeeze(1),
        ]);
        let pc = Sponge::<G::Scalar, U24>::api_constants(Strength::Standard);
        let mut ns = cs.namespace(|| "composition_sponge");

        let z_out = {
            let mut sponge = SpongeCircuit::new_with_constants(&pc, Simplex);
            let acc = &mut ns;
            sponge.start(parameter, None, acc);
            SpongeAPI::absorb(&mut sponge, (STEP_WIDTH + 1) as u32, &elt, acc);
            let output = SpongeAPI::squeeze(&mut sponge, 1, acc);
            sponge.finish(acc).unwrap();
            Elt::ensure_allocated(&output[0], &mut ns.namespace(|| "ensure"), true)?
        };

        Ok(vec![z_out])
    }
}

fn keys_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(KEYS_DIR)
}

fn artifact_path(stem: &str) -> std::path::PathBuf {
    keys_dir().join(format!("{stem}.{RECURSIVE_CIRCUIT_ID}.bin"))
}

fn compressed_key_tag_path() -> std::path::PathBuf {
    keys_dir().join(format!("compressed_keys.{RECURSIVE_CIRCUIT_ID}.sha256"))
}

fn key_cache_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

fn pp_digest_tag(pp: &PublicParams<E1, E2, C>) -> Result<String, ComposedProofError> {
    let digest = bincode::serialize(&pp.digest())
        .map_err(|e| ComposedProofError::Binding(format!("serialize pp digest: {e}")))?;
    Ok(hex::encode(digest))
}

fn scalar_from_digest<G: Group>(digest: [u8; 32]) -> G::Scalar {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&digest);
    G::Scalar::from_uniform(&wide)
}

fn field_from_label(label: &str, value: &str) -> <E1 as Engine>::Scalar {
    let digest: [u8; 32] = Sha256::digest(format!("{label}:{value}").as_bytes()).into();
    scalar_from_digest::<<E1 as Engine>::GE>(digest)
}

fn field_from_u64(value: u64) -> <E1 as Engine>::Scalar {
    scalar_from_digest::<<E1 as Engine>::GE>({
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        bytes
    })
}

pub fn composition_seed(bindings: &ComposedBindings) -> Result<<E1 as Engine>::Scalar, ComposedProofError> {
    let encoded = serde_json::to_string(bindings).map_err(|e| {
        ComposedProofError::Binding(format!("serialize composition bindings: {e}"))
    })?;
    let digest: [u8; 32] = Sha256::digest(encoded.as_bytes()).into();
    Ok(scalar_from_digest::<<E1 as Engine>::GE>(digest))
}

pub fn composition_digest(bindings: &ComposedBindings) -> Result<String, ComposedProofError> {
    let encoded = serde_json::to_string(bindings).map_err(|e| {
        ComposedProofError::Binding(format!("serialize composition bindings: {e}"))
    })?;
    Ok(hex::encode(Sha256::digest(encoded.as_bytes())))
}

fn policy_step_elements(
    policy: &PolicyProofEnvelope,
) -> Result<[<E1 as Engine>::Scalar; STEP_WIDTH], ComposedProofError> {
    let score_scaled: u64 = policy.public_inputs.first().ok_or_else(|| {
        ComposedProofError::Binding("policy missing scaled score public input".into())
    })?.parse().map_err(|_| {
        ComposedProofError::Binding("policy scaled score public input parse error".into())
    })?;
    let mask: u64 = match policy.public_inputs.get(3) {
        Some(value) => value.parse().map_err(|_| {
            ComposedProofError::Binding("policy required presence mask parse error".into())
        })?,
        None => 0,
    };
    Ok([
        field_from_label("policy_commitment", &policy.policy_commitment),
        field_from_label("output_hash", &policy.output_hash),
        field_from_u64(score_scaled),
        field_from_u64(mask),
    ])
}

fn inference_step_elements(
    inference: &InferenceProofEnvelope,
) -> [<E1 as Engine>::Scalar; STEP_WIDTH] {
    let scaled = (inference.public_score * 1_000_000.0).round() as u64;
    [
        field_from_label("model_provenance_hash", &inference.model_provenance_hash),
        field_from_label("output_hash", &inference.output_hash),
        field_from_u64(scaled),
        <E1 as Engine>::Scalar::ZERO,
    ]
}

fn load_or_setup_pp() -> Result<PublicParams<E1, E2, C>, ComposedProofError> {
    use std::fs;
    use std::io::Read;

    let _guard = key_cache_lock().lock().map_err(|e| {
        ComposedProofError::Binding(format!("recursive key cache lock poisoned: {e}"))
    })?;
    fs::create_dir_all(keys_dir()).map_err(|e| ComposedProofError::Binding(e.to_string()))?;
    let pp_path = artifact_path("pp");
    if pp_path.is_file() {
        let mut bytes = Vec::new();
        fs::File::open(&pp_path)
            .map_err(|e| ComposedProofError::Binding(e.to_string()))?
            .read_to_end(&mut bytes)
            .map_err(|e| ComposedProofError::Binding(e.to_string()))?;
        return bincode::deserialize(&bytes)
            .map_err(|e| ComposedProofError::Binding(format!("load pp: {e}")));
    }

    let template = BindingStepCircuit {
        elements: [<E1 as Engine>::Scalar::ZERO; STEP_WIDTH],
    };
    let pp = PublicParams::<E1, E2, C>::setup(&template, &*S1::ck_floor(), &*S2::ck_floor())
        .map_err(|e| ComposedProofError::Binding(format!("nova setup failed: {e:?}")))?;
    let encoded = bincode::serialize(&pp)
        .map_err(|e| ComposedProofError::Binding(format!("serialize pp: {e}")))?;
    fs::write(&pp_path, encoded).map_err(|e| ComposedProofError::Binding(e.to_string()))?;
    for stem in ["compressed_pk", "compressed_vk"] {
        let _ = fs::remove_file(artifact_path(stem));
    }
    let _ = fs::remove_file(compressed_key_tag_path());
    for legacy in ["pp.bin", "compressed_pk.bin", "compressed_vk.bin"] {
        let _ = fs::remove_file(keys_dir().join(legacy));
    }
    Ok(pp)
}

fn load_or_setup_vk(
    pp: &PublicParams<E1, E2, C>,
) -> Result<(RecursiveProverKey, RecursiveVerifierKey), ComposedProofError> {
    use std::fs;
    use std::io::Read;

    let _guard = key_cache_lock().lock().map_err(|e| {
        ComposedProofError::Binding(format!("recursive key cache lock poisoned: {e}"))
    })?;
    fs::create_dir_all(keys_dir()).map_err(|e| ComposedProofError::Binding(e.to_string()))?;
    let pk_path = artifact_path("compressed_pk");
    let vk_path = artifact_path("compressed_vk");
    let tag_path = compressed_key_tag_path();
    let expected_tag = pp_digest_tag(pp)?;
    let cached_tag_matches = fs::read_to_string(&tag_path)
        .map(|tag| tag.trim() == expected_tag)
        .unwrap_or(false);

    if pk_path.is_file() && vk_path.is_file() && cached_tag_matches {
        let mut pk_bytes = Vec::new();
        let mut vk_bytes = Vec::new();
        fs::File::open(&pk_path)
            .map_err(|e| ComposedProofError::Binding(e.to_string()))?
            .read_to_end(&mut pk_bytes)
            .map_err(|e| ComposedProofError::Binding(e.to_string()))?;
        fs::File::open(&vk_path)
            .map_err(|e| ComposedProofError::Binding(e.to_string()))?
            .read_to_end(&mut vk_bytes)
            .map_err(|e| ComposedProofError::Binding(e.to_string()))?;
        let pk: RecursiveProverKey = bincode::deserialize(&pk_bytes)
            .map_err(|e| ComposedProofError::Binding(format!("load pk: {e}")))?;
        let vk: RecursiveVerifierKey = bincode::deserialize(&vk_bytes)
            .map_err(|e| ComposedProofError::Binding(format!("load vk: {e}")))?;
        return Ok((pk, vk));
    }

    for path in [&pk_path, &vk_path, &tag_path] {
        let _ = fs::remove_file(path);
    }
    let (pk, vk) = CompressedSNARK::<_, _, _, S1, S2>::setup(pp)
        .map_err(|e| ComposedProofError::Binding(format!("compressed setup failed: {e:?}")))?;
    fs::write(
        &pk_path,
        bincode::serialize(&pk).map_err(|e| ComposedProofError::Binding(format!("serialize pk: {e}")))?,
    )
    .map_err(|e| ComposedProofError::Binding(e.to_string()))?;
    fs::write(
        &vk_path,
        bincode::serialize(&vk).map_err(|e| ComposedProofError::Binding(format!("serialize vk: {e}")))?,
    )
    .map_err(|e| ComposedProofError::Binding(e.to_string()))?;
    fs::write(&tag_path, expected_tag).map_err(|e| ComposedProofError::Binding(e.to_string()))?;
    Ok((pk, vk))
}

fn encode_compressed_snark(
    snark: &CompressedSNARK<E1, E2, C, S1, S2>,
) -> Result<String, ComposedProofError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    bincode::serialize_into(&mut encoder, snark)
        .map_err(|e| ComposedProofError::Binding(format!("serialize snark: {e}")))?;
    let bytes = encoder
        .finish()
        .map_err(|e| ComposedProofError::Binding(format!("compress snark: {e}")))?;
    Ok(hex::encode(bytes))
}

fn decode_compressed_snark(
    proof_hex: &str,
) -> Result<CompressedSNARK<E1, E2, C, S1, S2>, ComposedProofError> {
    use std::io::Read;

    let bytes = hex::decode(proof_hex).map_err(|e| ComposedProofError::Binding(e.to_string()))?;
    let mut decoder = ZlibDecoder::new(bytes.as_slice());
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|e| ComposedProofError::Binding(format!("decompress snark: {e}")))?;
    bincode::deserialize(&decoded)
        .map_err(|e| ComposedProofError::Binding(format!("deserialize snark: {e}")))
}

pub fn prove_recursive_composition(
    policy: &PolicyProofEnvelope,
    inference: &InferenceProofEnvelope,
    bindings: &ComposedBindings,
    allow_stub_inference: bool,
) -> Result<RecursiveCompositionProof, ComposedProofError> {
    let envelope = ComposedProofEnvelope {
        version: 1,
        composition_id: COMPOSITION_ID_RECURSIVE.to_string(),
        bindings: bindings.clone(),
        policy: policy.clone(),
        inference: inference.clone(),
        recursive: None,
    };
    verify_bindings(&envelope)?;
    verify_policy_range(policy).map_err(|e| ComposedProofError::Policy(e.to_string()))?;
    verify_inference_envelope(inference, allow_stub_inference)?;

    let z0 = composition_seed(bindings)?;
    let digest = composition_digest(bindings)?;
    let circuits = vec![
        BindingStepCircuit {
            elements: policy_step_elements(policy)?,
        },
        BindingStepCircuit {
            elements: inference_step_elements(inference),
        },
    ];

    let pp = load_or_setup_pp()?;
    let first = circuits
        .first()
        .ok_or_else(|| ComposedProofError::Binding("missing policy step".into()))?;
    let mut recursive =
        RecursiveSNARK::<E1, E2, C>::new(&pp, first, &[z0]).map_err(|e| {
            ComposedProofError::Binding(format!("recursive init failed: {e:?}"))
        })?;
    for circuit in &circuits {
        recursive
            .prove_step(&pp, circuit)
            .map_err(|e| ComposedProofError::Binding(format!("recursive step failed: {e:?}")))?;
    }

    let (pk, _vk) = load_or_setup_vk(&pp)?;
    let compressed = CompressedSNARK::<_, _, _, S1, S2>::prove(&pp, &pk, &recursive).map_err(
        |e| ComposedProofError::Binding(format!("compressed prove failed: {e:?}")),
    )?;

    Ok(RecursiveCompositionProof {
        proof_hex: encode_compressed_snark(&compressed)?,
        composition_digest: digest,
        step_count: circuits.len() as u32,
    })
}

pub fn verify_recursive_composition(
    envelope: &ComposedProofEnvelope,
    recursive: &RecursiveCompositionProof,
    allow_stub_inference: bool,
) -> Result<bool, ComposedProofError> {
    if envelope.composition_id != COMPOSITION_ID_RECURSIVE {
        return Err(ComposedProofError::Binding(format!(
            "expected composition_id {COMPOSITION_ID_RECURSIVE}, got {}",
            envelope.composition_id
        )));
    }
    verify_bindings(envelope)?;
    verify_policy_range(&envelope.policy)
        .map_err(|e| ComposedProofError::Policy(e.to_string()))?;
    verify_inference_envelope(&envelope.inference, allow_stub_inference)?;
    if recursive.composition_digest != composition_digest(&envelope.bindings)? {
        return Err(ComposedProofError::Binding(
            "composition_digest does not match bindings".into(),
        ));
    }
    if recursive.step_count != 2 {
        return Err(ComposedProofError::Binding(format!(
            "expected 2 recursive steps, got {}",
            recursive.step_count
        )));
    }

    let pp = load_or_setup_pp()?;
    let (_pk, vk) = load_or_setup_vk(&pp)?;
    let compressed = decode_compressed_snark(&recursive.proof_hex)?;
    let z0 = composition_seed(&envelope.bindings)?;
    compressed
        .verify(&vk, recursive.step_count as usize, &[z0])
        .map_err(|e| ComposedProofError::Binding(format!("compressed verify failed: {e:?}")))?;
    Ok(true)
}

pub fn compose_proofs_recursive(
    policy: PolicyProofEnvelope,
    inference: InferenceProofEnvelope,
    bindings: ComposedBindings,
    allow_stub_inference: bool,
) -> Result<ComposedProofEnvelope, ComposedProofError> {
    let recursive = prove_recursive_composition(&policy, &inference, &bindings, allow_stub_inference)?;
    Ok(ComposedProofEnvelope {
        version: 1,
        composition_id: COMPOSITION_ID_RECURSIVE.to_string(),
        bindings,
        policy,
        inference,
        recursive: Some(recursive),
    })
}

#[cfg(test)]
mod tests {
    use agent_receipts_policy_circuit::prove_policy_range;
    use serde_json::json;

    use super::*;
    use crate::compose::compose_proofs;
    use crate::inference::{prove_inference_ezkl, InferenceAttestation};

    fn sample_output(score: f64) -> serde_json::Value {
        json!({"decision": "approve", "fraud_score": score})
    }

    #[test]
    fn recursive_composed_accepts_stub_subproofs() {
        let output_hash = "out-recursive";
        let out = sample_output(0.25);
        let required = vec!["decision".into(), "fraud_score".into()];
        let policy = prove_policy_range(0.25, 0.0, 1.0, "pol", output_hash, &required, &out).unwrap();
        let inference = prove_inference_ezkl(2500.0, "model", output_hash, true).unwrap();
        assert_eq!(inference.attestation, InferenceAttestation::Stub);
        let bindings = ComposedBindings {
            output_hash: output_hash.into(),
            policy_commitment: "pol".into(),
            model_provenance_hash: "model".into(),
            context_hash: "ctx".into(),
            public_score: 0.25,
        };
        let composed =
            compose_proofs_recursive(policy, inference, bindings, true).unwrap();
        assert!(composed.recursive.is_some());
        assert!(crate::compose::verify_composed(&composed, true).unwrap());
    }

    #[test]
    fn recursive_rejects_invalid_policy_subproof() {
        let output_hash = "out-recursive";
        let out = sample_output(0.25);
        let required = vec!["decision".into(), "fraud_score".into()];
        let policy = prove_policy_range(0.25, 0.0, 1.0, "pol", output_hash, &required, &out).unwrap();
        let inference = prove_inference_ezkl(2500.0, "model", output_hash, true).unwrap();
        let bindings = ComposedBindings {
            output_hash: output_hash.into(),
            policy_commitment: "pol".into(),
            model_provenance_hash: "model".into(),
            context_hash: "ctx".into(),
            public_score: 0.25,
        };
        let mut composed =
            compose_proofs_recursive(policy, inference, bindings, true).unwrap();
        composed.policy.proof_hex = "00".repeat(32);
        assert!(crate::compose::verify_composed(&composed, true).is_err());
    }

    #[test]
    fn recursive_rejects_tampered_output_hash() {
        let output_hash = "out-recursive";
        let out = sample_output(0.25);
        let policy = prove_policy_range(0.25, 0.0, 1.0, "pol", output_hash, &[], &out).unwrap();
        let inference = prove_inference_ezkl(2500.0, "model", output_hash, true).unwrap();
        let bindings = ComposedBindings {
            output_hash: output_hash.into(),
            policy_commitment: "pol".into(),
            model_provenance_hash: "model".into(),
            context_hash: "ctx".into(),
            public_score: 0.25,
        };
        let mut composed =
            compose_proofs_recursive(policy, inference, bindings, true).unwrap();
        composed.bindings.output_hash = "tampered".into();
        assert!(crate::compose::verify_composed(&composed, true).is_err());
    }

    #[test]
    fn logical_and_recursive_both_available() {
        let output_hash = "out-both";
        let out = sample_output(0.5);
        let policy = prove_policy_range(0.5, 0.0, 1.0, "pol", output_hash, &[], &out).unwrap();
        let inference = prove_inference_ezkl(5000.0, "model", output_hash, true).unwrap();
        let bindings = ComposedBindings {
            output_hash: output_hash.into(),
            policy_commitment: "pol".into(),
            model_provenance_hash: "model".into(),
            context_hash: "ctx".into(),
            public_score: 0.5,
        };
        let logical = compose_proofs(policy.clone(), inference.clone(), bindings.clone());
        let recursive = compose_proofs_recursive(policy, inference, bindings, true).unwrap();
        assert_eq!(logical.composition_id, "inference_and_policy_v1");
        assert_eq!(recursive.composition_id, COMPOSITION_ID_RECURSIVE);
    }
}
