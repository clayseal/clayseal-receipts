//! Nova folding with compressed Spartan proof (sub-linear verification).
//!
//! ``nova_fold_v1`` compresses a chain of action-binding digests; it does **not**
//! verify per-action Halo2 ``policy_range_v3`` proofs inside the fold. Use
//! ``halo2_batch_v1`` when full cryptographic policy satisfaction is required,
//! or retain batch proof bytes alongside a fold artifact for audit.

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

use agent_receipts_policy_circuit::check_range;

use crate::batch::build_circuit;
use crate::envelope::{
    build_action_refs, session_digest, validate_action_ref, SessionActionInput, SessionActionRef,
    SessionProofEnvelope, AGGREGATION_NOVA_FOLD,
};
use crate::SessionProofError;

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;
type C = SessionStepCircuit<<E1 as Engine>::GE>;

const SESSION_FOLD_KEYS_DIR: &str = "keys/session_fold";
const SESSION_FOLD_KEYS_DIR_ENV: &str = "AGENT_RECEIPTS_SESSION_FOLD_KEYS_DIR";
/// Version tag for on-disk Nova artifacts; bump when the step circuit changes.
const SESSION_FOLD_CIRCUIT_ID: &str = "session_step_v1";

fn keys_dir() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os(SESSION_FOLD_KEYS_DIR_ENV) {
        return std::path::PathBuf::from(path);
    }
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(SESSION_FOLD_KEYS_DIR)
}

fn artifact_path(stem: &str) -> std::path::PathBuf {
    keys_dir().join(format!("{stem}.{SESSION_FOLD_CIRCUIT_ID}.bin"))
}

#[derive(Clone, Debug)]
struct SessionStepCircuit<G: Group> {
    action_binding: G::Scalar,
}

impl<G: Group> StepCircuit<G::Scalar> for SessionStepCircuit<G> {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<G::Scalar>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<G::Scalar>],
    ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
        assert_eq!(z_in.len(), 1);
        let x_i = AllocatedNum::alloc(cs.namespace(|| "action_binding"), || {
            Ok(self.action_binding)
        })?;

        let mut m = z_in.to_vec();
        m.push(x_i);

        let elt = m
            .iter()
            .map(|x| Elt::Allocated(x.clone()))
            .collect::<Vec<_>>();

        let parameter = IOPattern(vec![SpongeOp::Absorb(2), SpongeOp::Squeeze(1)]);
        let pc = Sponge::<G::Scalar, U24>::api_constants(Strength::Standard);
        let mut ns = cs.namespace(|| "session_sponge");

        let z_out = {
            let mut sponge = SpongeCircuit::new_with_constants(&pc, Simplex);
            let acc = &mut ns;
            sponge.start(parameter, None, acc);
            SpongeAPI::absorb(&mut sponge, 2, &elt, acc);
            let output = SpongeAPI::squeeze(&mut sponge, 1, acc);
            sponge.finish(acc).unwrap();
            Elt::ensure_allocated(&output[0], &mut ns.namespace(|| "ensure"), true)?
        };

        Ok(vec![z_out])
    }
}

fn scalar_from_digest<G: Group>(digest: [u8; 32]) -> G::Scalar {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&digest);
    G::Scalar::from_uniform(&wide)
}

fn session_seed(session_id: &str, policy_commitment: &str) -> <E1 as Engine>::Scalar {
    let digest: [u8; 32] = Sha256::digest(format!("session:{session_id}:{policy_commitment}").as_bytes()).into();
    scalar_from_digest::<<E1 as Engine>::GE>(digest)
}

fn action_binding(action: &SessionActionRef) -> Result<<E1 as Engine>::Scalar, SessionProofError> {
    let step = serde_json::json!({
        "output_hash": action.output_hash,
        "policy_commitment": action.policy_commitment,
        "score_scaled": action.score_scaled,
        "required_presence_mask": action.required_presence_mask,
    });
    let encoded = serde_json::to_string(&step).map_err(|e| {
        SessionProofError::Envelope(format!("action binding json encode failed: {e}"))
    })?;
    let digest: [u8; 32] = Sha256::digest(encoded.as_bytes()).into();
    Ok(scalar_from_digest::<<E1 as Engine>::GE>(digest))
}

fn load_or_setup_pp() -> Result<PublicParams<E1, E2, C>, SessionProofError> {
    use std::fs;
    use std::io::{Read, Write};

    fs::create_dir_all(keys_dir()).map_err(|e| SessionProofError::Prove(e.to_string()))?;
    let pp_path = artifact_path("pp");
    if pp_path.is_file() {
        let mut file = fs::File::open(&pp_path).map_err(|e| SessionProofError::Prove(e.to_string()))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| SessionProofError::Prove(e.to_string()))?;
        return bincode::deserialize(&bytes)
            .map_err(|e| SessionProofError::Prove(format!("load pp: {e}")));
    }

    let template = SessionStepCircuit {
        action_binding: <E1 as Engine>::Scalar::ZERO,
    };
    let pp = PublicParams::<E1, E2, C>::setup(&template, &*S1::ck_floor(), &*S2::ck_floor())
        .map_err(|e| SessionProofError::Prove(format!("nova setup failed: {e:?}")))?;
    let encoded = bincode::serialize(&pp)
        .map_err(|e| SessionProofError::Prove(format!("serialize pp: {e}")))?;
    let mut file = fs::File::create(&pp_path).map_err(|e| SessionProofError::Prove(e.to_string()))?;
    file.write_all(&encoded)
        .map_err(|e| SessionProofError::Prove(e.to_string()))?;
    for stem in ["compressed_pk", "compressed_vk"] {
        let _ = fs::remove_file(artifact_path(stem));
    }
    // Drop pre-versioning artifact names so stale pk/vk cannot desync from a new pp.
    for legacy in ["pp.bin", "compressed_pk.bin", "compressed_vk.bin"] {
        let _ = fs::remove_file(keys_dir().join(legacy));
    }
    Ok(pp)
}

fn load_or_setup_vk(
    pp: &PublicParams<E1, E2, C>,
) -> Result<
    (
        nova_snark::nova::ProverKey<E1, E2, C, S1, S2>,
        nova_snark::nova::VerifierKey<E1, E2, C, S1, S2>,
    ),
    SessionProofError,
> {
    use std::fs;
    use std::io::Read;

    fs::create_dir_all(keys_dir()).map_err(|e| SessionProofError::Prove(e.to_string()))?;
    let pk_path = artifact_path("compressed_pk");
    let vk_path = artifact_path("compressed_vk");
    if pk_path.is_file() && vk_path.is_file() {
        let mut pk_bytes = Vec::new();
        let mut vk_bytes = Vec::new();
        fs::File::open(&pk_path)
            .map_err(|e| SessionProofError::Prove(e.to_string()))?
            .read_to_end(&mut pk_bytes)
            .map_err(|e| SessionProofError::Prove(e.to_string()))?;
        fs::File::open(&vk_path)
            .map_err(|e| SessionProofError::Prove(e.to_string()))?
            .read_to_end(&mut vk_bytes)
            .map_err(|e| SessionProofError::Prove(e.to_string()))?;
        let pk: nova_snark::nova::ProverKey<E1, E2, C, S1, S2> = bincode::deserialize(&pk_bytes)
            .map_err(|e| SessionProofError::Prove(format!("load pk: {e}")))?;
        let vk: nova_snark::nova::VerifierKey<E1, E2, C, S1, S2> = bincode::deserialize(&vk_bytes)
            .map_err(|e| SessionProofError::Prove(format!("load vk: {e}")))?;
        return Ok((pk, vk));
    }

    let (pk, vk) = CompressedSNARK::<_, _, _, S1, S2>::setup(pp)
        .map_err(|e| SessionProofError::Prove(format!("compressed setup failed: {e:?}")))?;
    fs::write(
        &pk_path,
        bincode::serialize(&pk).map_err(|e| SessionProofError::Prove(format!("serialize pk: {e}")))?,
    )
    .map_err(|e| SessionProofError::Prove(e.to_string()))?;
    fs::write(
        &vk_path,
        bincode::serialize(&vk).map_err(|e| SessionProofError::Prove(format!("serialize vk: {e}")))?,
    )
    .map_err(|e| SessionProofError::Prove(e.to_string()))?;
    Ok((pk, vk))
}

fn encode_compressed_snark(
    snark: &CompressedSNARK<E1, E2, C, S1, S2>,
) -> Result<String, SessionProofError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    bincode::serialize_into(&mut encoder, snark)
        .map_err(|e| SessionProofError::Prove(format!("serialize compressed snark: {e}")))?;
    let bytes = encoder
        .finish()
        .map_err(|e| SessionProofError::Prove(format!("compress snark: {e}")))?;
    Ok(hex::encode(bytes))
}

fn decode_compressed_snark(
    proof_hex: &str,
) -> Result<CompressedSNARK<E1, E2, C, S1, S2>, SessionProofError> {
    use std::io::Read;

    let bytes =
        hex::decode(proof_hex).map_err(|e| SessionProofError::Envelope(e.to_string()))?;
    let mut decoder = ZlibDecoder::new(bytes.as_slice());
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|e| SessionProofError::Verify(format!("decompress snark: {e}")))?;
    bincode::deserialize(&decoded)
        .map_err(|e| SessionProofError::Verify(format!("deserialize compressed snark: {e}")))
}

pub fn prove_session_fold(
    session_id: &str,
    actions: &[SessionActionInput],
) -> Result<SessionProofEnvelope, SessionProofError> {
    for action in actions {
        check_range(action.score, action.min, action.max)?;
        let _ = build_circuit(action)?;
    }

    let action_refs = build_action_refs(actions)?;
    let policy_commitment = actions[0].policy_commitment.clone();
    let digest = session_digest(session_id, &action_refs)?;
    let z0 = session_seed(session_id, &policy_commitment);

    let pp = load_or_setup_pp()?;
    let mut circuits: Vec<C> = Vec::with_capacity(action_refs.len());
    for action in &action_refs {
        circuits.push(SessionStepCircuit {
            action_binding: action_binding(action)?,
        });
    }

    let first = circuits
        .first()
        .ok_or_else(|| SessionProofError::Envelope("session requires actions".into()))?;

    let mut recursive =
        RecursiveSNARK::<E1, E2, C>::new(&pp, first, &[z0]).map_err(|e| {
            SessionProofError::Prove(format!("recursive snark init failed: {e:?}"))
        })?;

    for circuit in &circuits {
        recursive
            .prove_step(&pp, circuit)
            .map_err(|e| SessionProofError::Prove(format!("recursive step failed: {e:?}")))?;
    }

    let (pk, _vk) = load_or_setup_vk(&pp)?;
    let compressed = CompressedSNARK::<_, _, _, S1, S2>::prove(&pp, &pk, &recursive).map_err(
        |e| SessionProofError::Prove(format!("compressed prove failed: {e:?}")),
    )?;

    Ok(SessionProofEnvelope {
        version: SessionProofEnvelope::VERSION,
        aggregation_mode: AGGREGATION_NOVA_FOLD.to_string(),
        session_id: session_id.to_string(),
        policy_commitment,
        action_count: actions.len() as u32,
        actions: action_refs,
        session_digest: digest,
        proof_hex: encode_compressed_snark(&compressed)?,
    })
}

pub fn verify_session_fold(envelope: &SessionProofEnvelope) -> Result<bool, SessionProofError> {
    if envelope.aggregation_mode != AGGREGATION_NOVA_FOLD {
        return Err(SessionProofError::Envelope(format!(
            "expected mode {AGGREGATION_NOVA_FOLD}, got {}",
            envelope.aggregation_mode
        )));
    }

    let recomputed = session_digest(&envelope.session_id, &envelope.actions)?;
    if recomputed != envelope.session_digest {
        return Err(SessionProofError::Verify(
            "session_digest does not match actions".into(),
        ));
    }

    for action in &envelope.actions {
        if action.policy_commitment != envelope.policy_commitment {
            return Err(SessionProofError::Verify(
                "action policy_commitment disagrees with envelope".into(),
            ));
        }
        validate_action_ref(action)?;
    }

    let pp = load_or_setup_pp()?;
    let (_pk, vk) = load_or_setup_vk(&pp)?;
    let compressed = decode_compressed_snark(&envelope.proof_hex)?;
    let z0 = session_seed(&envelope.session_id, &envelope.policy_commitment);
    compressed
        .verify(&vk, envelope.action_count as usize, &[z0])
        .map_err(|e| SessionProofError::Verify(format!("compressed verify failed: {e:?}")))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::sync::{Mutex, OnceLock};

    fn fold_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn sample_actions(n: usize) -> Vec<SessionActionInput> {
        (0..n)
            .map(|i| SessionActionInput {
                score: 0.1 * (i as f64 + 1.0),
                min: 0.0,
                max: 1.0,
                policy_commitment: "pol-session".into(),
                output_hash: format!("out-{i}"),
                required_fields: vec!["decision".into(), "fraud_score".into()],
                output: json!({"decision": "approve", "fraud_score": 0.1 * (i as f64 + 1.0)}),
            })
            .collect()
    }

    #[test]
    fn fold_prove_verify_roundtrip() {
        let _guard = fold_test_lock().lock().unwrap();
        let actions = sample_actions(3);
        let env = prove_session_fold("sess-fold", &actions).unwrap();
        assert_eq!(env.aggregation_mode, AGGREGATION_NOVA_FOLD);
        assert!(verify_session_fold(&env).unwrap());
    }

    #[test]
    fn fold_rejects_out_of_range_action_metadata() {
        let _guard = fold_test_lock().lock().unwrap();
        let actions = sample_actions(2);
        let mut env = prove_session_fold("sess-fold", &actions).unwrap();
        env.actions[0].score_scaled = "2000000".into();
        assert!(verify_session_fold(&env).is_err());
    }

    #[test]
    fn pp_regeneration_invalidates_stale_compressed_keys() {
        let _guard = fold_test_lock().lock().unwrap();
        let temp = std::env::temp_dir().join(format!(
            "agent-receipts-session-fold-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        std::env::set_var(SESSION_FOLD_KEYS_DIR_ENV, &temp);

        fs::write(artifact_path("compressed_pk"), b"stale-pk").unwrap();
        fs::write(artifact_path("compressed_vk"), b"stale-vk").unwrap();
        assert!(artifact_path("compressed_pk").is_file());
        assert!(artifact_path("compressed_vk").is_file());

        let _ = load_or_setup_pp().unwrap();

        assert!(!artifact_path("compressed_pk").exists());
        assert!(!artifact_path("compressed_vk").exists());
        assert!(artifact_path("pp").is_file());

        std::env::remove_var(SESSION_FOLD_KEYS_DIR_ENV);
        let _ = fs::remove_dir_all(&temp);
    }
}
