use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InferenceProofError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ezkl: {0}")]
    Ezkl(String),
    #[error("envelope: {0}")]
    Envelope(String),
    #[error("stub proofs are not valid in production verification")]
    StubNotAllowed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InferenceAttestation {
    /// Halo2 proof compiled from the ONNX head by EZKL (per-model setup).
    Ezkl,
    /// RISC Zero zkVM receipt over the fraud-head program (no per-model setup; SOTA-8).
    Risc0,
    /// SP1 (Plonky3) zkVM proof over the fraud-head program (no per-model setup; SOTA-12).
    Sp1,
    Stub,
}

/// Canonical fraud-head computation: `amount -> fraud_score`.
///
/// This is the single source of truth for the head's semantics. The EZKL circuit,
/// the RISC Zero guest, and the stub all commit to this exact function, so a proof
/// in any backend attests to the same scoring rule.
pub fn fraud_head_score(amount: f64) -> f64 {
    (amount / 10_000.0).clamp(0.0, 1.0)
}

/// EZKL (or stub) inference proof artifact for the fraud head circuit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InferenceProofEnvelope {
    pub version: u32,
    pub circuit_id: String,
    pub attestation: InferenceAttestation,
    pub model_provenance_hash: String,
    /// Transaction amount scored by the fraud head (bound into the proof).
    #[serde(default)]
    pub amount: f64,
    pub input_hash: String,
    pub output_hash: String,
    /// Scaled fraud score committed by the proof (float for verifier binding checks).
    pub public_score: f64,
    /// Relative paths under `circuits/fraud_head/ezkl/` or hex-encoded proof bytes.
    pub proof_path: Option<String>,
    pub proof_hex: Option<String>,
    pub settings_path: Option<String>,
    pub vk_path: Option<String>,
    pub srs_path: Option<String>,
    /// zkVM verification anchor (hex): RISC Zero guest `image_id` or SP1 program vk hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_id: Option<String>,
}

impl InferenceProofEnvelope {
    pub const CIRCUIT_ID: &'static str = "fraud_head_ezkl_v1";
}

pub fn fraud_head_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circuits/fraud_head")
}

pub fn ezkl_dir() -> PathBuf {
    fraud_head_dir().join("ezkl")
}

pub fn hash_bytes(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn hash_json_value<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hash_bytes(&bytes))
}

fn ezkl_available() -> bool {
    Command::new("ezkl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn prove_inference_ezkl(
    amount: f64,
    model_provenance_hash: &str,
    output_hash: &str,
    allow_stub: bool,
) -> Result<InferenceProofEnvelope, InferenceProofError> {
    let ezkl = ezkl_dir();
    let compiled = ezkl.join("model.compiled");
    if !compiled.exists() {
        if allow_stub {
            return Ok(stub_envelope(amount, model_provenance_hash, output_hash));
        }
        return Err(InferenceProofError::Ezkl(format!(
            "missing compiled circuit at {} — run scripts/ezkl_setup_fraud_head.sh",
            compiled.display()
        )));
    }
    if !ezkl_available() {
        if allow_stub {
            return Ok(stub_envelope(amount, model_provenance_hash, output_hash));
        }
        return Err(InferenceProofError::Ezkl("ezkl binary not on PATH".into()));
    }

    let score = fraud_head_score(amount);
    let input = serde_json::json!({
        "input_data": [[amount]],
        "output_data": [[score]],
    });
    let input_path = ezkl.join("witness_input.json");
    fs::write(&input_path, serde_json::to_vec_pretty(&input)?)?;

    let witness = ezkl.join("witness.json");
    let proof = ezkl.join("proof.json");
    let pk = ezkl.join("pk.key");
    let srs = ezkl.join("kzg.srs");

    run_ezkl(&["gen-witness", "-D", &path_str(&input_path), "-M", &path_str(&compiled), "-O", &path_str(&witness)])?;
    run_ezkl(&[
        "prove",
        "-M",
        &path_str(&compiled),
        "-W",
        &path_str(&witness),
        "--pk-path",
        &path_str(&pk),
        "--proof-path",
        &path_str(&proof),
        "--srs-path",
        &path_str(&srs),
    ])?;

    let proof_bytes = fs::read(&proof)?;
  Ok(InferenceProofEnvelope {
        version: 1,
        circuit_id: InferenceProofEnvelope::CIRCUIT_ID.to_string(),
        attestation: InferenceAttestation::Ezkl,
        model_provenance_hash: model_provenance_hash.to_string(),
        amount,
        input_hash: hash_json_value(&serde_json::json!({"amount": amount}))?,
        output_hash: output_hash.to_string(),
        public_score: score,
        proof_path: Some(relative_ezkl("proof.json")),
        proof_hex: Some(hex::encode(proof_bytes)),
        settings_path: Some(relative_ezkl("settings.json")),
        vk_path: Some(relative_ezkl("vk.key")),
        srs_path: Some(relative_ezkl("kzg.srs")),
        image_id: None,
    })
}

/// Configurable RISC Zero host binary (built from `crates/agent-receipts-zkvm`).
fn zkvm_bin() -> String {
    std::env::var("AGENT_RECEIPTS_ZKVM_BIN").unwrap_or_else(|_| "agent-receipts-zkvm".to_string())
}

fn zkvm_available() -> bool {
    Command::new(zkvm_bin())
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Prove the fraud head with a RISC Zero zkVM receipt (no per-model trusted setup).
///
/// Delegates proving to the `agent-receipts-zkvm` host (kept out of this crate's build so
/// the default workspace does not require the zkVM toolchain). The returned envelope binds
/// the guest `image_id` and the receipt bytes; verification re-runs the zkVM verifier.
pub fn prove_inference_risc0(
    amount: f64,
    model_provenance_hash: &str,
    output_hash: &str,
    allow_stub: bool,
) -> Result<InferenceProofEnvelope, InferenceProofError> {
    if !zkvm_available() {
        if allow_stub {
            return Ok(stub_envelope(amount, model_provenance_hash, output_hash));
        }
        return Err(InferenceProofError::Ezkl(format!(
            "zkVM host `{}` not on PATH — build crates/agent-receipts-zkvm",
            zkvm_bin()
        )));
    }
    let out = Command::new(zkvm_bin())
        .args([
            "prove",
            "--amount",
            &amount.to_string(),
            "--output-hash",
            output_hash,
            "--model-provenance-hash",
            model_provenance_hash,
            "--json",
        ])
        .output()?;
    if !out.status.success() {
        return Err(InferenceProofError::Ezkl(format!(
            "zkVM prove failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let image_id = report["image_id"]
        .as_str()
        .ok_or_else(|| InferenceProofError::Envelope("zkVM output missing image_id".into()))?;
    let receipt_hex = report["receipt_hex"]
        .as_str()
        .ok_or_else(|| InferenceProofError::Envelope("zkVM output missing receipt_hex".into()))?;
    Ok(InferenceProofEnvelope {
        version: 1,
        circuit_id: InferenceProofEnvelope::CIRCUIT_ID.to_string(),
        attestation: InferenceAttestation::Risc0,
        model_provenance_hash: model_provenance_hash.to_string(),
        amount,
        input_hash: hash_json_value(&serde_json::json!({ "amount": amount }))?,
        output_hash: output_hash.to_string(),
        public_score: fraud_head_score(amount),
        proof_path: None,
        proof_hex: Some(receipt_hex.to_string()),
        settings_path: None,
        vk_path: None,
        srs_path: None,
        image_id: Some(image_id.to_string()),
    })
}

/// Configurable SP1 host binary (built from `crates/agent-receipts-sp1`).
fn sp1_bin() -> String {
    std::env::var("AGENT_RECEIPTS_SP1_BIN").unwrap_or_else(|_| "agent-receipts-sp1".to_string())
}

fn sp1_available() -> bool {
    Command::new(sp1_bin())
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Prove the fraud head with an SP1 (Plonky3) zkVM proof (no per-model trusted setup).
///
/// Delegates proving to the `agent-receipts-sp1` host (kept out of this crate's build so
/// the default workspace does not require the SP1 toolchain). The returned envelope binds
/// the program vk hash (`image_id`) and the proof bytes; verification re-runs the SP1 verifier.
pub fn prove_inference_sp1(
    amount: f64,
    model_provenance_hash: &str,
    output_hash: &str,
    allow_stub: bool,
) -> Result<InferenceProofEnvelope, InferenceProofError> {
    if !sp1_available() {
        if allow_stub {
            return Ok(stub_envelope(amount, model_provenance_hash, output_hash));
        }
        return Err(InferenceProofError::Ezkl(format!(
            "SP1 host `{}` not on PATH — build crates/agent-receipts-sp1",
            sp1_bin()
        )));
    }
    let out = Command::new(sp1_bin())
        .args([
            "prove",
            "--amount",
            &amount.to_string(),
            "--output-hash",
            output_hash,
            "--model-provenance-hash",
            model_provenance_hash,
            "--json",
        ])
        .output()?;
    if !out.status.success() {
        return Err(InferenceProofError::Ezkl(format!(
            "SP1 prove failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let report: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let vk_hash = report["vk_hash"]
        .as_str()
        .or_else(|| report["image_id"].as_str())
        .ok_or_else(|| InferenceProofError::Envelope("SP1 output missing vk_hash".into()))?;
    let receipt_hex = report["receipt_hex"]
        .as_str()
        .ok_or_else(|| InferenceProofError::Envelope("SP1 output missing receipt_hex".into()))?;
    Ok(InferenceProofEnvelope {
        version: 1,
        circuit_id: InferenceProofEnvelope::CIRCUIT_ID.to_string(),
        attestation: InferenceAttestation::Sp1,
        model_provenance_hash: model_provenance_hash.to_string(),
        amount,
        input_hash: hash_json_value(&serde_json::json!({ "amount": amount }))?,
        output_hash: output_hash.to_string(),
        public_score: fraud_head_score(amount),
        proof_path: None,
        proof_hex: Some(receipt_hex.to_string()),
        settings_path: None,
        vk_path: None,
        srs_path: None,
        image_id: Some(vk_hash.to_string()),
    })
}

fn verify_inference_envelope_bindings(
    envelope: &InferenceProofEnvelope,
) -> Result<(), InferenceProofError> {
    if envelope.output_hash.is_empty() {
        return Err(InferenceProofError::Envelope("missing output_hash".into()));
    }
    if envelope.model_provenance_hash.is_empty() {
        return Err(InferenceProofError::Envelope(
            "missing model_provenance_hash".into(),
        ));
    }
    if envelope.input_hash.is_empty() {
        return Err(InferenceProofError::Envelope("missing input_hash".into()));
    }
    let expected_input = hash_json_value(&serde_json::json!({"amount": envelope.amount}))?;
    if envelope.input_hash != expected_input {
        return Err(InferenceProofError::Envelope(
            "input_hash does not match amount".into(),
        ));
    }
    let expected_score = fraud_head_score(envelope.amount);
    if (envelope.public_score - expected_score).abs() > 1e-9 {
        return Err(InferenceProofError::Envelope(
            "public_score does not match amount under fraud_head_score".into(),
        ));
    }
    Ok(())
}

fn verify_inference_risc0(
    envelope: &InferenceProofEnvelope,
) -> Result<bool, InferenceProofError> {
    verify_inference_envelope_bindings(envelope)?;
    if !zkvm_available() {
        return Err(InferenceProofError::Ezkl(format!(
            "zkVM host `{}` not on PATH",
            zkvm_bin()
        )));
    }
    let image_id = envelope
        .image_id
        .as_deref()
        .ok_or_else(|| InferenceProofError::Envelope("Risc0 envelope missing image_id".into()))?;
    let receipt_hex = envelope
        .proof_hex
        .as_deref()
        .ok_or_else(|| InferenceProofError::Envelope("Risc0 envelope missing receipt_hex".into()))?;
    let out = Command::new(zkvm_bin())
        .args([
            "verify",
            "--image-id",
            image_id,
            "--amount",
            &envelope.amount.to_string(),
            "--output-hash",
            &envelope.output_hash,
            "--model-provenance-hash",
            &envelope.model_provenance_hash,
            "--score",
            &envelope.public_score.to_string(),
            "--receipt-hex",
            receipt_hex,
        ])
        .output()?;
    if !out.status.success() {
        return Err(InferenceProofError::Ezkl(format!(
            "zkVM verify failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(true)
}

fn verify_inference_sp1(envelope: &InferenceProofEnvelope) -> Result<bool, InferenceProofError> {
    verify_inference_envelope_bindings(envelope)?;
    if !sp1_available() {
        return Err(InferenceProofError::Ezkl(format!(
            "SP1 host `{}` not on PATH",
            sp1_bin()
        )));
    }
    let vk_hash = envelope
        .image_id
        .as_deref()
        .ok_or_else(|| InferenceProofError::Envelope("Sp1 envelope missing vk_hash/image_id".into()))?;
    let receipt_hex = envelope
        .proof_hex
        .as_deref()
        .ok_or_else(|| InferenceProofError::Envelope("Sp1 envelope missing receipt_hex".into()))?;
    let out = Command::new(sp1_bin())
        .args([
            "verify",
            "--vk-hash",
            vk_hash,
            "--amount",
            &envelope.amount.to_string(),
            "--output-hash",
            &envelope.output_hash,
            "--model-provenance-hash",
            &envelope.model_provenance_hash,
            "--score",
            &envelope.public_score.to_string(),
            "--receipt-hex",
            receipt_hex,
        ])
        .output()?;
    if !out.status.success() {
        return Err(InferenceProofError::Ezkl(format!(
            "SP1 verify failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(true)
}

fn stub_envelope(amount: f64, model_hash: &str, output_hash: &str) -> InferenceProofEnvelope {
    InferenceProofEnvelope {
        version: 1,
        circuit_id: InferenceProofEnvelope::CIRCUIT_ID.to_string(),
        attestation: InferenceAttestation::Stub,
        model_provenance_hash: model_hash.to_string(),
        amount,
        input_hash: hash_json_value(&serde_json::json!({"amount": amount}))
            .unwrap_or_else(|_| hash_bytes(format!("{{\"amount\":{amount}}}").as_bytes())),
        output_hash: output_hash.to_string(),
        public_score: fraud_head_score(amount),
        proof_path: None,
        proof_hex: Some(hex::encode(b"STUB_INFERENCE_V1")),
        settings_path: None,
        vk_path: None,
        srs_path: None,
        image_id: None,
    }
}

pub fn verify_inference_envelope(
    envelope: &InferenceProofEnvelope,
    allow_stub: bool,
) -> Result<bool, InferenceProofError> {
    if envelope.circuit_id != InferenceProofEnvelope::CIRCUIT_ID {
        return Err(InferenceProofError::Envelope(format!(
            "unknown circuit_id {}",
            envelope.circuit_id
        )));
    }
    match envelope.attestation {
        InferenceAttestation::Stub => {
            if allow_stub {
                return Ok(true);
            }
            return Err(InferenceProofError::StubNotAllowed);
        }
        InferenceAttestation::Risc0 => return verify_inference_risc0(envelope),
        InferenceAttestation::Sp1 => return verify_inference_sp1(envelope),
        InferenceAttestation::Ezkl => {}
    }
    if !ezkl_available() {
        return Err(InferenceProofError::Ezkl("ezkl binary not on PATH".into()));
    }
    let ezkl = ezkl_dir();
    let proof = envelope
        .proof_path
        .as_ref()
        .map(|p| ezkl.join(p))
        .ok_or_else(|| InferenceProofError::Envelope("missing proof_path".into()))?;
    let settings = ezkl.join(
        envelope
            .settings_path
            .as_deref()
            .unwrap_or("settings.json"),
    );
    let vk = ezkl.join(envelope.vk_path.as_deref().unwrap_or("vk.key"));
    let srs = ezkl.join(envelope.srs_path.as_deref().unwrap_or("kzg.srs"));

    run_ezkl(&[
        "verify",
        "--proof-path",
        &path_str(&proof),
        "-S",
        &path_str(&settings),
        "--vk-path",
        &path_str(&vk),
        "--srs-path",
        &path_str(&srs),
    ])?;
    verify_inference_envelope_bindings(envelope)?;
    Ok(true)
}

fn relative_ezkl(name: &str) -> String {
    name.to_string()
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn run_ezkl(args: &[&str]) -> Result<(), InferenceProofError> {
    let out = Command::new("ezkl").args(args).output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(InferenceProofError::Ezkl(format!(
            "ezkl {} failed: {stdout}{stderr}",
            args.first().unwrap_or(&"?")
        )));
    }
    Ok(())
}

pub fn envelope_to_json(envelope: &InferenceProofEnvelope) -> Result<String, serde_json::Error> {
    serde_json::to_string(envelope)
}

pub fn envelope_from_json(json: &str) -> Result<InferenceProofEnvelope, serde_json::Error> {
    serde_json::from_str(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fraud_head_score_is_the_committed_rule() {
        // The score backends all attest to this exact function.
        for amount in [0.0_f64, 1234.5, 9_999.0, 10_000.0, 25_000.0] {
            let expected = (amount / 10_000.0).clamp(0.0, 1.0);
            assert_eq!(fraud_head_score(amount), expected);
        }
        assert_eq!(fraud_head_score(-50.0), 0.0); // clamped low
        assert_eq!(fraud_head_score(1e9), 1.0); // clamped high
    }

    #[test]
    fn risc0_envelope_roundtrips_with_image_id() {
        let env = InferenceProofEnvelope {
            version: 1,
            circuit_id: InferenceProofEnvelope::CIRCUIT_ID.to_string(),
            attestation: InferenceAttestation::Risc0,
            model_provenance_hash: "model".into(),
            amount: 7_500.0,
            input_hash: "in".into(),
            output_hash: "out".into(),
            public_score: fraud_head_score(7_500.0),
            proof_path: None,
            proof_hex: Some("abcd".into()),
            settings_path: None,
            vk_path: None,
            srs_path: None,
            image_id: Some("deadbeef".into()),
        };
        let json = envelope_to_json(&env).unwrap();
        assert_eq!(envelope_from_json(&json).unwrap(), env);
    }

    #[test]
    fn envelope_bindings_reject_score_mismatch() {
        let mut env = stub_envelope(5_000.0, "model", "out");
        env.public_score = 0.99;
        assert!(verify_inference_envelope_bindings(&env).is_err());
    }

    #[test]
    fn envelope_bindings_reject_input_hash_mismatch() {
        let mut env = stub_envelope(5_000.0, "model", "out");
        env.input_hash = "bad".into();
        assert!(verify_inference_envelope_bindings(&env).is_err());
    }

    #[test]
    fn risc0_verify_requires_the_zkvm_host() {
        std::env::set_var("AGENT_RECEIPTS_ZKVM_BIN", "agent-receipts-zkvm-does-not-exist");
        let env = InferenceProofEnvelope {
            version: 1,
            circuit_id: InferenceProofEnvelope::CIRCUIT_ID.to_string(),
            attestation: InferenceAttestation::Risc0,
            model_provenance_hash: "m".into(),
            amount: 1_000.0,
            input_hash: hash_json_value(&serde_json::json!({"amount": 1000.0})).unwrap(),
            output_hash: "out".into(),
            public_score: fraud_head_score(1_000.0),
            proof_path: None,
            proof_hex: Some("abcd".into()),
            settings_path: None,
            vk_path: None,
            srs_path: None,
            image_id: Some("deadbeef".into()),
        };
        assert!(verify_inference_envelope(&env, false).is_err());
        std::env::remove_var("AGENT_RECEIPTS_ZKVM_BIN");
    }

    #[test]
    fn sp1_envelope_roundtrips_with_vk_hash() {
        let env = InferenceProofEnvelope {
            version: 1,
            circuit_id: InferenceProofEnvelope::CIRCUIT_ID.to_string(),
            attestation: InferenceAttestation::Sp1,
            model_provenance_hash: "model".into(),
            amount: 7_500.0,
            input_hash: "in".into(),
            output_hash: "out".into(),
            public_score: fraud_head_score(7_500.0),
            proof_path: None,
            proof_hex: Some("abcd".into()),
            settings_path: None,
            vk_path: None,
            srs_path: None,
            image_id: Some("deadbeef".into()),
        };
        let json = envelope_to_json(&env).unwrap();
        assert_eq!(envelope_from_json(&json).unwrap(), env);
    }

    #[test]
    fn sp1_verify_requires_the_sp1_host() {
        std::env::set_var("AGENT_RECEIPTS_SP1_BIN", "agent-receipts-sp1-does-not-exist");
        let env = InferenceProofEnvelope {
            version: 1,
            circuit_id: InferenceProofEnvelope::CIRCUIT_ID.to_string(),
            attestation: InferenceAttestation::Sp1,
            model_provenance_hash: "m".into(),
            amount: 1_000.0,
            input_hash: hash_json_value(&serde_json::json!({"amount": 1000.0})).unwrap(),
            output_hash: "out".into(),
            public_score: fraud_head_score(1_000.0),
            proof_path: None,
            proof_hex: Some("abcd".into()),
            settings_path: None,
            vk_path: None,
            srs_path: None,
            image_id: Some("deadbeef".into()),
        };
        assert!(verify_inference_envelope(&env, false).is_err());
        std::env::remove_var("AGENT_RECEIPTS_SP1_BIN");
    }
}
