use std::fs;
use std::path::PathBuf;

use agent_receipts_composed::{
    compose_from_json_parts, compose_proofs, compose_proofs_recursive, composed_from_json,
    composed_to_json, prove_inference_ezkl, prove_inference_risc0, prove_inference_sp1,
    verify_composed,
    verify_inference_envelope, ComposedBindings, InferenceProofEnvelope,
};
use agent_receipts_policy_circuit::{
    envelope_from_json, envelope_to_json, load_or_setup, prove_policy_range,
    prove_policy_range_confidential, setup_policy_range_keys, verify_policy_range,
    verify_policy_range_confidential, ConfidentialPolicyProofEnvelope, PolicyProofEnvelope,
};
use agent_receipts_session::{
    prove_session, session_from_json, session_to_json, verify_session, SessionActionInput,
    SessionProofEnvelope,
};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "agent-receipts",
    about = "Agent Receipts: policy (Halo2) + inference (EZKL) proofs"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate Halo2 params and proving keys under keys/
    Setup,
    /// Prove a numeric range policy on fraud_score
    ProvePolicy {
        #[arg(long)]
        score: f64,
        #[arg(long, default_value = "0.0")]
        min: f64,
        #[arg(long, default_value = "1.0")]
        max: f64,
        #[arg(long)]
        policy_commitment: String,
        #[arg(long)]
        output_hash: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        output_json: Option<PathBuf>,
        #[arg(long)]
        required_field: Vec<String>,
    },
    /// Verify a PolicyProofEnvelope JSON file
    VerifyPolicy {
        #[arg(long)]
        envelope: PathBuf,
    },
    /// Prove a range policy over a HIDDEN score (confidential, SOTA-9)
    ProvePolicyConfidential {
        #[arg(long)]
        score: f64,
        #[arg(long, default_value = "0.0")]
        min: f64,
        #[arg(long, default_value = "1.0")]
        max: f64,
        #[arg(long)]
        policy_commitment: String,
        #[arg(long)]
        output_hash: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a confidential policy proof (verifier never learns the score)
    VerifyPolicyConfidential {
        #[arg(long)]
        envelope: PathBuf,
    },
    /// Prove EZKL inference for fraud head (amount -> score)
    ProveInference {
        #[arg(long)]
        amount: f64,
        #[arg(long)]
        model_provenance_hash: String,
        #[arg(long)]
        output_hash: String,
        #[arg(long)]
        out: PathBuf,
        /// Inference backend: "ezkl" (per-model Halo2), "risc0", or "sp1" (zkVM, no setup).
        #[arg(long, default_value = "ezkl")]
        backend: String,
        #[arg(long, default_value_t = false)]
        allow_stub: bool,
    },
    /// Verify an InferenceProofEnvelope JSON file
    VerifyInference {
        #[arg(long)]
        envelope: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_stub: bool,
    },
    /// Compose policy + inference envelopes with bindings
    Compose {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        inference: PathBuf,
        #[arg(long)]
        output_hash: String,
        #[arg(long)]
        policy_commitment: String,
        #[arg(long)]
        model_provenance_hash: String,
        #[arg(long)]
        context_hash: String,
        #[arg(long)]
        public_score: f64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a ComposedProofEnvelope
    VerifyComposed {
        #[arg(long)]
        envelope: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_stub: bool,
    },
    /// One-shot: prove policy + inference + compose
    ProveComposed {
        #[arg(long)]
        amount: f64,
        #[arg(long)]
        fraud_score: f64,
        #[arg(long, default_value = "0.0")]
        min: f64,
        #[arg(long, default_value = "1.0")]
        max: f64,
        #[arg(long)]
        policy_commitment: String,
        #[arg(long)]
        model_provenance_hash: String,
        #[arg(long)]
        output_hash: String,
        #[arg(long)]
        context_hash: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_stub: bool,
        /// Fold policy ∪ inference into one Nova compressed SNARK (SOTA-10).
        #[arg(long, default_value_t = false)]
        recursive: bool,
        /// Inference backend: "ezkl", "risc0", or "sp1".
        #[arg(long, default_value = "ezkl")]
        backend: String,
    },
    /// Aggregate N policy-range actions into one session proof
    ProveSession {
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        actions: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "halo2_batch_v1")]
        mode: String,
    },
    /// Verify a SessionProofEnvelope JSON file
    VerifySession {
        #[arg(long)]
        envelope: PathBuf,
    },
    /// Benchmark session verify vs N independent policy verifies
    BenchmarkSession {
        #[arg(long, default_value_t = 5)]
        actions: usize,
        #[arg(long, default_value = "halo2_batch_v1")]
        mode: String,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Commands::Setup => {
            setup_policy_range_keys()?;
            let _ = load_or_setup()?;
            println!("policy keys written under {}", keys_dir().display());
            println!("for inference run: ./scripts/ezkl_setup_fraud_head.sh");
            Ok(())
        }
        Commands::ProvePolicy {
            score,
            min,
            max,
            policy_commitment,
            output_hash,
            out,
            output_json,
            required_field,
        } => {
            let output = read_output_json(output_json.as_ref())?;
            let env = prove_policy_range(
                score,
                min,
                max,
                &policy_commitment,
                &output_hash,
                &required_field,
                &output,
            )
            .map_err(|e| e.to_string())?;
            write_policy(&out, &env)?;
            println!("wrote {}", out.display());
            Ok(())
        }
        Commands::VerifyPolicy { envelope } => {
            let env: PolicyProofEnvelope = read_policy(&envelope)?;
            let ok = verify_policy_range(&env).map_err(|e| e.to_string())?;
            println!("valid={ok}");
            Ok(())
        }
        Commands::ProvePolicyConfidential {
            score,
            min,
            max,
            policy_commitment,
            output_hash,
            out,
        } => {
            let env = prove_policy_range_confidential(
                score,
                min,
                max,
                &policy_commitment,
                &output_hash,
                None,
            )
            .map_err(|e| e.to_string())?;
            let json = serde_json::to_string_pretty(&env).map_err(|e| e.to_string())?;
            write_bytes(&out, json.as_bytes())?;
            println!("wrote {} (score hidden; commitment {})", out.display(), env.score_commitment);
            Ok(())
        }
        Commands::VerifyPolicyConfidential { envelope } => {
            let raw = fs::read_to_string(&envelope).map_err(|e| e.to_string())?;
            let env: ConfidentialPolicyProofEnvelope =
                serde_json::from_str(&raw).map_err(|e| e.to_string())?;
            let ok = verify_policy_range_confidential(&env).map_err(|e| e.to_string())?;
            println!("valid={ok}");
            Ok(())
        }
        Commands::ProveInference {
            amount,
            model_provenance_hash,
            output_hash,
            out,
            backend,
            allow_stub,
        } => {
            let env = match backend.as_str() {
                "ezkl" => {
                    prove_inference_ezkl(amount, &model_provenance_hash, &output_hash, allow_stub)
                }
                "risc0" => {
                    prove_inference_risc0(amount, &model_provenance_hash, &output_hash, allow_stub)
                }
                "sp1" => {
                    prove_inference_sp1(amount, &model_provenance_hash, &output_hash, allow_stub)
                }
                other => return Err(format!("unknown backend {other:?} (ezkl|risc0|sp1)")),
            }
            .map_err(|e| e.to_string())?;
            write_inference(&out, &env)?;
            println!("wrote {} (attestation: {:?})", out.display(), env.attestation);
            Ok(())
        }
        Commands::VerifyInference {
            envelope,
            allow_stub,
        } => {
            let env: InferenceProofEnvelope = read_inference(&envelope)?;
            let ok = verify_inference_envelope(&env, allow_stub).map_err(|e| e.to_string())?;
            println!("valid={ok}");
            Ok(())
        }
        Commands::Compose {
            policy,
            inference,
            output_hash,
            policy_commitment,
            model_provenance_hash,
            context_hash,
            public_score,
            out,
        } => {
            let policy_json = fs::read_to_string(&policy).map_err(|e| e.to_string())?;
            let inference_json = fs::read_to_string(&inference).map_err(|e| e.to_string())?;
            let bindings = ComposedBindings {
                output_hash,
                policy_commitment,
                model_provenance_hash,
                context_hash,
                public_score,
            };
            let composed =
                compose_from_json_parts(&policy_json, &inference_json, bindings).map_err(|e| e.to_string())?;
            write_composed(&out, &composed)?;
            println!("wrote {}", out.display());
            Ok(())
        }
        Commands::VerifyComposed {
            envelope,
            allow_stub,
        } => {
            let env: agent_receipts_composed::ComposedProofEnvelope = read_composed(&envelope)?;
            let ok = verify_composed(&env, allow_stub).map_err(|e| e.to_string())?;
            println!("valid={ok}");
            Ok(())
        }
        Commands::ProveComposed {
            amount,
            fraud_score,
            min,
            max,
            policy_commitment,
            model_provenance_hash,
            output_hash,
            context_hash,
            out,
            allow_stub,
            recursive,
            backend,
        } => {
            let output = serde_json::json!({
                "decision": "approve",
                "fraud_score": fraud_score,
            });
            let required = vec!["decision".into(), "fraud_score".into()];
            let policy = prove_policy_range(
                fraud_score,
                min,
                max,
                &policy_commitment,
                &output_hash,
                &required,
                &output,
            )
            .map_err(|e| e.to_string())?;
            let inference = match backend.as_str() {
                "ezkl" => prove_inference_ezkl(
                    amount,
                    &model_provenance_hash,
                    &output_hash,
                    allow_stub,
                ),
                "risc0" => prove_inference_risc0(
                    amount,
                    &model_provenance_hash,
                    &output_hash,
                    allow_stub,
                ),
                "sp1" => prove_inference_sp1(
                    amount,
                    &model_provenance_hash,
                    &output_hash,
                    allow_stub,
                ),
                other => {
                    return Err(format!("unknown backend {other:?} (ezkl|risc0|sp1)"));
                }
            }
            .map_err(|e| e.to_string())?;
            let bindings = ComposedBindings {
                output_hash: output_hash.clone(),
                policy_commitment,
                model_provenance_hash,
                context_hash,
                public_score: fraud_score,
            };
            let composed = if recursive {
                compose_proofs_recursive(policy, inference, bindings, allow_stub)
                    .map_err(|e| e.to_string())?
            } else {
                compose_proofs(policy, inference, bindings)
            };
            write_composed(&out, &composed)?;
            println!(
                "wrote {} (composition_id={})",
                out.display(),
                composed.composition_id
            );
            Ok(())
        }
        Commands::ProveSession {
            session_id,
            actions,
            out,
            mode,
        } => {
            let action_inputs = read_session_actions(&actions)?;
            let env = prove_session(&session_id, &action_inputs, &mode).map_err(|e| e.to_string())?;
            write_session(&out, &env)?;
            println!(
                "wrote {} (mode={}, actions={})",
                out.display(),
                env.aggregation_mode,
                env.action_count
            );
            Ok(())
        }
        Commands::VerifySession { envelope } => {
            let env: SessionProofEnvelope = read_session(&envelope)?;
            let ok = verify_session(&env).map_err(|e| e.to_string())?;
            println!("valid={ok} mode={}", env.aggregation_mode);
            Ok(())
        }
        Commands::BenchmarkSession { actions, mode } => {
            benchmark_session(actions, &mode)?;
            Ok(())
        }
    }
}

fn read_output_json(path: Option<&PathBuf>) -> Result<serde_json::Value, String> {
    match path {
        Some(p) => {
            let raw = fs::read_to_string(p).map_err(|e| e.to_string())?;
            serde_json::from_str(&raw).map_err(|e| e.to_string())
        }
        None => Ok(serde_json::json!({})),
    }
}

fn keys_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../keys")
}

fn write_policy(path: &PathBuf, env: &PolicyProofEnvelope) -> Result<(), String> {
    let json = envelope_to_json(env).map_err(|e| e.to_string())?;
    write_bytes(path, json.as_bytes())
}

fn write_inference(path: &PathBuf, env: &InferenceProofEnvelope) -> Result<(), String> {
    let json = agent_receipts_composed::inference::envelope_to_json(env).map_err(|e| e.to_string())?;
    write_bytes(path, json.as_bytes())
}

fn write_composed(
    path: &PathBuf,
    env: &agent_receipts_composed::ComposedProofEnvelope,
) -> Result<(), String> {
    let json = composed_to_json(env).map_err(|e| e.to_string())?;
    write_bytes(path, json.as_bytes())
}

fn write_bytes(path: &PathBuf, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(path, bytes).map_err(|e| e.to_string())
}

fn read_policy(path: &PathBuf) -> Result<PolicyProofEnvelope, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    envelope_from_json(&raw).map_err(|e| e.to_string())
}

fn read_inference(path: &PathBuf) -> Result<InferenceProofEnvelope, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    agent_receipts_composed::inference::envelope_from_json(&raw).map_err(|e| e.to_string())
}

fn read_composed(path: &PathBuf) -> Result<agent_receipts_composed::ComposedProofEnvelope, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    composed_from_json(&raw).map_err(|e| e.to_string())
}

fn read_session_actions(path: &PathBuf) -> Result<Vec<SessionActionInput>, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}

fn write_session(path: &PathBuf, env: &SessionProofEnvelope) -> Result<(), String> {
    let json = session_to_json(env).map_err(|e| e.to_string())?;
    write_bytes(path, json.as_bytes())
}

fn read_session(path: &PathBuf) -> Result<SessionProofEnvelope, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    session_from_json(&raw).map_err(|e| e.to_string())
}

fn benchmark_session(action_count: usize, mode: &str) -> Result<(), String> {
    use std::time::Instant;

    if action_count == 0 {
        return Err("action_count must be >= 1".into());
    }
    let _ = load_or_setup().map_err(|e| e.to_string())?;

    let actions: Vec<SessionActionInput> = (0..action_count)
        .map(|i| SessionActionInput {
            score: 0.1 + (i as f64 * 0.01),
            min: 0.0,
            max: 1.0,
            policy_commitment: "bench-policy".into(),
            output_hash: format!("bench-out-{i}"),
            required_fields: vec!["decision".into(), "fraud_score".into()],
            output: serde_json::json!({
                "decision": "approve",
                "fraud_score": 0.1 + (i as f64 * 0.01),
            }),
        })
        .collect();

    let session_env =
        prove_session("bench-session", &actions, mode).map_err(|e| e.to_string())?;

    let mut individual_envs = Vec::with_capacity(action_count);
    for action in &actions {
        let env = prove_policy_range(
            action.score,
            action.min,
            action.max,
            &action.policy_commitment,
            &action.output_hash,
            &action.required_fields,
            &action.output,
        )
        .map_err(|e| e.to_string())?;
        individual_envs.push(env);
    }

    let mut individual_verify_ns = 0u128;
    for env in &individual_envs {
        let start = Instant::now();
        let ok = verify_policy_range(env).map_err(|e| e.to_string())?;
        if !ok {
            return Err("individual policy verify failed".into());
        }
        individual_verify_ns += start.elapsed().as_nanos();
    }

    let session_start = Instant::now();
    let session_ok = verify_session(&session_env).map_err(|e| e.to_string())?;
    let session_verify_ns = session_start.elapsed().as_nanos();

    println!("benchmark actions={action_count} mode={mode}");
    println!("individual_verify_total_ns={individual_verify_ns}");
    println!("session_verify_ns={session_verify_ns}");
    println!(
        "verify_speedup={:.2}x",
        individual_verify_ns as f64 / session_verify_ns.max(1) as f64
    );
    println!("session_proof_bytes={}", session_env.proof_hex.len() / 2);
    println!("valid={session_ok}");
    Ok(())
}
