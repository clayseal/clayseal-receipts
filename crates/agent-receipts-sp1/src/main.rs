//! SP1 host for the fraud-head zkVM proof (SOTA-12).
//!
//! Subcommands:
//!   prove  --amount <f64> --output-hash <hex> --model-provenance-hash <hex> [--json]
//!   verify --vk-hash <hex> --amount <f64> --output-hash <hex>
//!           --model-provenance-hash <hex> --score <f64> --receipt-hex <hex>
//!
//! Proving uses a universal zkVM (no per-model trusted setup): the same program verification
//! key hash identifies the fraud-head program regardless of inputs, analogous to RISC Zero's
//! `image_id` (stored in `InferenceProofEnvelope.image_id` when `attestation` is `sp1`).

use std::fs;
use std::path::PathBuf;
use std::process::exit;

use sp1_sdk::{HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};

const VERSION: &str = env!("CARGO_PKG_VERSION");

type FraudHeadJournal = (f64, String, String, f64);

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("{}", msg.as_ref());
    exit(1);
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn normalize_vk_hash(hash: &str) -> String {
    hash.trim()
        .strip_prefix("0x")
        .unwrap_or(hash.trim())
        .to_ascii_lowercase()
}

fn vk_hash_hex(vk: &SP1VerifyingKey) -> String {
    normalize_vk_hash(&vk.bytes32())
}

fn resolve_elf() -> (Vec<u8>, String) {
    if let Ok(path) = std::env::var("SP1_FRAUD_ELF") {
        let bytes = fs::read(&path).unwrap_or_else(|e| {
            die(format!("read SP1_FRAUD_ELF {path}: {e}"))
        });
        return (bytes, path);
    }
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("program/target/elf-compilation");
    for sub in [
        "riscv32im-succinct-zkvm-elf/release/fraud-head-program",
        "riscv64im-succinct-zkvm-elf/release/fraud-head-program",
    ] {
        let path = base.join(sub);
        if path.is_file() {
            let bytes = fs::read(&path).unwrap_or_else(|e| {
                die(format!("read guest ELF {}: {e}", path.display()))
            });
            return (bytes, path.display().to_string());
        }
    }
    die(
        "guest ELF not found — run scripts/sp1_build_fraud_head.sh (requires sp1up; pin CLI to match sp1-sdk 6.3.1)",
    )
}

fn local_vk_hash() -> String {
    let (elf, _) = resolve_elf();
    let client = ProverClient::from_env();
    let (_, vk) = client.setup(&elf);
    vk_hash_hex(&vk)
}

fn cmd_prove(args: &[String]) {
    let amount: f64 = arg_value(args, "--amount")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| die("prove requires --amount <f64>"));
    let output_hash = arg_value(args, "--output-hash")
        .unwrap_or_else(|| die("prove requires --output-hash <hex>"));
    let model_provenance_hash = arg_value(args, "--model-provenance-hash").unwrap_or_else(|| {
        die("prove requires --model-provenance-hash <hex>")
    });

    let (elf, elf_path) = resolve_elf();
    let mut stdin = SP1Stdin::new();
    stdin.write(&amount);
    stdin.write(&output_hash);
    stdin.write(&model_provenance_hash);

    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(&elf);
    let vk_hash = vk_hash_hex(&vk);

    let start = std::time::Instant::now();
    let mut proof = client
        .prove(&pk, &stdin)
        .run()
        .unwrap_or_else(|e| die(format!("prove: {e}")));
    let prove_ms = start.elapsed().as_millis() as u64;

    client
        .verify(&proof, &vk)
        .unwrap_or_else(|e| die(format!("local verify: {e}")));

    let (journal_amount, journal_output, journal_model, score): FraudHeadJournal =
        proof.public_values.read();
    let proof_bytes =
        bincode::serialize(&proof).unwrap_or_else(|e| die(format!("serialize proof: {e}")));

    let report = serde_json::json!({
        "backend": "sp1",
        "vk_hash": vk_hash,
        "image_id": vk_hash,
        "elf_path": elf_path,
        "amount": journal_amount,
        "output_hash": journal_output,
        "model_provenance_hash": journal_model,
        "score": score,
        "prove_ms": prove_ms,
        "proof_bytes": proof_bytes.len(),
        "receipt_bytes": proof_bytes.len(),
        "receipt_hex": hex::encode(&proof_bytes),
    });
    let json = if args.iter().any(|a| a == "--json") {
        serde_json::to_string(&report).unwrap()
    } else {
        serde_json::to_string_pretty(&report).unwrap()
    };
    println!("{json}");
}

fn cmd_verify(args: &[String]) {
    let expected_vk = arg_value(args, "--vk-hash")
        .or_else(|| arg_value(args, "--image-id"))
        .unwrap_or_else(|| die("verify requires --vk-hash <hex> (or --image-id)"));
    let expected_amount: f64 = arg_value(args, "--amount")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| die("verify requires --amount <f64>"));
    let expected_output_hash = arg_value(args, "--output-hash")
        .unwrap_or_else(|| die("verify requires --output-hash <hex>"));
    let expected_model_hash = arg_value(args, "--model-provenance-hash").unwrap_or_else(|| {
        die("verify requires --model-provenance-hash <hex>")
    });
    let expected_score: f64 = arg_value(args, "--score")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| die("verify requires --score <f64>"));
    let receipt_hex = arg_value(args, "--receipt-hex")
        .unwrap_or_else(|| die("verify requires --receipt-hex <hex>"));

    if normalize_vk_hash(&expected_vk) != local_vk_hash() {
        die(format!(
            "vk_hash mismatch: envelope {} != local {}",
            normalize_vk_hash(&expected_vk),
            local_vk_hash()
        ));
    }

    let bytes = hex::decode(receipt_hex).unwrap_or_else(|e| die(format!("bad receipt hex: {e}")));
    let mut proof: SP1ProofWithPublicValues = bincode::deserialize(&bytes)
        .unwrap_or_else(|e| die(format!("decode proof: {e}")));

    let (elf, _) = resolve_elf();
    let client = ProverClient::from_env();
    let (_, vk) = client.setup(&elf);
    client
        .verify(&proof, &vk)
        .unwrap_or_else(|e| die(format!("proof verification failed: {e}")));

    let (amount, output_hash, model_hash, score): FraudHeadJournal = proof.public_values.read();
    if (amount - expected_amount).abs() > 1e-9 {
        die(format!(
            "journal amount {amount} != expected {expected_amount}"
        ));
    }
    if output_hash != expected_output_hash {
        die(format!(
            "journal output_hash {output_hash} != expected {expected_output_hash}"
        ));
    }
    if model_hash != expected_model_hash {
        die(format!(
            "journal model_provenance_hash {model_hash} != expected {expected_model_hash}"
        ));
    }
    if (score - expected_score).abs() > 1e-9 {
        die(format!(
            "journal score {score} != expected {expected_score}"
        ));
    }
    println!(
        "ok vk_hash={} amount={amount} score={score} output_hash={output_hash}",
        normalize_vk_hash(&expected_vk)
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => println!("agent-receipts-sp1 {VERSION}"),
        Some("prove") => cmd_prove(&args[1..]),
        Some("verify") => cmd_verify(&args[1..]),
        _ => {
            eprintln!("usage: agent-receipts-sp1 <prove|verify|--version> [flags]");
            exit(2);
        }
    }
}
