//! RISC Zero host for the fraud-head zkVM proof (SOTA-8).
//!
//! Subcommands:
//!   prove  --amount <f64> --output-hash <hex> --model-provenance-hash <hex> [--json]
//!   verify --image-id <hex> --amount <f64> --output-hash <hex>
//!           --model-provenance-hash <hex> --score <f64> --receipt-hex <hex>
//!
//! Proving uses a universal zkVM (no per-model trusted setup): the same `image_id`
//! identifies the fraud-head program regardless of inputs, unlike EZKL's per-circuit
//! proving/verifying keys.

use std::process::exit;

use fraud_head_methods::{FRAUD_HEAD_GUEST_ELF, FRAUD_HEAD_GUEST_ID};
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

const VERSION: &str = env!("CARGO_PKG_VERSION");

type FraudHeadJournal = (f64, String, String, f64);

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("{}", msg.as_ref());
    exit(1);
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

fn image_id_hex() -> String {
    Digest::from(FRAUD_HEAD_GUEST_ID).to_string()
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

    let env = ExecutorEnv::builder()
        .write(&amount)
        .unwrap_or_else(|e| die(format!("write amount: {e}")))
        .write(&output_hash)
        .unwrap_or_else(|e| die(format!("write output_hash: {e}")))
        .write(&model_provenance_hash)
        .unwrap_or_else(|e| die(format!("write model_provenance_hash: {e}")))
        .build()
        .unwrap_or_else(|e| die(format!("build env: {e}")));

    let start = std::time::Instant::now();
    let prove_info = default_prover()
        .prove(env, FRAUD_HEAD_GUEST_ELF)
        .unwrap_or_else(|e| die(format!("prove: {e}")));
    let prove_ms = start.elapsed().as_millis() as u64;

    let receipt = prove_info.receipt;
    let (journal_amount, journal_output, journal_model, score): FraudHeadJournal = receipt
        .journal
        .decode()
        .unwrap_or_else(|e| die(format!("decode journal: {e}")));
    let receipt_bytes =
        bincode::serialize(&receipt).unwrap_or_else(|e| die(format!("serialize receipt: {e}")));

    let report = serde_json::json!({
        "image_id": image_id_hex(),
        "amount": journal_amount,
        "output_hash": journal_output,
        "model_provenance_hash": journal_model,
        "score": score,
        "prove_ms": prove_ms,
        "receipt_bytes": receipt_bytes.len(),
        "receipt_hex": hex::encode(&receipt_bytes),
    });
    let json = if args.iter().any(|a| a == "--json") {
        serde_json::to_string(&report).unwrap()
    } else {
        serde_json::to_string_pretty(&report).unwrap()
    };
    println!("{json}");
}

fn cmd_verify(args: &[String]) {
    let expected_id = arg_value(args, "--image-id")
        .unwrap_or_else(|| die("verify requires --image-id <hex>"));
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

    if expected_id != image_id_hex() {
        die(format!(
            "image_id mismatch: envelope {expected_id} != local {}",
            image_id_hex()
        ));
    }

    let bytes = hex::decode(receipt_hex).unwrap_or_else(|e| die(format!("bad receipt hex: {e}")));
    let receipt: Receipt =
        bincode::deserialize(&bytes).unwrap_or_else(|e| die(format!("decode receipt: {e}")));

    receipt
        .verify(FRAUD_HEAD_GUEST_ID)
        .unwrap_or_else(|e| die(format!("receipt verification failed: {e}")));

    let (amount, output_hash, model_hash, score): FraudHeadJournal = receipt
        .journal
        .decode()
        .unwrap_or_else(|e| die(format!("decode journal: {e}")));
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
        "ok image_id={expected_id} amount={amount} score={score} output_hash={output_hash}"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => println!("agent-receipts-zkvm {VERSION}"),
        Some("prove") => cmd_prove(&args[1..]),
        Some("verify") => cmd_verify(&args[1..]),
        _ => {
            eprintln!("usage: agent-receipts-zkvm <prove|verify|--version> [flags]");
            exit(2);
        }
    }
}
