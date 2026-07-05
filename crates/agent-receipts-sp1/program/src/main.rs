//! Fraud-head SP1 guest program (SOTA-12).
//!
//! Reads transaction `amount`, output/model commitments, applies the canonical fraud-head
//! rule, and commits `(amount, output_hash, model_provenance_hash, score)` to the public
//! values. The rule mirrors `agent_receipts_composed::inference::fraud_head_score` and the
//! RISC Zero guest, so both zkVM backends attest to the same computation.
#![no_main]
sp1_zkvm::entrypoint!(main);

type FraudHeadJournal = (f64, String, String, f64);

pub fn main() {
    let amount = sp1_zkvm::io::read::<f64>();
    let output_hash = sp1_zkvm::io::read::<String>();
    let model_provenance_hash = sp1_zkvm::io::read::<String>();
    let score = (amount / 10_000.0).clamp(0.0, 1.0);
    sp1_zkvm::io::commit(&(amount, output_hash, model_provenance_hash, score));
}
