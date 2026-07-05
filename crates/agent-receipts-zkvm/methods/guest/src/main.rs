// Fraud-head guest program. Runs inside the RISC Zero zkVM.
//
// Reads transaction `amount`, output/model commitments, applies the canonical fraud-head
// rule, and commits `(amount, output_hash, model_provenance_hash, score)` to the journal.
// The rule mirrors `agent_receipts_composed::inference::fraud_head_score`.
use risc0_zkvm::guest::env;

type FraudHeadJournal = (f64, String, String, f64);

fn main() {
    let amount: f64 = env::read();
    let output_hash: String = env::read();
    let model_provenance_hash: String = env::read();
    let score = (amount / 10_000.0).clamp(0.0, 1.0);
    env::commit(&(
        amount,
        output_hash,
        model_provenance_hash,
        score,
    ));
}
