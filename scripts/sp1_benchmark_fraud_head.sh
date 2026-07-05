#!/usr/bin/env bash
# Build the SP1 fraud-head host, prove the same head as the RISC Zero crate, and print a
# JSON report (prove time, proof size, score) for the SOTA-12 benchmark.
# Requires the SP1 toolchain (https://sp1up.succinct.xyz ; run scripts/sp1_build_fraud_head.sh).
#
# Usage: scripts/sp1_benchmark_fraud_head.sh [amount] [output_hash] [model_provenance_hash]
set -euo pipefail

AMOUNT="${1:-25000}"
OUTPUT_HASH="${2:-bench-output-hash}"
MODEL_HASH="${3:-sha256:fraud-head-onnx-v1}"
CRATE="crates/agent-receipts-sp1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

"${ROOT}/scripts/sp1_build_fraud_head.sh"

BIN="${CRATE}/target/release/agent-receipts-sp1"

echo "==> proving fraud head for amount=${AMOUNT} (SP1 core STARK)"
time "${BIN}" prove \
  --amount "${AMOUNT}" \
  --output-hash "${OUTPUT_HASH}" \
  --model-provenance-hash "${MODEL_HASH}" \
  --json | tee /tmp/sp1_report.json | python3 -m json.tool
