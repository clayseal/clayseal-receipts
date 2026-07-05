#!/usr/bin/env bash
# Build the RISC Zero fraud-head host, prove an inference, and verify the receipt.
# Requires the RISC Zero toolchain (https://risczero.com/install ; `rzup install`).
#
# Usage: scripts/zkvm_prove_fraud_head.sh [amount]
set -euo pipefail

AMOUNT="${1:-25000}"
CRATE="crates/agent-receipts-zkvm"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PATH="$HOME/.risc0/bin:$PATH"

echo "==> building $CRATE (release)"
cargo build --release --manifest-path "$CRATE/Cargo.toml"

BIN="$CRATE/target/release/agent-receipts-zkvm"

echo "==> proving fraud head for amount=$AMOUNT"
REPORT="$("$BIN" prove --amount "$AMOUNT" --json)"
echo "$REPORT" | python3 -m json.tool

IMAGE_ID="$(echo "$REPORT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["image_id"])')"
SCORE="$(echo "$REPORT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["score"])')"
RECEIPT_HEX="$(echo "$REPORT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["receipt_hex"])')"

echo "==> verifying receipt"
"$BIN" verify --image-id "$IMAGE_ID" --score "$SCORE" --receipt-hex "$RECEIPT_HEX"

echo "==> tampered-score verification must fail"
if "$BIN" verify --image-id "$IMAGE_ID" --score 0.123 --receipt-hex "$RECEIPT_HEX" 2>/dev/null; then
  echo "ERROR: tampered score verified" >&2
  exit 1
fi
echo "ok: tampered score rejected"
