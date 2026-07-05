#!/usr/bin/env bash
# One-time (or CI) setup for design partners: Python deps, Rust CLI, proving keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Python dependencies"
pip install -e ".[mcp,dev]" -q

echo "==> Rust prover CLI"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
cargo build -p agent-receipts-cli --release

echo "==> Policy proving keys (Halo2 setup)"
"$CARGO_TARGET_DIR/release/agent-receipts" setup

echo "==> Diagnostics"
arctl doctor --require-prover

echo ""
echo "Bootstrap complete."
echo "  arctl doctor"
echo "  python3 examples/partner_pilot.py"
