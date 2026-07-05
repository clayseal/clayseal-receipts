#!/usr/bin/env bash
# One-time EZKL compile/setup for circuits/fraud_head (requires `ezkl` on PATH).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/circuits/fraud_head"
EZKL_DIR="$DIR/ezkl"
MODEL="$DIR/model.onnx"
INPUT="$DIR/input.sample.json"

if ! command -v ezkl >/dev/null; then
  echo "ezkl not found. Install: curl https://raw.githubusercontent.com/zkonduit/ezkl/main/install_ezkl_cli.sh | bash"
  exit 1
fi

python3 "$ROOT/scripts/export_fraud_onnx.py"
mkdir -p "$EZKL_DIR"

SETTINGS="$EZKL_DIR/settings.json"
COMPILED="$EZKL_DIR/model.compiled"
SRS="$EZKL_DIR/kzg.srs"
VK="$EZKL_DIR/vk.key"
PK="$EZKL_DIR/pk.key"

echo "==> gen-settings"
ezkl gen-settings -M "$MODEL" -O "$SETTINGS"

echo "==> calibrate-settings"
ezkl calibrate-settings -M "$MODEL" -D "$INPUT" -O "$SETTINGS" --target resources

echo "==> compile-circuit"
ezkl compile-circuit -M "$MODEL" -S "$SETTINGS" -C "$COMPILED"

echo "==> SRS"
LOGROWS=$(python3 -c "import json; print(json.load(open('$SETTINGS'))['run_args']['logrows'])")
ezkl gen-srs --logrows "$LOGROWS" --srs-path "$SRS"

echo "==> setup"
ezkl setup -M "$COMPILED" --srs-path "$SRS" --vk-path "$VK" --pk-path "$PK"

echo "Done. Artifacts under $EZKL_DIR"
