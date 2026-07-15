#!/usr/bin/env bash
# Build the SP1 fraud-head guest ELF and the detached host binary.
# Requires the SP1 toolchain: https://sp1up.succinct.xyz
#
# Pin the cargo-prove CLI to the same release as sp1-sdk in Cargo.toml (default 6.3.1).
# Keep sp1up and crates.io sp1-sdk on the same minor line; mismatches can emit
# guest ELFs that the host SDK rejects.
# ("must be a 32-bit elf").
#
# Usage: scripts/sp1_build_fraud_head.sh
set -euo pipefail

SP1_VERSION="${SP1_VERSION:-6.3.1}"
CRATE="crates/agent-receipts-sp1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

GUEST_DIR="${ROOT}/${CRATE}/program"
GUEST_TARGET_DIR="${GUEST_DIR}/target/elf-compilation"
HOST_TARGET_DIR="${ROOT}/${CRATE}/target"

export PATH="$HOME/.sp1/bin:$PATH"

if ! command -v cargo-prove >/dev/null 2>&1; then
  echo "sp1 toolchain not found — install with: curl -L https://sp1up.succinct.xyz | bash && sp1up --version ${SP1_VERSION}" >&2
  exit 1
fi

echo "==> ensuring SP1 toolchain ${SP1_VERSION}"
if command -v sp1up >/dev/null 2>&1; then
  sp1up --version "${SP1_VERSION}" || sp1up
fi

echo "==> building guest (cargo prove build)"
echo "    output: ${GUEST_TARGET_DIR}"
(
  cd "${GUEST_DIR}"
  # cargo prove manages target/elf-compilation itself — do not set CARGO_TARGET_DIR here.
  unset CARGO_TARGET_DIR
  cargo prove build
)

echo "==> building host (release)"
echo "    CARGO_TARGET_DIR=${HOST_TARGET_DIR}"
unset CARGO_TARGET_DIR
CARGO_TARGET_DIR="${HOST_TARGET_DIR}" cargo build --release --manifest-path "${CRATE}/Cargo.toml"

BIN="${HOST_TARGET_DIR}/release/agent-receipts-sp1"
echo "==> built host ${BIN}"

ELF=""
for candidate in \
  "${GUEST_TARGET_DIR}/riscv32im-succinct-zkvm-elf/release/fraud-head-program" \
  "${GUEST_TARGET_DIR}/riscv64im-succinct-zkvm-elf/release/fraud-head-program"; do
  if [[ -f "${candidate}" ]]; then
    ELF="${candidate}"
    break
  fi
done

if [[ -z "${ELF}" ]]; then
  echo "error: guest ELF not found under ${GUEST_TARGET_DIR}" >&2
  exit 1
fi

echo "==> built guest ${ELF} ($(wc -c < "${ELF}" | tr -d ' ') bytes)"
echo "    export SP1_FRAUD_ELF=${ELF}  # optional override"
