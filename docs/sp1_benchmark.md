# SP1 (Plonky3) vs RISC Zero — fraud-head zkVM benchmark (SOTA-12)

Ports the SOTA-8 fraud head to **SP1** (Succinct, on Plonky3) to compare against the RISC Zero
baseline. Same guest computation and journal bindings as RISC Zero for an apples-to-apples result.
Crate: [`crates/agent-receipts-sp1/`](../crates/agent-receipts-sp1/) (detached from the workspace,
like the RISC Zero crate).

## Integration (done)

| Piece | Location |
|-------|----------|
| SP1 guest (full journal) | [`program/src/main.rs`](../crates/agent-receipts-sp1/program/src/main.rs) |
| Host `prove` / `verify` CLI | [`src/main.rs`](../crates/agent-receipts-sp1/src/main.rs) |
| Composed inference backend | [`inference.rs`](../crates/agent-receipts-composed/src/inference.rs) — `InferenceAttestation::Sp1`, `prove_inference_sp1`, `verify_inference_sp1` |
| Main CLI | `agent-receipts prove-inference --backend sp1` |
| Python | `prove_inference(..., backend="sp1")`, `AgentWrapper(inference_backend="sp1")` |
| Build script | [`scripts/sp1_build_fraud_head.sh`](../scripts/sp1_build_fraud_head.sh) |
| Benchmark script | [`scripts/sp1_benchmark_fraud_head.sh`](../scripts/sp1_benchmark_fraud_head.sh) |

The guest commits `(amount, output_hash, model_provenance_hash, score)` — identical to the RISC Zero
guest. The program verification key hash is stored in `InferenceProofEnvelope.image_id` (same field
as RISC Zero's `image_id`).

## Toolchain pin

Pin **`cargo-prove` CLI** and **`sp1-sdk` / `sp1-zkvm`** to the same release (currently **5.2.4** in
`Cargo.toml`). A bleeding-edge `sp1up` emits **riscv64im** ELFs that panic against crates.io
`sp1-sdk` 5.2.4: `must be a 32-bit elf`.

```bash
export SP1_VERSION=5.2.4
curl -L https://sp1up.succinct.xyz | bash
sp1up --version "${SP1_VERSION}"
scripts/sp1_build_fraud_head.sh
scripts/sp1_benchmark_fraud_head.sh 25000
```

Override the guest ELF path with `SP1_FRAUD_ELF`. Override the host binary with
`AGENT_RECEIPTS_SP1_BIN`.

## Comparison

RISC Zero numbers are **measured here** (SOTA-8, Apple Silicon, default core STARK). SP1 numbers are
**cited** from published Succinct/Plonky3 benchmarks — labeled as such, **not measured here** until
the pinned toolchain run completes on your machine.

| Dimension | RISC Zero (measured, SOTA-8) | SP1 / Plonky3 (cited) |
|-----------|------------------------------|------------------------|
| Prove time (tiny head, CPU) | 6.3–7.2 s | ~**5× faster** CPU vs RISC Zero on comparable workloads ([Succinct](https://blog.succinct.xyz/sp1-testnet/), [Plonky3](https://polygon.technology/blog/open-source-polygon-plonky3-is-once-again-the-fastest-zk-proving-system)) |
| Default proof | ~205 KB core receipt | larger **core** STARK proof; compresses to a succinct **Groth16/PLONK** wrapper (~constant, small) for on-chain/transport |
| Precompiles | fewer | most complete set incl. **ed25519**, sha256, keccak, bn254/bls12-381 ([a16z zkvm-benchmarks](https://github.com/a16z/zkvm-benchmarks)) |
| Per-model setup | none (universal zkVM) | none (universal zkVM) |

Two caveats on the cited speedup: (1) zkVM benchmarks are **point-in-time** and workload-dependent;
(2) our fraud head exercises **no precompiles**, so it understates SP1's advantage on realistic
workloads (e.g. verifying our **Ed25519** receipt/checkpoint signatures *inside* the zkVM).

## Recommendation

- **SP1/Plonky3 is the stronger zkVM choice** for richer workloads and in-circuit Ed25519 verification.
- **Pin the `cargo-prove` CLI and `sp1-sdk` to one release** — the integration is wired; measured
  numbers require a version-locked build session.
- Keep RISC Zero (SOTA-8) as a working baseline until SP1 measured numbers are captured on a locked
  toolchain.
