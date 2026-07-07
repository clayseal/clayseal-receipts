# Fraud head (EZKL)

Tiny ONNX model: `amount` → `fraud_score` (sigmoid linear), used for Milestone 3 inference proofs.

## Setup

```bash
pip install torch onnx  # or onnx only (see export script)
curl https://raw.githubusercontent.com/zkonduit/ezkl/main/install_ezkl_cli.sh | bash
./scripts/ezkl_setup_fraud_head.sh
```

## Prove (CLI)

```bash
ezkl gen-witness -D input.sample.json -M ezkl/model.compiled -O ezkl/witness.json
ezkl prove -M ezkl/model.compiled -W ezkl/witness.json --pk-path ezkl/pk.key --proof-path ezkl/proof.json --srs-path ezkl/kzg.srs
ezkl verify --proof-path ezkl/proof.json -S ezkl/settings.json --vk-path ezkl/vk.key --srs-path ezkl/kzg.srs
```

Clay Seal Receipts wraps this via `agent-receipts prove-inference` and composes with Halo2 policy proofs.
