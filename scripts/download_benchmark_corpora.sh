#!/usr/bin/env bash
# Fetch public benchmark corpora into benchmarks/corpus/ (gitignored).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORPUS="$ROOT/benchmarks/corpus"
mkdir -p "$CORPUS"
cd "$CORPUS"

echo "==> ULB credit card (ccfraud / Amount column for fraud head)"
mkdir -p ulb_creditcard
if [[ ! -f ulb_creditcard/creditcard.csv ]]; then
  curl -L --fail -o ulb_creditcard/creditcard.csv \
    "https://huggingface.co/datasets/jyunyilin/credit-card-fraud-detection/resolve/main/creditcard.csv"
fi

echo "==> Amazon Fraud Dataset Benchmark (loaders + bundled ipblock dataset)"
if [[ ! -d amazon_fdb/.git ]]; then
  git clone --depth 1 https://github.com/amazon-science/fraud-dataset-benchmark.git amazon_fdb
fi
if [[ ! -f amazon_fdb/src/fdb/versioned_datasets/ipblock/20220607.zip ]]; then
  echo "    missing ipblock bundle — re-clone amazon_fdb or extract fraud-dataset-benchmark-main.zip into benchmarks/corpus/"
fi

echo "==> MCP agent trajectory benchmark (ATIF v1.2, HF)"
if [[ ! -f mcp_agent_trajectory_benchmark/train.jsonl ]]; then
  hf download obaydata/mcp-agent-trajectory-benchmark --repo-type dataset \
    --local-dir mcp_agent_trajectory_benchmark
fi

echo "==> tau2-bench (L3 policy / multi-step tool simulators)"
if [[ ! -d tau2_bench/.git ]]; then
  git clone --depth 1 https://github.com/sierra-research/tau2-bench.git tau2_bench
fi

echo "==> MCP-Bench (live MCP task definitions + servers)"
if [[ ! -d mcp_bench/.git ]]; then
  git clone --depth 1 https://github.com/Accenture/mcp-bench.git mcp_bench
fi

echo "==> Gorilla BFCL (cap / tool-call enforcement prompts)"
if [[ ! -d gorilla/.git ]]; then
  git clone --depth 1 --filter=blob:none --sparse https://github.com/ShishirPatil/gorilla.git gorilla
  (cd gorilla && git sparse-checkout set berkeley-function-call-leaderboard)
fi

echo "==> SWE-agent trajectories (README only unless SWE_FULL=1)"
mkdir -p swe_agent_trajectories
if [[ ! -f swe_agent_trajectories/README.md ]]; then
  hf download nebius/SWE-agent-trajectories --repo-type dataset \
    --include "README.md" --local-dir swe_agent_trajectories
fi
if [[ "${SWE_FULL:-0}" == "1" ]]; then
  hf download nebius/SWE-agent-trajectories --repo-type dataset \
    --local-dir swe_agent_trajectories
fi

echo "==> IEEE-CIS via FDB (requires ~/.kaggle/kaggle.json + competition join)"
if [[ -f "$HOME/.kaggle/kaggle.json" ]]; then
  pip install -q "$CORPUS/amazon_fdb" 2>/dev/null || pip install -q "$CORPUS/amazon_fdb"
  python3 - <<'PY'
from fdb.datasets import FraudDatasetBenchmark
ds = FraudDatasetBenchmark("ieeecis", load_pre_downloaded=False, delete_downloaded=False)
print("ieeecis train rows:", len(ds.train), "test rows:", len(ds.test))
PY
else
  echo "    skip ieeecis — no Kaggle credentials at ~/.kaggle/kaggle.json"
fi

echo "Done. Corpus under $CORPUS"
