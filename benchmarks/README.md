# Benchmark harness

Self-contained E2E tests for the agent-receipts pipeline (L1 optional → L3 policy → agent/MCP execution → L4 export/verify → audit chain). All code lives under `benchmarks/` so it does not touch the rest of `main` while partners work elsewhere.

## Prerequisites

```bash
# From repo root — unified agentauth package (post PR #2)
pip install -e ".[partner]"

# Corpora (gitignored, ~2GB)
scripts/download_benchmark_corpora.sh

# Optional: SWE parquet adapter
pip install -r benchmarks/requirements.txt
```

## Run

```bash
python benchmarks/run.py --limit 10
python benchmarks/run.py --suite ulb_fraud,atif_mcp --limit 50
python benchmarks/run.py --suite tau2_policy --tau2-domain mock,airline,retail --limit 200
python benchmarks/run.py --suite atif_mcp --policy-mode tight --limit 20
python benchmarks/run.py --suite tau2_policy --policy-mode tight --tau2-domain mock,airline --limit 50
python benchmarks/run.py --suite red_team
python benchmarks/run.py --suite synthetic_revocation,synthetic_tenant,synthetic_l1,synthetic_assurance
python benchmarks/run.py --suite ieee_cis_fraud --ulb-sample stratified --limit 1000 --no-export
python benchmarks/run.py --suite ieee_cis_fraud,paysim_fraud,elliptic_fraud,baf_fraud --limit 100
python benchmarks/run.py --suite swe_session --swe-shard 1 --limit 50
python benchmarks/run.py --suite all --limit 20 --with-identity
python benchmarks/run.py --suite ulb_fraud,atif_mcp --with-identity --limit 100 --results-dir benchmarks/results/ev101_identity_100
AGENT_RECEIPTS_ALLOW_STUB=1 python benchmarks/run.py --suite ulb_fraud --mode prove --limit 10 --results-dir benchmarks/results/ev201_prove_10
AGENT_RECEIPTS_ALLOW_STUB=1 python benchmarks/ev201_compare.py --limit 100
AGENT_RECEIPTS_ALLOW_STUB=1 python benchmarks/ev202_compare.py --limit 10
python benchmarks/run.py --suite ulb_fraud --limit 10000 --no-export
python benchmarks/demo/generate.py
python benchmarks/run.py --suite amazon_fdb --limit 1000 --no-export
python benchmarks/run.py --mode shadow --no-export
```

See [DATA_EVIDENCE_BACKLOG.md](./DATA_EVIDENCE_BACKLOG.md) for metric interpretation.

Results land in `benchmarks/results/<timestamp>/`:

- `summary.json` — per-suite pass rates, latency, verify/policy rates, fraud `label_mismatch_rate`, identity/prove metrics, red team category rates
- `cases.jsonl` — one row per case
- `<suite>_<case_id>.json` — exported receipt bundles (unless `--no-export`)

## Suites

| Suite | Corpus | Pipeline exercised |
|-------|--------|-------------------|
| `ulb_fraud` | ULB creditcard CSV | Fraud model → `fraud_decision.yaml` → run → export → verify → audit |
| `ieee_cis_fraud` | IEEE-CIS (ARL export or local) | Same pipeline; auto-resolves `adaptive-reliability-layer/data/fraud/` |
| `paysim_fraud` | PaySim (ARL / local) | Tabular fraud receipt benchmark |
| `elliptic_fraud` | Elliptic BTC (ARL / local) | Tabular fraud receipt benchmark |
| `baf_fraud` | Bank Account Fraud (ARL / local) | Tabular fraud receipt benchmark |
| `amazon_fdb` | Amazon FDB ipblock (versioned zip) | Tabular fraud receipt benchmark; 43k test rows |
| `atif_mcp` | MCP ATIF trajectories | Replay tool calls via `ReceiptedMcpGateway` + mock handlers; `--policy-mode tight` blocks non-allowlisted tools |
| `bfcl_caps` | Gorilla BFCL simple_python | Allowed tool passes; decoy tool blocked by policy allowlist |
| `tau2_policy` | τ²-bench mock domain | Replay `evaluation_criteria.actions` through MCP gateway; `--policy-mode tight` enforces partial allowlist |
| `mcp_bench_tasks` | MCP-Bench task JSON | Planned tool sequence from task descriptions → receipts (**56** single-server tasks) |
| `swe_session` | SWE-agent parquet (shard 0) | Multi-step `agent.record()` session aggregation (**deduped by instance_id**) |
| `red_team` | Synthetic attacks + documented blind spots | **Controls** must block; **baselines** must pass; **blind_spots** track known gaps; see `red_team_metrics` in summary |
| `synthetic_revocation` | EV-103 lifecycle + scale (73 cases) | Revoke blocks live validate; offline bundle blind spot |
| `synthetic_tenant` | EV-102 tenant isolation + scale (43 cases) | Cross-tenant API + bundle JWT blocked |
| `synthetic_l1` | EV-101 L1 hardening (7 cases) | Ed25519 JWT, Biscuit, PoP, key rotation grace |
| `synthetic_assurance` | EV-203/EV-008 assurance (5 cases) | Mock Nitro TEE verify; tamper injection controls |

See [DATA_EVIDENCE_BACKLOG.md](./DATA_EVIDENCE_BACKLOG.md) for metric interpretation. **Do not read 100% on smoke suites as safety proof** — run `red_team` for discriminating signal.

Suites skip gracefully when corpus files are missing.

## Layout

```
benchmarks/
  run.py                 # CLI entrypoint
  harness/
    pipeline.py          # export + verify + audit wrapper
    runner.py            # orchestrates suites
    adapters/            # one module per corpus
  policies/              # harness-local YAML (MCP / tau2)
  corpus/                # downloaded data (gitignored)
  results/               # run output (gitignored)
```

Repo policies (`policies/fraud_decision.yaml`) are read-only references — not modified by the harness.
