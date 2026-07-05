# Partner sync — Jun 2026

Quick reference so both sides stay aligned after the unified `agentauth` package and
benchmarks harness merge ([PR #5](https://github.com/pberlizov/agent-receipts/pull/5)).

## What is on `main`

| PR | Status | Summary |
|----|--------|---------|
| [#1](https://github.com/pberlizov/agent-receipts/pull/1) | **Merged** | L1/L3/L4 authority alignment |
| [#2](https://github.com/pberlizov/agent-receipts/pull/2) | **Merged** | Single `agentauth` package |
| [#5](https://github.com/pberlizov/agent-receipts/pull/5) | **Merged** | Benchmarks E2E harness, dynamic sandbox, `agentauth-mcp/`, red-team gate |

**Install / import surface**

```bash
pip install -e ".[partner]"   # or ".[dev]" for tests
from agentauth import AgentAuth, AgentWrapper, Policy
from agentauth.receipts import ...
```

Legacy paths (`python/agent_receipts`, `sdk/python/agentauth`, `backend/app`) are
removed. The `agent_receipts/` top-level package is a thin deprecation shim only.

## Benchmarks harness

- **`benchmarks/`** — self-contained E2E harness (six public corpora: run → export → verify → audit).
- **`benchmarks/tests/`** — unit/smoke tests (included in root `pytest`; corpus-dependent cases skip when data is absent).
- **Dynamic sandbox** — `agentauth/receipts/sandbox_builder.py`, scoping, governors; backlog in [docs/dynamic_planning.md](../docs/dynamic_planning.md).

## How to run benchmarks (after corpora download)

```bash
scripts/download_benchmark_corpora.sh   # ~2GB, gitignored under benchmarks/corpus/
pip install -r benchmarks/requirements.txt   # pyarrow for SWE adapter
python benchmarks/run.py --limit 20
pytest benchmarks/tests -q
```

## Coordination rules

- **Partner works on `main`** (identity, dashboard, backend verifier, unified package).
- **Benchmark harness + corpus adapters** live under `benchmarks/` — merge via PR; touch `agentauth/*` only when a shared API is needed.
- **Corpus data** stays gitignored; share `scripts/download_benchmark_corpora.sh` instead of checking in CSVs/parquet.
- Before pulling: `git fetch origin && git pull origin main`; resolve conflicts in `agentauth/receipts/` carefully.

## Open follow-ups

- [ ] Wire harness `--with-identity` to live backend in CI (optional job).
- [ ] IEEE-CIS / FDB CSVs need Kaggle creds (`~/.kaggle/kaggle.json`).
- [ ] `verify_valid` in harness is 0% in `bounded_auto` (no TEE quote) — track separately from `policy_satisfied` / `audit_chain_ok`.
