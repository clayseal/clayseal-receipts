# AgentAuth — Examples & Demos

Runnable demos grouped by what they show. Most identity scripts are **zero-config**:
they use a backend at `AGENTAUTH_BASE_URL` (default `http://localhost:8000`) when
present, otherwise boot the backend in-process on a throwaway database.

## Quickstart (identity)

| File | Shows |
|------|-------|
| [`01_quickstart.py`](01_quickstart.py) | Identity lifecycle: `identify()`, `validate()`, `agents()`, `revoke()` |

## Runtime & MCP demos

| File | Shows |
|------|-------|
| [`shadow_fraud_agent.py`](shadow_fraud_agent.py) | Receipted fraud agent in `shadow` mode |
| [`../demo/poisoned_mcp_demo.py`](../demo/poisoned_mcp_demo.py) — see [`POISONED_MCP_DEMO.md`](POISONED_MCP_DEMO.md) | **Featured:** LLM vs poisoned MCP server; Biscuit blocks ungranted tools; tamper-evident receipts |
| [`poisoned_mcp_server.py`](poisoned_mcp_server.py) | Poisoned MCP server used by the demo |

## Devin / red-team assets

| Path | Shows |
|------|-------|
| [`devin-agentauth-demo/`](devin-agentauth-demo/) | Devin gate integration walkthrough |
| [`../scripts/run_devin_redteam_gate.sh`](../scripts/run_devin_redteam_gate.sh) | PR-gate red-team scenario matrix (10/10) |
| [`../docs/devin_redteam_index.md`](../docs/devin_redteam_index.md) | Index of Devin red-team scripts and scenarios |
| [`../benchmarks/`](../benchmarks/) | E2E harness, soundness benchmarks, trajectory corpus |

## Rippling Deep Agents / red-team assets

Second benchmark target, alongside Devin above: a local fixture modeled on
Rippling AI's publicly-confirmed architecture (LangChain Deep Agents —
supervisor + read/RAG/action subagents). 100% local; no network call to any
real Rippling tenant. See [`../docs/rippling_deepagents_redteaming_backlog.md`](../docs/rippling_deepagents_redteaming_backlog.md)
for sourcing and scope.

| Path | Shows |
|------|-------|
| [`rippling-deepagents-demo/`](rippling-deepagents-demo/) | Fixture HR/payroll data, runtime policy, `rippling_fixture_agent.py` |
| [`../demo/rippling_deepagents_demo.py`](../demo/rippling_deepagents_demo.py) | **Featured:** RAG-doc injection, confused deputy, plausible-lie forensics, tamper-evidence, optional live Deep Agents run |
| [`../docs/rippling_deepagents_redteaming_backlog.md`](../docs/rippling_deepagents_redteaming_backlog.md) | Scorecard: 107 harnessed scenarios (full Devin backlog ported + native cases) |
| [`../docs/rippling_redteaming_backlog.md`](../docs/rippling_redteaming_backlog.md) | Live LLM volley findings + tricked/partial scorecard |
| [`rippling-deepagents-demo/live_hit_verdicts.py`](rippling-deepagents-demo/live_hit_verdicts.py) | Canonical tricked / partial / not_tricked verdicts per scenario |
| [`../python/tests/test_rippling_deepagents_redteaming_backlog.py`](../python/tests/test_rippling_deepagents_redteaming_backlog.py) | Deterministic JSONL harness (`pytest python/tests/test_rippling_deepagents_redteaming_backlog.py`) |

## Setup

```bash
# from the repo root
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,mcp]"
```

## Run

```bash
python examples/01_quickstart.py
python demo/poisoned_mcp_demo.py
```

### Point at a real backend

```bash
uvicorn agentauth.backend.main:app   # terminal 1
AGENTAUTH_BASE_URL=http://localhost:8000 python examples/01_quickstart.py
```

Each example creates its own tenant when it boots an embedded backend.
