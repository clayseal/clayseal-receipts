# Developer guide — Clay Seal Receipts (Layer 3)

This is the operational manual for **Clay Seal Receipts**: the top layer of the
Clay Seal stack. The package name remains `agentauth-receipts`, and the Python
namespace remains `agentauth.receipts`, for compatibility. The product name for
developers and customers is Clay Seal. This guide covers installation,
day-to-day use of `AgentWrapper`, MCP gateways, verification, partner
deployment, and how this repo relates to identity (L1) and capabilities (L2).

If you read one document before integrating Clay Seal into a production agent, make it this one — then drill into the linked deep dives (`docs/trust_model.md`, `docs/deployment.md`, etc.) as needed.

---

## What this repository delivers

Autonomous agents create **consequential side effects**: commits, payments, database writes, infrastructure changes. Traditional logging is not enough — logs can be altered, and OAuth tokens only prove *who could act*, not *what happened under policy*.

This repo answers:

1. **Authorization** — Was this specific action allowed *before* it ran?
2. **Attribution** — Which agent identity, under which human principal?
3. **Integrity** — Is the record of what happened tamper-evident?
4. **Verification** — Can a third party validate a receipt offline or via HTTP?

Main artifacts:

| Artifact | Role |
|----------|------|
| `AgentWrapper` | Wrap a model/agent; enforce policy; emit receipts |
| `ExecutionProof` | Cryptographic bundle binding output, policy, identity |
| Audit log (Merkle) | Hash-chained append-only history |
| MCP gateway / sandbox | Enforce capability scope at tool-call time |
| `arctl` CLI | Doctor, verify, export, preflight |
| HTTP verifier | Partner-facing verification API |

This repo **owns the top-level Python namespace**:

```python
from agentauth import Identity, AgentWrapper
from agentauth.receipts import Policy
```

Lower layers use subpackages (`agentauth.identity`, `agentauth.capabilities`).

---

## Three-layer architecture

```
Partner / operator view
─────────────────────────────────────────────────────────────
  pip install receipts directly

Runtime data flow
─────────────────────────────────────────────────────────────
  Optional identity claims → AuthorityBinding / IdentitySession
  Optional capability lease → action scope
  AgentWrapper records DecisionResult → ExecutionProof → audit log
```

| Layer | Repo | You use it for |
|-------|------|----------------|
| Built-in core | **this repo** | Shared contracts, signing, runtime descriptors |
| Optional identity | [clayseal-identity](https://github.com/clayseal/clayseal-identity) | Mint/verify agent credentials |
| Optional capabilities | Clay Seal L2 package | Commit tokens, mandates, leases |
| Receipts | **this repo** | Receipts, MCP, verify, demos |

**Release rule:** receipts must install and run without any private Clay Seal repository.

---

## Installation

### Production / partner (pinned tag)

```bash
pip install "agentauth-receipts[server,verifier] @ git+https://github.com/pberlizov/clay-seal-receipts.git@v0.5.0"
```

Use `[identity]` when you want native Clay Seal identity sessions. Use
`[scoping]` only in environments where the unreleased L2 capabilities package is
available.

### Local development (editable)

```bash
git clone https://github.com/pberlizov/clay-seal-receipts.git
cd clay-seal-receipts
python -m venv .venv && source .venv/bin/activate

pip install -e ".[dev]"
```

### Smoke verification

```bash
bash scripts/layer_install_smoke.sh   # clean venv, install receipts from a tag
arctl doctor                          # config + import checks
python demo/poisoned_mcp_demo.py      # narrated security demo
```

### Optional extras

| Extra | Purpose |
|-------|---------|
| `server` | FastAPI identity + verifier dependencies |
| `mcp` | MCP server and Groq-backed demos |
| `verifier` | Standalone HTTP verifier |
| `deepagents` | Rippling-style red-team fixtures (heavy deps) |
| `kms` | AWS/GCP KMS for signing key encryption |
| `frameworks` | LangChain, Pydantic AI, LlamaIndex, CrewAI, OpenAI Agents, Semantic Kernel, AutoGen, Haystack |

---

## First hour: shadow mode fraud agent

The gentlest on-ramp is **shadow mode** — receipts are recorded but policy violations do not block execution.

```bash
pip install -e ".[dev]"
python examples/shadow_fraud_agent.py
```

What happens:

1. A toy fraud-scoring model runs inside `AgentWrapper`.
2. A YAML policy (`policies/`) defines allowed score ranges and outputs.
3. Each decision produces a receipt bundle under `receipts/`.
4. You verify with `arctl verify-bundle receipts/<id>.json`.

Shadow mode is ideal for **instrumentation** before you enable blocking.

---

## Core concepts

### Policy

Policies are committed rules (YAML) hashed into the receipt. Changing the policy changes the commitment — verifiers detect mismatch.

```python
from agentauth.receipts import Policy

policy = Policy.from_yaml("policies/fraud_decision.yaml")
```

See `docs/policy_language.md` for the full grammar.

### AgentWrapper and modes

```python
from agentauth import Identity, AgentWrapper

auth = Identity(trust_domain="example.org")
agent = auth.register_agent("review/fraud-bot")
credential = auth.identify(agent, principal="alice@example.org")

wrapper = AgentWrapper(
    model=my_model,
    policy=policy,
    auth=auth,
    credential=credential,
    mode="shadow",       # "shadow" | "bounded_auto" | ...
)
result = wrapper.run({"transaction_id": "tx-1", "amount": 50000})
```

| Mode | Behavior |
|------|----------|
| `shadow` | Log violations; still execute |
| `bounded_auto` | Block on policy violation (abstain / error) |

### ExecutionProof and receipt bundles

Each run emits a structured bundle: decision, output hash, policy commitment, identity evidence, optional ZK proofs, signatures. **`arctl verify-bundle`** and the HTTP verifier recompute checks.

Trust properties are documented honestly in `docs/trust_model.md`.

### Audit log

Append-only Merkle log (`agentauth/receipts/audit.py`). Supports inclusion proofs, consistency proofs, optional signed checkpoints. Use when you need **tamper-evidence across many receipts**, not just single-bundle integrity.

---

## Cross-provider identity

Layer 3 accepts the same `IdentitySession` abstraction as the rest of the stack.
You can wrap agents with OIDC, SPIFFE, Auth0, AWS STS, Azure AD, GCP service
account, or native Clay Seal sessions.

```python
from agentauth.receipts import Policy
from agentauth.receipts.identity_providers import get_identity_provider
from agentauth.receipts.integration import wrap_with_identity_session

# verified_claims should already have been checked by your IdP/gateway.
session = get_identity_provider("oidc").build_session(
    verified_claims,
    evidence_verified=True,
)
wrapper = wrap_with_identity_session(
    model,
    Policy.from_yaml("policies/fraud_decision.yaml"),
    session,
    mode="bounded_auto",
)
result = wrapper.run({"transaction_id": "t1"})
```

The built-in providers are claim mappers, not JWT verifiers. That is deliberate:
receipts can be used behind your existing gateway, OIDC middleware, SPIFFE
verifier, or cloud workload identity verifier without taking over your auth
stack.

---

## MCP integration and the poisoned-server demo

Many agents call tools via MCP. This repo provides gateway patterns that:

- Enforce **capability scope** before `tools/call`
- Bind **identity** into each tool invocation receipt
- Detect **schema / description tampering** in hostile servers

Run the flagship demo:

```bash
python demo/poisoned_mcp_demo.py
python demo/poisoned_mcp_demo.py --verbose
# Optional real LLM:
GROQ_API_KEY=... python demo/poisoned_mcp_demo.py
```

Without an API key, a deterministic agent still demonstrates the attack and defense story.

For sandboxed gateways (goal-bound leases, protected zones):

- Read `docs/dynamic_planning.md`
- See `build_sandboxed_gateway()` in `agentauth/receipts/sandbox_builder.py`

---

## The `arctl` CLI

Installed as `arctl` when you `pip install agentauth-receipts`.

Common commands:

```bash
arctl doctor                    # environment + config sanity
arctl preflight config/partner.yaml
arctl verify-bundle receipts/proof.json
arctl export-audit --help       # audit log operations
```

Partner configs live under `config/` (`partner.example.yaml`, `partner.production.example.yaml`). See `docs/deployment.md` and `docs/partner_runbook.md`.

---

## HTTP verifier service

For teams that want verification as a service:

```bash
pip install -e ".[verifier,server]"
# or docker compose up verifier
arctl serve --host 127.0.0.1 --port 8787
curl -s http://localhost:8787/health | jq .
curl -s -X POST http://localhost:8787/v1/verify \
  -H 'Content-Type: application/json' \
  -d @receipts/your-proof.json | jq .
```

Configure API keys, rate limits, and body size caps for production (`docs/http_verifier.md`).

---

## Partner deployment workflow

1. **Pin a tag** — see [RELEASE.md](../RELEASE.md) (currently `v0.5.0`).
2. **Copy config** — `cp config/partner.example.yaml config/partner.yaml`.
3. **Preflight** — `bash scripts/partner_preflight.sh config/partner.yaml`.
4. **Run smoke** — `bash scripts/layer_install_smoke.sh` then `arctl doctor`.
5. **Choose mode** — start in `shadow`, move to `bounded_auto` after review.
6. **Verify exports** — `arctl verify-bundle` on sample receipts.

Environment variables use the `AGENT_RECEIPTS_*` prefix (documented in `config/env.example`).

Legacy `scripts/partner_smoke.sh` assumes a monolithic checkout with a built Rust CLI. Prefer `layer_install_smoke.sh` for the three-repo layout.

---

## Testing

Full developer install:

```bash
pytest python/tests -q       # receipts runtime
pytest sdk/python/tests -q    # identity->receipt seam e2e
```

Capability-scoping tests are skipped automatically when the optional L2 package
is not installed.

CI also runs `cargo test --all`. Locally, Rust builds are optional unless you work on ZK proving.

High-value test modules for integrators:

- `python/tests/test_cross_provider_integration.py` — L2 adapters → L3 wrap
- `python/tests/test_interop_conformance.py` — SCITT/COSE/tlog interop
- Signing and audit tests — bundle signatures and checkpoint verification

---

## Repository map (where to look in the code)

| Path | Purpose |
|------|---------|
| `agentauth/receipts/wrapper.py` | `AgentWrapper` |
| `agentauth/receipts/integration.py` | Cross-provider `wrap_with_identity_session` |
| `agentauth/receipts/audit.py` | Merkle audit log |
| `agentauth/receipts/signing.py` | Ed25519 bundle signatures |
| `agentauth/receipts/sandbox_builder.py` | Goal-bound MCP sandbox |
| `agentauth/receipts/mcp_server.py` | MCP server entry |
| `agentauth/receipts/cli.py` | `arctl` |
| `agentauth/backend/` | Identity + verifier HTTP (optional) |
| `policies/` | Example YAML policies |
| `demo/` | End-to-end narrated demos |
| `examples/` | Smaller focused scripts |
| `docs/` | Deep dives (trust model, deployment, MCP, …) |
| `crates/` | Rust CLI and ZK proving |

---

## Troubleshooting

### Import and namespace issues

**Symptom:** `ImportError` for `agentauth.identity` or wrong class at runtime.

**Cause:** Python merged multiple `agentauth` directories from sibling clones via `PYTHONPATH` or cwd.

**Fix:** Use a single venv and avoid exporting `PYTHONPATH=.` across repos.

### Version skew

**Symptom:** Subtle verification failures after upgrading one repo only.

**Fix:** Check `VERSION`, `pyproject.toml`, and `agentauth/receipts/_version.py` in this repo match.

### Shadow vs bounded_auto confusion

**Symptom:** Policy violation but action still ran.

**Fix:** Expected in `shadow`. Switch to `bounded_auto` only after validating receipts in shadow.

### Unsigned bundle verification in dev

Demos set `AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES=0` for convenience. **Production partners must enable signatures** and signed audit checkpoints — see `docs/trust_model.md`.

### Git pip install fails on capabilities/receipts

**Cause:** Identity tag not published yet.

**Fix:** Maintain release order — push and tag **identity first**.

---

## Security and honesty

Clay Seal is a verification system; overstated claims undermine the product.

- **Implemented today:** pre-action capability checks, identity-bound receipts, Merkle audit, Ed25519 signing, SCITT/COSE export, empirical tamper benchmarks (see README soundness section).
- **Roadmap / proposed:** items marked in README Section 3 and `docs/roadmap.md`.

Read `docs/trust_model.md` before telling customers what guarantees they get.

---

## Privacy and data handling

Layer 3 can process prompts, tool inputs, model outputs, source-code snippets,
policy decisions, identity context, capability context, and exported audit
payloads. Decide which fields belong in receipts before production rollout.

Use hashes or external references for sensitive payloads when the verifier does
not need raw content. Enable signed bundles, signed audit checkpoints, trusted
signer allowlists, HTTP verifier limits, exporter allowlists, and retention
rules before handling user, employee, financial, or regulated data.

Read [docs/PRIVACY.md](PRIVACY.md) alongside [docs/trust_model.md](trust_model.md)
and [docs/deployment.md](deployment.md).

---

## Releases (maintainers)

1. Align versions in identity, capabilities, receipts.
2. Update [CHANGELOG.md](../CHANGELOG.md) and [RELEASE.md](../RELEASE.md).
3. Tag and push **L1 → L2 → L3**.
4. Run `bash scripts/layer_install_smoke.sh` against published tags.
5. Notify partners with exact pip lines (in RELEASE.md).

Current release line: **0.5.0** (`v0.5.0`).

---

## Related documentation index

| Topic | Document |
|-------|----------|
| Trust guarantees | [docs/trust_model.md](trust_model.md) |
| Partner deployment | [docs/deployment.md](deployment.md), [docs/partner_runbook.md](partner_runbook.md) |
| MCP wiring | [docs/mcp_integration.md](mcp_integration.md) |
| Sandbox / leases | [docs/dynamic_planning.md](dynamic_planning.md) |
| Policy syntax | [docs/policy_language.md](policy_language.md) |
| HTTP verifier | [docs/http_verifier.md](http_verifier.md) |
| Privacy and data handling | [docs/PRIVACY.md](PRIVACY.md) |
| L1 operations | [identity DEV_GUIDE](https://github.com/clayseal/clayseal-identity/blob/main/docs/DEV_GUIDE.md) |
| L2 / IdP adapters | Capability package docs, when available |

---

## Getting help

Open issues on the repo where the bug lives (identity vs capabilities vs receipts). Include:

- Tag or commit SHA for **each** installed layer
- Install method (pip git URL vs editable)
- Minimal repro command
- Redacted receipt bundle if verification-related

That single checklist saves a round trip almost every time.
