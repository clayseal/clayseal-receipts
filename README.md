# Clay Seal Receipts

<img src="docs/assets/clay-seal-logo.png" alt="Clay Seal logo" width="420">

Clay Seal Receipts is layer 3 of Clay Seal: verifiable execution records for
autonomous agents. The package is still published as `agentauth-receipts` and
imports from `agentauth.receipts` for compatibility while the product brand is
Clay Seal.

Use this repo when you need to answer:

- What did the agent do?
- Was the action authorized before it ran?
- Which identity, principal, policy, model, and capability context were bound to
  the decision?
- Can a partner or auditor verify the result without trusting your logs?

## Current State

Implemented today:

- `AgentWrapper` for policy-aware model and agent execution.
- `ExecutionProof` receipt bundles with policy commitments and output hashes.
- Identity-bound receipts via native Clay Seal, OIDC, SPIFFE, Auth0, AWS STS,
  Entra, Azure AD, and GCP-backed sessions.
- Capability-aware receipts using commit tokens, mandates, leases, and sandbox
  scopes from layer 2.
- MCP gateway patterns, poisoned-server demos, and goal-bound coding-agent
  sandboxing.
- Merkle audit logs, signed checkpoints, Ed25519 bundle signatures, SCITT/COSE
  export, OCSF export, OpenTelemetry GenAI mapping, Vanta and Drata exporters.
- HTTP verifier service, `arctl` CLI, partner preflight checks, and benchmark
  harnesses for tamper and policy evaluation.
- Optional framework adapters for LangChain, Pydantic AI, LlamaIndex, CrewAI,
  OpenAI Agents, Semantic Kernel, AutoGen, and Haystack.

Clay Seal Receipts can run with only `agentauth-core` for receipt creation and
verification. Install the optional identity and scoping extras when you want
native L1/L2 binding.

| Layer | Repository | Purpose |
| --- | --- | --- |
| Core | [clay-seal-core](https://github.com/pberlizov/clay-seal-core) | Shared contracts and crypto helpers |
| L1 | [clay-seal-identity](https://github.com/pberlizov/clay-seal-identity) | Agent identity and credential issuance |
| L2 | [clay-seal-capabilities](https://github.com/pberlizov/clay-seal-capabilities) | Commit tokens, mandates, leases, budgets |
| L3 | this repo | Receipts, MCP gateways, audit, verification |

## Install

Pinned partner install:

```bash
pip install "git+https://github.com/pberlizov/clay-seal-core.git@v0.5.0"
pip install "git+https://github.com/pberlizov/clay-seal-identity.git@v0.5.0"
pip install "git+https://github.com/pberlizov/clay-seal-capabilities.git@v0.5.0"
pip install "agentauth-receipts[partner] @ git+https://github.com/pberlizov/clay-seal-receipts.git@v0.5.0"
```

Editable development:

```bash
git clone https://github.com/pberlizov/clay-seal-core.git ../clay-seal-core
git clone https://github.com/pberlizov/clay-seal-identity.git ../clay-seal-identity
git clone https://github.com/pberlizov/clay-seal-capabilities.git ../clay-seal-capabilities
git clone https://github.com/pberlizov/clay-seal-receipts.git
cd clay-seal-receipts
python -m venv .venv && source .venv/bin/activate
pip install -e "../clay-seal-core[dev]"
pip install -e "../clay-seal-identity[dev]"
pip install -e "../clay-seal-capabilities[dev]"
pip install -e ".[dev]"
pytest python/tests -q
arctl doctor
```

Optional extras:

```bash
pip install "agentauth-receipts[identity]"          # native L1 binding
pip install "agentauth-receipts[scoping]"           # L2 leases/sandbox integration
pip install "agentauth-receipts[server,verifier]"   # hosted verifier
pip install "agentauth-receipts[mcp]"               # MCP demos and gateway pieces
pip install "agentauth-receipts[frameworks]"        # common agent framework adapters
pip install "agentauth-receipts[kms]"               # AWS/GCP KMS signing support
```

## Quickstart

Shadow mode records receipts without blocking actions:

```bash
python examples/shadow_fraud_agent.py
arctl verify-bundle receipts/<receipt-id>.json
```

Programmatic usage:

```python
from agentauth.receipts import AgentWrapper, Policy

policy = Policy.from_yaml("policies/fraud_decision.yaml")
wrapper = AgentWrapper(model=my_model, policy=policy, mode="shadow")

result = wrapper.run({"transaction_id": "tx-1", "amount": 50000})
report = result.proof.verify()
assert report.valid
```

Identity-bound usage:

```python
from agentauth.capabilities.identity_adapters import get_identity_provider
from agentauth.receipts import Policy
from agentauth.receipts.integration import wrap_with_identity_session

session = get_identity_provider("oidc").build_session(
    verified_claims,
    evidence_verified=True,
)
wrapper = wrap_with_identity_session(
    model=my_model,
    policy=Policy.from_yaml("policies/fraud_decision.yaml"),
    session=session,
    mode="bounded_auto",
)
result = wrapper.run({"transaction_id": "tx-1"})
```

## Production Path

Recommended launch sequence:

1. Run in `shadow` mode and collect receipts.
2. Enable signed bundles and signed audit checkpoints.
3. Require identity binding in production partner configs.
4. Add layer 2 commit-token checks for consequential tools.
5. Move selected workflows to `bounded_auto`.
6. Expose the HTTP verifier to partners or auditors.
7. Export to OCSF, OpenTelemetry, SCITT, Vanta, Drata, or your own registered
   exporter.

Read [docs/DEV_GUIDE.md](docs/DEV_GUIDE.md), [docs/deployment.md](docs/deployment.md),
and [docs/trust_model.md](docs/trust_model.md) before production use.

## Framework Integrations

See [docs/framework_integrations.md](docs/framework_integrations.md) for adapters
covering LangChain, Pydantic AI, LlamaIndex, CrewAI, OpenAI Agents, Semantic
Kernel, AutoGen, Haystack, and generic callable/model wrappers.

## MCP and Coding-Agent Demos

```bash
python demo/poisoned_mcp_demo.py
python demo/code_exec_demo.py
python demo/rippling_deepagents_demo.py
```

The demos illustrate tool-description poisoning, stdio command risk,
goal-bound path scopes, and receipt-backed verification for enterprise coding
agents.

## Privacy and Data Handling

Layer 3 can process the richest data in the stack: prompts, tool inputs, model
outputs, policy decisions, identities, capability context, receipt bundles,
audit checkpoints, and exporter payloads. Configure minimization and retention
before sending production data through receipts.

Read [docs/PRIVACY.md](docs/PRIVACY.md) before integrating with user,
employee, financial, source-code, or regulated data.

## Documentation

- [Developer guide](docs/DEV_GUIDE.md)
- [Deployment guide](docs/deployment.md)
- [Trust model](docs/trust_model.md)
- [HTTP verifier](docs/http_verifier.md)
- [MCP integration](docs/mcp_integration.md)
- [Framework integrations](docs/framework_integrations.md)
- [Privacy and data handling](docs/PRIVACY.md)
- [Release notes](RELEASE.md)

## Compatibility Note

The public brand is Clay Seal. The package names and import paths intentionally
remain `agentauth-*` / `agentauth.*` for now so existing integrations keep
working.
