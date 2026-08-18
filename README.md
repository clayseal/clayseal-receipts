# Clay Seal Receipts

<img src="docs/assets/clay-seal-logo.png" alt="Clay Seal logo" width="360">

After an agent acts, logs lie. A receipt is a signed record of what was
requested, what policy said, and what happened. Another party can check it
later without trusting your app.

Python package: `clayseal-receipts`. Import path remains `agentauth.receipts`.

## Install

```bash
pip install "clayseal-receipts[server,verifier] @ git+https://github.com/clayseal/clayseal-receipts.git@v0.5.2"
```

For local development from this repo:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest python/tests -q
```

The identity seam tests need the optional identity package:

```bash
pip install -e ".[identity]"
pytest sdk/python/tests -q
```

Receipts is standalone. It ships the small `agentauth.core` contract layer it
needs, so you do not need a private Clay Seal dependency to use it. Native Clay
Seal identity and capability binding are optional extras:

```bash
pip install "clayseal-receipts[identity] @ git+https://github.com/clayseal/clayseal-receipts.git@v0.5.2"   # Clay Seal identity sessions
pip install "clayseal-receipts[frameworks] @ git+https://github.com/clayseal/clayseal-receipts.git@v0.5.2" # common agent framework adapters
pip install "clayseal-receipts[mcp] @ git+https://github.com/clayseal/clayseal-receipts.git@v0.5.2"        # MCP examples and gateway pieces
pip install "clayseal-receipts[opa] @ git+https://github.com/clayseal/clayseal-receipts.git@v0.5.2"        # OPA authorization provider
```

## Quickstart

```python
from agentauth.receipts import AgentWrapper, Policy

policy = Policy.from_yaml("policies/fraud_decision.yaml")
wrapper = AgentWrapper(model=my_model, policy=policy, mode="shadow")

result = wrapper.run({"transaction_id": "tx-1", "amount": 50000})
report = result.proof.verify()
assert report.valid
```

`shadow` mode records receipts without blocking actions. Move selected
workflows to `bounded_auto` only after you have reviewed receipts from real
traffic.

## Identity Binding

Receipts can bind to Clay Seal Identity or to claims from providers you already
verify, including OIDC, SPIFFE JWT, Auth0, AWS STS, Azure AD, Entra, and GCP.

```python
from agentauth.receipts.identity_providers import get_identity_provider
from agentauth.receipts.integration import wrap_with_identity_session

session = get_identity_provider("oidc").build_session(
    verified_claims,
    evidence_verified=True,
)

wrapper = wrap_with_identity_session(
    model=my_model,
    policy=policy,
    session=session,
    mode="shadow",
)
```

Provider adapters map already-verified identity claims into receipt authority
bindings. They do not replace JWT verification, PoP checks, token revocation, or
your normal gateway policy.

## Authorization Providers

Receipts can enforce actions through a session authorizer or through a
swappable provider. Built-in provider names are `agentauth`, `opa`, `cedar`,
`openfga`, and `casbin`; teams can also register a provider from a Python
callable.

```python
from agentauth.receipts.capability_providers import from_callable
from agentauth.receipts.integration import authorizer_from_provider

provider = from_callable(
    lambda action, resource, context: action == "read",
    name="read_only",
)
authorize = authorizer_from_provider(provider)
```

## What this is

Clay Seal Receipts is an audit layer. It helps you prove what an agent was
allowed to do and what it actually did. It is not a sandbox by itself.

## Docs

- [Developer guide](docs/DEV_GUIDE.md)
- [Deployment guide](docs/deployment.md)
- [Trust model](docs/trust_model.md)
- [Framework integrations](docs/framework_integrations.md)
- [HTTP verifier](docs/http_verifier.md)
- [Privacy and data handling](docs/PRIVACY.md)
- [Security policy](SECURITY.md)
