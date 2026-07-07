# Framework Integrations

Clay Seal receipts are intentionally framework-neutral. The core runtime wraps a
callable and records an execution receipt; optional adapters make that callable
shape fit common agent frameworks without adding hard dependencies to the base
package.

## Layer Substitutions

The stack is designed so each layer can be used independently:

- **L1 only:** `agentauth.identity.adapters` normalizes OIDC, SPIFFE JWT-SVID,
  Azure AD, GCP service-account, and static/local identities without importing
  capabilities or receipts.
- **L2 only:** `agentauth.capabilities.identity_adapters` and
  `agentauth.capabilities.layer` normalize external identity claims and register
  capability-layer implementations without installing the Clay Seal identity
  server/client package. `agentauth.capabilities.authorizers` also adapts
  OPA/Rego, Cedar, OpenFGA, or other external decision engines into the same
  provider-neutral capability-authorizer shape.
- **L3 only:** `AgentWrapper` works with a model and policy directly. When an
  external identity is present, `wrap_with_provider_claims()` can bind OIDC,
  SPIFFE, Auth0, AWS STS, Azure AD, or GCP service-account claims into receipts
  without requiring native L1.
- **Full stack:** `wrap_with_identity_session()` still binds a provider-neutral
  `IdentitySession` into receipts, and can carry a substituted capability-layer
  name for audit/debug metadata.

## Install

Core adapters are included in the base package:

```bash
pip install agentauth-receipts
```

Framework-specific helpers are opt-in:

```bash
pip install "agentauth-receipts[langchain]"
pip install "agentauth-receipts[pydantic-ai]"
pip install "agentauth-receipts[llamaindex]"
pip install "agentauth-receipts[crewai]"
pip install "agentauth-receipts[openai-agents]"
pip install "agentauth-receipts[semantic-kernel]"
pip install "agentauth-receipts[autogen]"
pip install "agentauth-receipts[haystack]"
pip install "agentauth-receipts[frameworks]"
```

## Plain Python Tools

Use `receipted_function()` for frameworks that accept normal Python functions as
tools, including simple Pydantic AI / CrewAI / AutoGen-style tool registration
paths.

```python
from agentauth.receipts import Policy
from agentauth.receipts.frameworks import receipted_function

policy = Policy.from_yaml("policies/fraud_decision.yaml")

def score_transaction(transaction_id: str, amount: float) -> dict[str, object]:
    return {"decision": "approve", "fraud_score": 0.12}

tool = receipted_function(
    score_transaction,
    policy,
    mode="shadow",
    audit_db=".audit/chain.sqlite",
)

result = tool("txn_123", 42.00)
```

The wrapper preserves the function signature for frameworks that inspect tool
schemas and stores the underlying `ReceiptedCallable` on `tool.agentauth_adapter`
for receipt/audit access.

## LangChain Runnable

```python
from agentauth.receipts import Policy
from agentauth.receipts.frameworks.langchain import receipted_runnable

policy = Policy.from_yaml("policies/fraud_decision.yaml")

runnable = receipted_runnable(
    lambda data: {"decision": "approve", "fraud_score": data["score"]},
    policy,
    mode="shadow",
    audit_db=".audit/chain.sqlite",
)

output = runnable.invoke({"score": 0.2})
```

## LangChain StructuredTool

```python
from agentauth.receipts import Policy
from agentauth.receipts.frameworks.langchain import receipted_tool

policy = Policy.from_yaml("policies/fraud_decision.yaml")

def score_transaction(score: float) -> dict[str, object]:
    """Score a transaction."""
    return {"decision": "approve", "fraud_score": score}

tool = receipted_tool(
    score_transaction,
    policy,
    mode="shadow",
    audit_db=".audit/chain.sqlite",
)
```

## External L2 Authorizers

Use the capabilities package directly when a deployment already has policy
infrastructure and only needs Clay Seal's provider-neutral L2 contract:

```python
from agentauth.capabilities.authorizers import opa_authorizer, openfga_authorizer

opa = opa_authorizer(
    lambda payload: opa_client.evaluate(payload),
    principal="agent-1",
    context={"tenant": "demo"},
)

openfga = openfga_authorizer(
    lambda payload: fga_client.check(payload),
    user="agent:agent-1",
    relation_for_action=lambda action: "viewer" if action == "read" else action,
)
```

These return `CapabilityAuthorizer` callables that can be attached to an
`IdentitySession` or passed through an identity-provider adapter without pulling
in native Clay Seal L1 or L3.

## Returning Receipt Metadata

By default, adapters return the target output. For observability callbacks or
framework traces, pass `output_with_receipt_metadata`:

```python
from agentauth.receipts.frameworks import output_with_receipt_metadata

tool = receipted_function(
    score_transaction,
    policy,
    mode="shadow",
    audit_db=".audit/chain.sqlite",
    output_adapter=output_with_receipt_metadata,
)
```

This adds an `_agentauth_receipt` block containing the policy decision, session
metadata, violations, and proof dictionary.

## Pydantic AI

Pydantic AI can register plain functions, which is the most portable integration
surface:

```python
from agentauth.receipts import Policy
from agentauth.receipts.frameworks.pydantic_ai import receipted_plain_tool

policy = Policy.from_yaml("policies/fraud_decision.yaml")

def score_transaction(score: float) -> dict[str, object]:
    return {"decision": "approve", "fraud_score": score}

tool = receipted_plain_tool(
    score_transaction,
    policy,
    mode="shadow",
    audit_db=".audit/chain.sqlite",
)

agent.tool_plain(tool)
```

If you prefer an SDK `Tool` object:

```python
from agentauth.receipts.frameworks.pydantic_ai import receipted_tool

tool = receipted_tool(
    score_transaction,
    policy,
    name="score_transaction",
    mode="shadow",
    audit_db=".audit/chain.sqlite",
)
```

Context-taking Pydantic AI tools should wrap the side-effecting inner function
instead of receipting the framework context object.

## LlamaIndex

```python
from agentauth.receipts import Policy
from agentauth.receipts.frameworks.llamaindex import receipted_function_tool

policy = Policy.from_yaml("policies/fraud_decision.yaml")

tool = receipted_function_tool(
    score_transaction,
    policy,
    name="score_transaction",
    description="Score a transaction under Clay Seal receipt policy.",
    mode="shadow",
    audit_db=".audit/chain.sqlite",
)
```

The returned object is a LlamaIndex `FunctionTool`.

## CrewAI

```python
from agentauth.receipts import Policy
from agentauth.receipts.frameworks.crewai import receipted_tool

policy = Policy.from_yaml("policies/fraud_decision.yaml")

tool = receipted_tool(
    score_transaction,
    policy,
    name="score_transaction",
    mode="shadow",
    audit_db=".audit/chain.sqlite",
)
```

The helper applies CrewAI's `@tool` decorator after wrapping the callable with
Clay Seal receipts.

## OpenAI Agents SDK

```python
from agentauth.receipts import Policy
from agentauth.receipts.frameworks.openai_agents import receipted_function_tool

policy = Policy.from_yaml("policies/fraud_decision.yaml")

tool = receipted_function_tool(
    score_transaction,
    policy,
    function_tool_kwargs={"name_override": "score_transaction"},
    mode="shadow",
    audit_db=".audit/chain.sqlite",
)
```

The helper wraps a sync function with Clay Seal receipts, then applies the Agents
SDK `function_tool` decorator. Pass SDK options such as `name_override` or
`description_override` through `function_tool_kwargs`.

## Semantic Kernel

```python
from agentauth.receipts import Policy
from agentauth.receipts.frameworks.semantic_kernel import receipted_kernel_function

policy = Policy.from_yaml("policies/fraud_decision.yaml")

tool = receipted_kernel_function(
    score_transaction,
    policy,
    name="score_transaction",
    description="Score a transaction under Clay Seal receipt policy.",
    mode="shadow",
    audit_db=".audit/chain.sqlite",
)
```

The helper wraps the callable and applies Semantic Kernel's `kernel_function`
decorator. Pass SDK-specific options through `kernel_function_kwargs`.

## AutoGen

```python
from agentauth.receipts import Policy
from agentauth.receipts.frameworks.autogen import receipted_function_tool

policy = Policy.from_yaml("policies/fraud_decision.yaml")

tool = receipted_function_tool(
    score_transaction,
    policy,
    name="score_transaction",
    description="Score a transaction under Clay Seal receipt policy.",
    mode="shadow",
    audit_db=".audit/chain.sqlite",
)
```

The returned object is an AutoGen Core `FunctionTool`. Pass SDK-specific options
through `function_tool_kwargs`.

## Haystack

```python
from agentauth.receipts import Policy
from agentauth.receipts.frameworks.haystack import receipted_tool

policy = Policy.from_yaml("policies/fraud_decision.yaml")

tool = receipted_tool(
    score_transaction,
    policy,
    name="score_transaction",
    description="Score a transaction under Clay Seal receipt policy.",
    parameters={"type": "object", "properties": {"score": {"type": "number"}}},
    mode="shadow",
    audit_db=".audit/chain.sqlite",
)
```

The returned object is a Haystack `Tool`. Pass SDK-specific options through
`tool_kwargs`.
