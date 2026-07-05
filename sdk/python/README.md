# AgentAuth - Python SDK

Verifiable identity for AI agents. Give your agents a real, attested identity
and a short-lived signed credential they can carry on outbound calls - in a few
lines of code.

The SDK **wraps your agent at the boundary**; you don't scatter identity
plumbing through your agent's logic.

## Install

```bash
pip install agentauth
```

## Quickstart

```python
from agentauth import AgentAuth

auth = AgentAuth(api_key="aa_...", dev_attestation=True)  # localhost demos/tests
agent = auth.identify(agent_type="researcher", owner="alice@acme.ai",
                      scopes=["db:read", "web:*"])

print(agent.token)                                 # signed JWT to carry on calls
```

`AgentAuth(base_url=...)` (or `AGENTAUTH_BASE_URL`) points at your hosted
service; it defaults to `http://localhost:8000`.

Identity is attested, not declared. For production, register node trust anchors
and registration entries out of band, then pass a platform/SPIRE-issued
attestation document:

```python
agent = auth.identify(
    agent_type="researcher",
    owner="alice@acme.ai",
    attestation_document=document,
)
```

`dev_attestation=True` is a localhost-only convenience for demos and tests: it
self-registers a throwaway node trust anchor and registration entry, then signs a
matching attestation document.

## Validate a token

```python
result = auth.validate(agent.token)
if result.valid:
    print(result.claims["sub"])    # the agent id
```

A session can validate itself, too:

```python
agent.validate()
```

## Revoke

```python
agent.revoke()                     # kill this credential
# or, by id, from the admin surface:
auth.revoke(agent.agent_id)
```

## Read the agent registry

```python
for info in auth.agents(status="active"):
    print(info.id, info.agent_type, info.owner)

info = auth.agent(agent.agent_id)
```

## Errors are actionable

Every exception carries a machine `code`, a human `message`, and a plain-English
`suggestion`:

```python
from agentauth import InvalidTokenError

try:
    auth.validate("not-a-jwt")
except InvalidTokenError as e:
    print(e.code)         # invalid_token
    print(e.suggestion)   # how to fix it
```

## Logging

The SDK provides a configured `agentauth` logger. Format auto-detects (JSON in
structured environments, text on a TTY) or set `AgentAuth(log_format="json")` /
`AGENTAUTH_LOG_FORMAT`.

## Development

```bash
# From the repo root — one package, one venv
pip install -e '.[dev]'
pytest sdk/python/tests   # runs the SDK against the backend over real HTTP
```
