# MCP integration

Clay Seal Receipts wraps [Model Context Protocol](https://modelcontextprotocol.io/) tool calls with the same audit chain and `ExecutionProof` envelope used for agent runs.

## Components

| Type | Role |
|------|------|
| `ReceiptedMcpGateway` | Register tool handlers; `call_tool` enforces Biscuit capabilities + delegation |
| `ToolCallResult` | Per-tool receipt (`proof`, `audit_record`, violations) |
| `DelegationToken` | Sub-agent scope with monotonic reduction |
| `mcp_bridge.wrap_mcp_session` | Optional patch for official `mcp` Python SDK |

## Audit shape

Each tool call appends an audit record:

- **action**: `mcp.tools/call/<tool_name>`
- **authorization context** (`protocol: mcp`):
  - `mcp_server`, `tool_name`, `arguments_hash`
  - `delegation_id`, `delegation_depth` (if delegated)
  - `mode`, `principal`, `blocked`

## Operating modes

| Mode | Disallowed tool | Policy violation on output |
|------|-----------------|---------------------------|
| `shadow` | Logged; handler still runs if registered | Logged |
| `recommend` | Runs; `recommended_action` set | Logged + recommend |
| `bounded_auto` | **Blocked** — no handler execution | Abstain on agent `run` only |
| `prove` | Same as shadow/bounded per mode + ZK when applicable | Same |

## Capability Authorization

MCP tools are authorized with the same capability-token grammar used everywhere
else:

```python
capabilities=[
    {"resource": "mcp_tool", "action": "score_transaction"},
    {"resource": "mcp_tool", "action": "fetch_customer_profile"},
]
```

`AgentSession.wrap()` installs a Biscuit-backed authorizer on the wrapped
`AgentWrapper`. `ReceiptedMcpGateway` maps `call_tool("score_transaction", ...)`
to the Biscuit operation `mcp_tool:score_transaction` and checks it before the
tool handler runs. A denied capability means no side-effecting tool body is
executed.

## Delegation

```python
from uuid import uuid4
from agentauth.receipts import issue_delegation, ReceiptedMcpGateway

child = issue_delegation(
    parent=None,
    delegate_agent_id=uuid4(),
    capabilities=[{"resource": "mcp_tool", "action": "score_transaction"}],
)
gateway = ReceiptedMcpGateway(worker_agent, delegation=child)
```

Issuing a delegation with expanded capabilities raises `ValueError`. Each child
delegation's capabilities must be a subset of its parent's capabilities. For
runtime authorization, prefer Biscuit attenuation via `AgentSession.delegate()`;
the signed delegation object is retained for receipt lineage and portable audit.

## Official MCP SDK (optional)

```bash
pip install "agentauth[mcp]"
```

```python
from agentauth.receipts.mcp_bridge import wrap_mcp_session

# session = mcp.ClientSession(...)
wrap_mcp_session(session, gateway)
# session.call_tool(...) now routes through receipts
```

## Examples

Local handlers (no MCP process):

```bash
python3 examples/mcp_fraud_agent.py
```

Live stdio MCP server:

```bash
pip install -e ".[mcp]"
python3 examples/mcp_live_client.py
```

See [mcp_live_server.md](mcp_live_server.md).
