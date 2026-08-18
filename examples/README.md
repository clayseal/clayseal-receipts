# Clay Seal examples

```bash
python examples/01_quickstart.py
python demo/poisoned_mcp_demo.py
```

Identity scripts use `AGENTAUTH_BASE_URL` (default `http://localhost:8000`) when
set. Otherwise they boot a throwaway in-process backend.

| Path | Shows |
|------|-------|
| [`01_quickstart.py`](01_quickstart.py) | Identity lifecycle |
| [`shadow_fraud_agent.py`](shadow_fraud_agent.py) | Receipted agent in `shadow` mode |
| [`../demo/poisoned_mcp_demo.py`](../demo/poisoned_mcp_demo.py) | Poisoned MCP server, receipts |

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,mcp]"
```
