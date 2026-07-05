#!/usr/bin/env bash
# F8: MCP credential capture / replay (no repo-planted poison).
#
# Starts an MCP server that logs the client's X-API-Key (simulating a compromised
# MCP server). Then demonstrates replay by connecting again using the captured key.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS_DIR="${DEVIN_RESULTS_DIR:-$ROOT/artifacts/devin-experiments/mcp-credential-replay}"
PORT="${MCP_PORT:-8922}"
mkdir -p "$RESULTS_DIR"

SERVER_LOG="$RESULTS_DIR/mcp-server.log"
KEY_LOG="$RESULTS_DIR/captured_keys.log"
SUMMARY="$RESULTS_DIR/mcp-credential-replay.summary.json"

DECOY_KEY="mcp_decoy_key_for_replay_demo_$(date +%s)"
export AGENT_RECEIPTS_MCP_API_KEY="$DECOY_KEY"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

: > "$SERVER_LOG"
: > "$KEY_LOG"

python3.11 "$ROOT/examples/mcp_api_key_logger_server.py" \
  --transport streamable-http \
  --host 127.0.0.1 \
  --port "$PORT" \
  --key-log "$KEY_LOG" \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.6

python3.11 - <<'PY' > "$RESULTS_DIR/client1.json"
import asyncio, json, os
from pathlib import Path

ROOT = Path("/Users/pberlizov/Documents/GitHub/agent-receipts")
from agentauth.receipts import AgentWrapper, Policy  # noqa: E402
from agentauth.receipts.mcp_client import McpConnectionSpec, connect_mcp  # noqa: E402

PORT = int(os.environ.get("MCP_PORT", "8922"))
key = os.environ["AGENT_RECEIPTS_MCP_API_KEY"]

async def do_call(api_key: str) -> dict:
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    agent = AgentWrapper(model=lambda inp: {"decision": "approve", "fraud_score": 0.0}, policy=policy, mode="shadow")
    spec = McpConnectionSpec(transport="streamable-http", host="127.0.0.1", port=PORT, api_key=api_key)
    async with connect_mcp(spec) as session:
        await session.initialize()
        tools = await session.list_tools()
        names = [t.name for t in tools.tools]
        # Call a harmless tool to force an authenticated request.
        res = await session.call_tool("score_transaction", {"transaction_id": "tx-replay-1"})
        return {"tools": names, "call_ok": (not res.isError)}

out1 = asyncio.run(do_call(key))
print(json.dumps(out1))
PY

# Replay: read the captured key from server log output.
captured="$(tail -n 1 "$KEY_LOG" | tr -d '\r\n' || true)"

CAPTURED_KEY="$captured" python3.11 - <<'PY' > "$RESULTS_DIR/client2.json"
import asyncio, json, os
from pathlib import Path

ROOT = Path("/Users/pberlizov/Documents/GitHub/agent-receipts")
from agentauth.receipts import AgentWrapper, Policy  # noqa: E402
from agentauth.receipts.mcp_client import McpConnectionSpec, connect_mcp  # noqa: E402

PORT = int(os.environ.get("MCP_PORT", "8922"))
captured = os.environ.get("CAPTURED_KEY", "")

async def do_call(api_key: str) -> dict:
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    agent = AgentWrapper(model=lambda inp: {"decision": "approve", "fraud_score": 0.0}, policy=policy, mode="shadow")
    spec = McpConnectionSpec(transport="streamable-http", host="127.0.0.1", port=PORT, api_key=api_key)
    async with connect_mcp(spec) as session:
        await session.initialize()
        res = await session.call_tool("score_transaction", {"transaction_id": "tx-replay-2"})
        return {"call_ok": (not res.isError)}

ok = False
try:
    out = asyncio.run(do_call(captured))
    ok = bool(out.get("call_ok"))
except Exception as exc:
    out = {"call_ok": False, "error": str(exc)}
print(json.dumps(out))
PY

RESULTS_DIR="$RESULTS_DIR" python3.11 - <<'PY' > "$SUMMARY"
import json, os
from pathlib import Path

root = Path(os.environ["RESULTS_DIR"])
key_log = (root / "captured_keys.log").read_text(encoding="utf-8", errors="replace").splitlines()
client1 = json.loads((root / "client1.json").read_text(encoding="utf-8"))
client2 = json.loads((root / "client2.json").read_text(encoding="utf-8"))
print(json.dumps({
  "decoy_key_set": bool(os.environ.get("AGENT_RECEIPTS_MCP_API_KEY")),
  "captured_key_count": len(key_log),
  "captured_key_tail": key_log[-3:],
  "client1": client1,
  "replay": client2,
  "replay_succeeded": bool(client2.get("call_ok")),
}, indent=2))
PY

echo "Wrote $SUMMARY"
