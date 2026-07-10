#!/usr/bin/env bash
# Boot the AgentAuth gate MCP server and expose it to Devin via ngrok.
#
#   ./run.sh            # set up venv (if needed), boot server + ngrok
#   PORT=8849 ./run.sh  # override port
#
# Then in Devin: Settings -> Connections -> MCP servers -> Add a custom MCP
#   Transport: HTTP   URL: <ngrok-https-url>/mcp   Auth: None
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

AGENT_RECEIPTS_SRC="${AGENT_RECEIPTS_SRC:-$(cd "$HERE/.." && pwd)}"
PORT="${PORT:-8849}"

# 1. venv + deps (agentauth consumed editable from the sibling checkout)
if [ ! -d .venv ]; then
  echo "[run] creating venv"
  uv venv --python 3.12 .venv
fi
echo "[run] installing deps (agent-receipts[mcp,server,verifier] + server deps)"
uv pip install --python .venv -e "${AGENT_RECEIPTS_SRC}[mcp,server,verifier]" uvicorn starlette httpx pyyaml >/dev/null

# 2. Halo2 policy-proof CLI (the gate proves; CI verifies). Build if missing.
CLI="${AGENT_RECEIPTS_CLI:-$AGENT_RECEIPTS_SRC/target/release/agent-receipts}"
if [ ! -x "$CLI" ]; then
  echo "[run] building agent-receipts Halo2 CLI (one-time, a few minutes)"
  (cd "$AGENT_RECEIPTS_SRC" && cargo build --release -p agent-receipts-cli)
fi
export AGENT_RECEIPTS_CLI="$CLI"
echo "[run] using prover CLI: $AGENT_RECEIPTS_CLI"

# 3. signed mandate (idempotent)
if [ ! -f mandates/swe-triage.authorization.json ]; then
  echo "[run] generating signed mandate"
  .venv/bin/python setup_mandate.py
fi

# 4. boot server (background) + ngrok tunnel.
# NOTE: STDIO is the default transport now (recommended for Devin — no ports/
# tunnels). This script is only for the optional remote/HTTP path, so force it.
export AGENTAUTH_MCP_TRANSPORT="streamable-http"
export AGENTAUTH_MCP_PORT="$PORT"
echo "[run] starting AgentAuth gate on http://127.0.0.1:$PORT (MCP at / and /mcp)"
.venv/bin/python server.py &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT

sleep 2
if command -v ngrok >/dev/null 2>&1; then
  echo "[run] opening ngrok tunnel -> point Devin at <ngrok-url>/mcp"
  ngrok http "$PORT"
else
  echo "[run] ngrok not found; server is local at http://127.0.0.1:$PORT/mcp"
  wait $SERVER_PID
fi
