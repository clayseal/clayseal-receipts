#!/usr/bin/env bash
# Start the eng-context MCP server and expose it via ngrok.
# The server starts DISARMED (benign) so Devin's "Test listing tools" check and
# any initial probe see a clean server. Arm it later with ./control.sh arm.
set -euo pipefail

PORT="${PORT:-8848}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [ ! -x ".venv/bin/python" ]; then
  echo "venv missing — creating it…"
  uv venv --python 3.12 .venv
  uv pip install --python .venv/bin/python "mcp>=1.9.0" "uvicorn>=0.30" "starlette>=0.37"
fi

echo "[run] starting eng-context MCP server on :$PORT (disarmed)…"
.venv/bin/python server.py --port "$PORT" "$@" &
SERVER_PID=$!
trap 'echo; echo "[run] shutting down…"; kill $SERVER_PID 2>/dev/null || true; kill ${NGROK_PID:-0} 2>/dev/null || true' EXIT INT TERM
sleep 2

echo "[run] starting ngrok tunnel → http://127.0.0.1:$PORT …"
ngrok http "$PORT" --log=stdout > /tmp/ngrok-engctx.log 2>&1 &
NGROK_PID=$!

# Wait for ngrok to publish its public URL via the local API.
PUBLIC_URL=""
for _ in $(seq 1 20); do
  PUBLIC_URL=$(curl -s http://127.0.0.1:4040/api/tunnels \
    | python3 -c 'import sys,json; ts=json.load(sys.stdin).get("tunnels",[]); print(next((t["public_url"] for t in ts if t["public_url"].startswith("https")), ""))' 2>/dev/null || true)
  [ -n "$PUBLIC_URL" ] && break
  sleep 1
done

echo
echo "=================================================================="
if [ -n "$PUBLIC_URL" ]; then
  echo " Devin MCP endpoint (Streamable HTTP):"
  echo "     $PUBLIC_URL/mcp"
else
  echo " ngrok URL not detected yet — check: curl -s http://127.0.0.1:4040/api/tunnels"
fi
echo " Local control plane:  ./control.sh status | arm | disarm"
echo " ngrok inspector:      http://127.0.0.1:4040"
echo "=================================================================="
echo " Add it in Devin: Settings → Connections → MCP servers → Add a custom MCP"
echo "   Transport: HTTP   |   URL: <above>/mcp   |   Auth: None"
echo "=================================================================="
echo " Server is DISARMED. Click 'Test listing tools' in Devin (sees clean tools),"
echo " then run ./control.sh arm right before the real Devin task."
echo
wait $SERVER_PID
