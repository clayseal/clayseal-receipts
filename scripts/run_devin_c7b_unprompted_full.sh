#!/usr/bin/env bash
# C7b: MCP rug-pull unprompted — full harness (starts MCP server + registers in Devin).
#
# This wraps `scripts/run_devin_c7b_unprompted.sh`, removing the manual steps:
# - start mcp-lab
# - expose with ngrok
# - add MCP server in Devin
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MCP_LAB="$ROOT/mcp-lab"
PORT="${PORT:-8848}"
SERVER_NAME="eng-context"

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: $1 required" >&2
    exit 1
  fi
}
require devin
require ngrok
require curl

cleanup() {
  devin mcp remove --scope user "$SERVER_NAME" 2>/dev/null || true
  if [[ -n "${LAB_PID:-}" ]]; then
    kill "$LAB_PID" 2>/dev/null || true
    wait "$LAB_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

find_ngrok_url_for_port() {
  python3 - "$PORT" <<'PY'
import json, sys, urllib.request
port = int(sys.argv[1])
try:
    with urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=1) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
except Exception:
    print("")
    raise SystemExit(0)
tunnels = payload.get("tunnels", []) or []
for t in tunnels:
    pub = t.get("public_url", "")
    if not isinstance(pub, str) or not pub.startswith("https://"):
        continue
    cfg = t.get("config") or {}
    addr = str(cfg.get("addr") or "")
    if addr.endswith(f":{port}") or addr.endswith(f"localhost:{port}") or addr.endswith(f"127.0.0.1:{port}"):
        print(pub.rstrip("/"))
        raise SystemExit(0)
print("")
PY
}

(
  cd "$MCP_LAB"
  PORT="$PORT" ./run.sh
) >/tmp/mcp-lab-c7b.log 2>&1 &
LAB_PID=$!

MCP_PUBLIC=""
for _ in $(seq 1 40); do
  MCP_PUBLIC="$(find_ngrok_url_for_port || true)"
  [[ -n "$MCP_PUBLIC" ]] && break
  sleep 0.5
done
if [[ -z "$MCP_PUBLIC" ]]; then
  echo "error: could not find ngrok URL for mcp-lab (see /tmp/mcp-lab-c7b.log)" >&2
  exit 2
fi
MCP_URL="$MCP_PUBLIC/mcp"

devin mcp remove --scope user "$SERVER_NAME" 2>/dev/null || true
devin mcp add --scope user --transport http "$SERVER_NAME" "$MCP_URL" >/dev/null

NGROK_MCP_URL="$MCP_URL" PORT="$PORT" bash "$ROOT/scripts/run_devin_c7b_unprompted.sh"
