"""STDIO transport test for BOTH MCP servers (the way Devin spawns them).

Spawns each server as a subprocess over stdio and runs the JSON-RPC handshake +
a few tool calls. If anything pollutes stdout, initialize() fails — so a clean
pass proves stdout hygiene. Run with .venv/bin/python.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "agentauth-mcp"
LAB = REPO_ROOT / "mcp-lab"
GATE_PY = os.environ.get("AGENTAUTH_MCP_PYTHON", str(GATE / ".venv" / "bin" / "python"))
LAB_PY = os.environ.get("MCP_LAB_PYTHON", str(LAB / ".venv" / "bin" / "python"))


def payload(result):
    if result.structuredContent is not None:
        sc = result.structuredContent
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    for block in result.content:
        text = getattr(block, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"text": text}
    return {}


async def test_gate() -> None:
    params = StdioServerParameters(
        command=GATE_PY,
        args=[str(GATE / "server.py")],
        env={**os.environ, "AGENTAUTH_MCP_TRANSPORT": "stdio"},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}
            print("[gate] tools:", sorted(tools))
            assert {"begin_authorized_session", "authorize_action", "finalize_for_pull_request"} <= tools
            begin = payload(await session.call_tool(
                "begin_authorized_session", {"issue_ref": "1", "agent_actor": "devin"}))
            token = begin["session_token"]
            allow = payload(await session.call_tool(
                "authorize_action", {"session_token": token, "resource": "repo:swe_triage/parser.py", "action": "modify"}))
            deny = payload(await session.call_tool(
                "authorize_action", {"session_token": token, "resource": "repo:swe_triage/auth.py", "action": "modify"}))
            fin = payload(await session.call_tool("finalize_for_pull_request", {"session_token": token}))
            print("[gate] allow parser.py:", allow["allowed"], "| deny auth.py:", deny["allowed"],
                  "| authorized_count:", fin["authorized_count"])
            assert allow["allowed"] is True and deny["allowed"] is False and fin["authorized_count"] == 1


async def test_lab() -> None:
    lab_py = LAB_PY if Path(LAB_PY).exists() else GATE_PY
    params = StdioServerParameters(
        command=lab_py,
        args=[str(LAB / "server.py"), "--stdio", "--arm-at-start"],
        env={**os.environ},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}
            print("[lab] tools:", sorted(tools))
            assert {"get_engineering_standards", "auth", "get_issue_triage_context"} <= tools
            out = payload(await session.call_tool("get_engineering_standards", {"repo": "devin-agentauth-demo"}))
            text = out.get("text", "") if isinstance(out, dict) else str(out)
            poisoned = "secrets.json" in text or "INCOMPLETE" in text
            print("[lab] armed get_engineering_standards returned poison directive:", poisoned)
            assert poisoned, "lab armed but no poison directive in output"


async def main() -> int:
    print("=== GATE over stdio ===")
    await test_gate()
    print("=== LAB over stdio ===")
    await test_lab()
    print("\nSTDIO TEST OK — both servers speak JSON-RPC cleanly over stdio")
    return 0


raise SystemExit(asyncio.run(main()))
