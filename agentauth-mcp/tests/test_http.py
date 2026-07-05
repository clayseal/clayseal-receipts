"""Over-the-wire MCP test: connect like Devin would (streamable-http) and drive
the full lifecycle. Assumes the server is already running on $TEST_PORT.
Run with .venv/bin/python after starting server.py."""
from __future__ import annotations

import asyncio
import json
import os

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

PORT = os.environ.get("TEST_PORT", "8851")


def payload(result):
    if result.structuredContent is not None:
        sc = result.structuredContent
        # FastMCP wraps non-dict returns under "result"; dict returns pass through.
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    for block in result.content:
        text = getattr(block, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"text": text}
    return {}


async def main() -> int:
    # Test the ROOT alias path too (Devin sometimes posts to "/").
    url = f"http://127.0.0.1:{PORT}/mcp"
    async with streamablehttp_client(url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}
            print("tools:", sorted(tools))
            assert {
                "begin_authorized_session",
                "authorize_action",
                "finalize_for_pull_request",
            } <= tools

            begin = payload(await session.call_tool(
                "begin_authorized_session", {"issue_ref": "1", "agent_actor": "devin-ai-integration[bot]"}
            ))
            token = begin["session_token"]
            assert "swe_triage" not in json.dumps(begin), "scope paths leaked to agent"
            print("begin OK, scope hidden (token-only):", begin["authority_summary"]["scope_model"][:50], "...")

            allow = payload(await session.call_tool(
                "authorize_action", {"session_token": token, "resource": "repo:swe_triage/parser.py", "action": "modify"}
            ))
            deny = payload(await session.call_tool(
                "authorize_action", {"session_token": token, "resource": "repo:swe_triage/auth.py", "action": "modify"}
            ))
            print("allow parser.py:", allow)
            print("deny auth.py:", deny)
            assert allow["allowed"] is True
            assert deny["allowed"] is False

            fin = payload(await session.call_tool(
                "finalize_for_pull_request", {"session_token": token}
            ))
            print("finalize:", {k: fin.get(k) for k in ("receipt_ref", "authorized_count", "denied_count")})
            assert fin["authorized_count"] == 1 and fin["denied_count"] == 1

    print("\nHTTP TEST OK")
    return 0


raise SystemExit(asyncio.run(main()))
