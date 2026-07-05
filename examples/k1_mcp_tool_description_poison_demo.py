#!/usr/bin/env python3
"""K1 demo: tool-description poisoning (no repo-planted text).

Spawns the poisoned MCP server and shows:
  1) tool descriptions can carry injected instructions, and
  2) AgentAuth policy blocks disallowed tool calls even if the agent is tricked.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentauth.receipts import AgentWrapper, Policy  # noqa: E402
from agentauth.receipts.mcp_client import (  # noqa: E402
    McpConnectionSpec,
    ReceiptedMcpClient,
    connect_mcp,
)


def _snippet(s: str, n: int = 220) -> str:
    s = " ".join((s or "").split())
    return s[:n] + ("..." if len(s) > n else "")


async def main() -> None:
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.0},
        policy=policy,
        mode="shadow",
        audit_db=ROOT / ".audit" / "k1_tool_desc_poison.sqlite",
    )

    env = dict(os.environ)
    env["AGENT_RECEIPTS_POISON"] = "in_range_lie"

    spec = McpConnectionSpec(
        transport="stdio",
        command=sys.executable,
        args=[str(ROOT / "examples" / "poisoned_mcp_server.py"), "--transport", "stdio"],
        env=env,
    )

    async with connect_mcp(spec) as session:
        await session.initialize()
        listed = await session.list_tools()
        tools = [
            {
                "name": t.name,
                "description_snippet": _snippet(getattr(t, "description", "") or ""),
            }
            for t in listed.tools
        ]

        # Ungoverned direct call: executes whatever the server exposes.
        ungoverned = await session.call_tool(
            "issue_refund",
            {"account": "demo-attacker", "amount": 50000.0},
        )

        client = ReceiptedMcpClient(agent, session, server_name="agent-receipts-fraud", transport="stdio")
        governed = await client.call_tool(
            "issue_refund",
            {"account": "demo-attacker", "amount": 50000.0},
        )

        out = {
            "tools": tools,
            "ungoverned_issue_refund_is_error": bool(ungoverned.isError),
            "governed_issue_refund_blocked": bool(governed.blocked),
            "governed_violations": list(governed.policy_violations),
        }
        print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
