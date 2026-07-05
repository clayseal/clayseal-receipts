from __future__ import annotations

import textwrap
from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy, ReceiptedMcpGateway
from agentauth.capabilities.scoping.goal import GoalSpec


def test_gateway_mint_lease_blocks_out_of_scope_write(tmp_path: Path) -> None:
    (tmp_path / "swe_triage").mkdir()
    (tmp_path / "swe_triage" / "parser.py").write_text(
        textwrap.dedent(
            '''
            def parse_ticket(raw: str) -> dict:
                return {"ok": True}
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "swe_triage" / "auth.py").write_text(
        "def verify_token(raw: str) -> bool:\n    return bool(raw)\n",
        encoding="utf-8",
    )

    policy = Policy.from_dict(
        {
            "version": 1,
            "name": "scope-gateway",
            "tier": "structural",
            "capability": "fully_proven",
            "allowed_tools": {"tools": ["write_file", "read_file"]},
        }
    )
    agent = AgentWrapper(model=lambda _inp: {"ok": True}, policy=policy, mode="shadow")
    gw = ReceiptedMcpGateway(agent, session_id="sess-1")
    gw.bind_repo(tmp_path)
    gw.set_query_id("q-1")
    gw.mint_capability_lease(
        GoalSpec(query_id="q-1", summary="Fix parse_ticket bug in parser"),
        top_k=3,
    )

    def _write(_args: dict[str, object]) -> object:
        raise AssertionError("write handler should not run when lease blocks")

    def _write_ok(_args: dict[str, object]) -> object:
        return {"status": "ok"}

    gw.register_tool("write_file", _write)
    gw.register_tool("read_file", lambda _args: {"content": "ok"})

    blocked = gw.call_tool(
        "write_file",
        {"path": "swe_triage/auth.py", "content": "evil"},
    )
    assert blocked.blocked is True
    assert any("capability lease" in v for v in blocked.policy_violations)

    gw.register_tool("write_file", _write_ok)
    in_scope = gw.call_tool(
        "write_file",
        {"path": "swe_triage/parser.py", "content": "# ok\n"},
    )
    assert in_scope.blocked is False

    allowed = gw.call_tool(
        "read_file",
        {"path": "swe_triage/parser.py"},
    )
    assert allowed.blocked is False
