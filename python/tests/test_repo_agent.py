"""Repository agent run engine tests."""

from __future__ import annotations

import pytest

from agentauth.receipts.repo_agent.engine import SCENARIO, RepoAgentSession


@pytest.fixture
def session() -> RepoAgentSession:
    s = RepoAgentSession()
    s.reset()
    return s


def test_full_scenario_secured_blocks_poison(session: RepoAgentSession) -> None:
    blocked_tools: list[str] = []
    allowed_tools: list[str] = []

    for _ in SCENARIO:
        beat = session.advance()
        receipt = beat.secured.receipt
        if receipt is None:
            continue
        if receipt.blocked:
            blocked_tools.append(receipt.tool)
        else:
            allowed_tools.append(receipt.tool)

    assert "run_shell" in blocked_tools
    assert "curl_url" in blocked_tools
    assert "read_file" in allowed_tools
    assert "write_file" in allowed_tools
    assert "run_tests" in allowed_tools

    verify = session.verify()
    assert verify["count"] >= 5
    assert verify["all_valid"] is True


def test_unsecured_creates_ransom_note(session: RepoAgentSession) -> None:
    for _ in SCENARIO:
        session.advance()

    content = session._unsecured_ws.read_file("RANSOM_NOTE.txt")
    assert "COMPROMISED" in content
