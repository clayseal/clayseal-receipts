from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from agentauth.receipts import AgentWrapper, Policy, ReceiptedMcpGateway
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.sandbox_governor import RuleBasedSandboxGovernor
from agentauth.core.signing import generate_keypair

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CASES = ROOT / "python" / "tests" / "fixtures" / "devin_redteaming_backlog.jsonl"


@dataclass(frozen=True)
class CaseStep:
    tool: str | None
    args: dict[str, Any]
    handler_result: dict[str, Any] | None
    expect_status: str | None
    expect_blocked: bool | None
    expect_violations_contain: list[str]
    attach_commit_token: bool
    issue_commit_token_as: str | None
    commit_token_ref: str | None
    admin: dict[str, Any] | None


@dataclass(frozen=True)
class CognitionCase:
    name: str
    query_id: str | None
    steps: list[CaseStep]
    commit_required_tools: set[str]
    permit_ttl_seconds: int


def _load_case_step(raw: dict[str, Any]) -> CaseStep:
    if isinstance(raw.get("admin"), dict):
        return CaseStep(
            tool=None,
            args={},
            handler_result=None,
            expect_status=None,
            expect_blocked=None,
            expect_violations_contain=[],
            attach_commit_token=False,
            issue_commit_token_as=None,
            commit_token_ref=None,
            admin=dict(raw["admin"]),
        )
    expect = raw.get("expect", {}) if isinstance(raw.get("expect"), dict) else {}
    return CaseStep(
        tool=str(raw["tool"]),
        args=dict(raw.get("args", {})),
        handler_result=dict(raw["handler_result"]) if isinstance(raw.get("handler_result"), dict) else None,
        expect_status=str(expect.get("status", "ok")),
        expect_blocked=bool(
            expect.get("blocked", expect.get("status") in {"blocked", "step_up_required"})
        ),
        expect_violations_contain=[str(s) for s in expect.get("violations_contain", [])],
        attach_commit_token=bool(raw.get("attach_commit_token", False)),
        issue_commit_token_as=(
            str(raw["issue_commit_token_as"]) if raw.get("issue_commit_token_as") else None
        ),
        commit_token_ref=str(raw["commit_token_ref"]) if raw.get("commit_token_ref") else None,
        admin=None,
    )


def _load_case(raw: dict[str, Any]) -> CognitionCase:
    name = str(raw.get("name") or "unnamed")
    query_id = raw.get("query_id")
    steps_raw = raw.get("steps", [])
    if not isinstance(steps_raw, list) or not steps_raw:
        raise ValueError(f"case {name!r} has no steps")
    commit_required_tools = set(str(s) for s in raw.get("commit_required_tools", []))
    permit_ttl_seconds = int(raw.get("permit_ttl_seconds", 60))
    if permit_ttl_seconds <= 0:
        raise ValueError(f"case {name!r} has invalid permit_ttl_seconds")
    steps = [_load_case_step(dict(step)) for step in steps_raw if isinstance(step, dict)]
    return CognitionCase(
        name=name,
        query_id=str(query_id) if query_id is not None else None,
        steps=steps,
        commit_required_tools=commit_required_tools,
        permit_ttl_seconds=permit_ttl_seconds,
    )


def _case_paths() -> list[Path]:
    paths: list[Path] = []
    for env_name in ("AGENT_RECEIPTS_DEVIN_CASES", "AGENT_RECEIPTS_COGNITION_CASES"):
        env = os.getenv(env_name)
        if not env:
            continue
        for item in env.split(","):
            item = item.strip()
            if item:
                paths.append(Path(item))
    if DEFAULT_CASES.is_file():
        paths.append(DEFAULT_CASES)
    return paths


def _load_cases() -> list[CognitionCase]:
    cases: list[CognitionCase] = []
    for path in _case_paths():
        if not path.is_file():
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            raw = json.loads(line)
            if not isinstance(raw, dict):
                raise ValueError(f"{path}:{i} is not a JSON object")
            cases.append(_load_case(raw))
    return cases


CASES = _load_cases()


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_cognition_case(case: CognitionCase):
    tool_names = {step.tool for step in case.steps if step.tool is not None}
    policy = Policy.from_dict(
        {
            "version": 1,
            "name": "cognition-cases",
            "tier": "structural",
            "capability": "fully_proven",
            "allowed_tools": {"tools": sorted(tool_names)},
        }
    )
    cert = dev_certificate(policy.commitment(), scope=sorted(tool_names))
    agent = AgentWrapper(
        model=lambda inp: {},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )

    permit_key = generate_keypair()
    commit_key = generate_keypair()
    governor = RuleBasedSandboxGovernor(
        commit_required_tools=set(case.commit_required_tools),
        permit_signing_key=permit_key,
        permit_ttl_seconds=int(case.permit_ttl_seconds),
    )
    gw = ReceiptedMcpGateway(
        agent,
        server_name="cognition",
        sandbox_governor=governor,
        query_id=case.query_id,
        commit_signing_key=commit_key,
        commit_ttl_seconds=300,
    )

    tool_queues: dict[str, list[dict[str, Any]]] = {}
    for step in case.steps:
        if step.handler_result is not None:
            tool_queues.setdefault(step.tool, []).append(step.handler_result)

    for tool in tool_names:
        queue = tool_queues.get(tool, [])

        def _handler(args: dict[str, Any], *, _tool=tool, _queue=queue):
            if _queue:
                return _queue.pop(0)
            return {"ok": True}

        gw.register_tool(tool, _handler)

    commit_tokens: dict[str, dict[str, Any]] = {}

    for step in case.steps:
        if step.admin is not None:
            if "set_query_id" in step.admin:
                gw.set_query_id(step.admin.get("set_query_id"))
            if step.admin.get("revoke_permits"):
                gw.revoke_permits(bump_authority_version=False)
            continue

        assert step.tool is not None
        args = dict(step.args)
        if step.issue_commit_token_as:
            commit_tokens[step.issue_commit_token_as] = gw.issue_commit_token(step.tool, args)
        if step.commit_token_ref:
            args["_commit_token"] = commit_tokens[step.commit_token_ref]
        elif step.attach_commit_token:
            args["_commit_token"] = gw.issue_commit_token(step.tool, args)

        result = gw.call_tool(step.tool, args)
        assert step.expect_status is not None
        assert step.expect_blocked is not None
        assert result.output["status"] == step.expect_status
        assert result.blocked is step.expect_blocked
        for needle in step.expect_violations_contain:
            assert any(needle in v for v in result.policy_violations)


@pytest.mark.skipif(CASES, reason="Devin redteaming backlog already loaded from fixtures/env")
def test_devin_redteaming_backlog_not_configured():
    """
    This test exists to document the harness when no case files are present.

    Provide a JSONL path via `AGENT_RECEIPTS_DEVIN_CASES` (or legacy
    `AGENT_RECEIPTS_COGNITION_CASES`) or add
    `python/tests/fixtures/devin_redteaming_backlog.jsonl`.
    """
    pytest.skip("No Devin cases configured")
