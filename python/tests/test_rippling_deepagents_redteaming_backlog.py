from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_MODULE_DIR = ROOT / "examples" / "rippling-deepagents-demo"
if str(FIXTURE_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_MODULE_DIR))

from rippling_fixture_agent import build_fixture_agent, gateway_for_tool  # noqa: E402

DEFAULT_CASES = (
    ROOT / "python" / "tests" / "fixtures" / "rippling_deepagents_redteaming_backlog.jsonl"
)
DEFAULT_DB = "fixtures/mock_rippling.db"


@dataclass(frozen=True)
class RipplingCaseStep:
    tool: str | None
    args: dict[str, Any]
    expect_status: str | None
    expect_blocked: bool | None
    expect_violations_contain: list[str]
    expect_output_contains: list[str]
    expect_output_not_contains: list[str]
    attach_commit_token: bool
    issue_commit_token_as: str | None
    commit_token_ref: str | None
    admin: dict[str, Any] | None
    via: str | None


@dataclass(frozen=True)
class RipplingCase:
    name: str
    query_id: str | None
    poison: str
    db_path: str | None
    tenant_id: str
    steps: list[RipplingCaseStep]


def _load_case_step(raw: dict[str, Any]) -> RipplingCaseStep:
    if isinstance(raw.get("admin"), dict):
        return RipplingCaseStep(
            tool=None,
            args={},
            expect_status=None,
            expect_blocked=None,
            expect_violations_contain=[],
            expect_output_contains=[],
            expect_output_not_contains=[],
            attach_commit_token=False,
            issue_commit_token_as=None,
            commit_token_ref=None,
            admin=dict(raw["admin"]),
            via=None,
        )
    expect = raw.get("expect", {}) if isinstance(raw.get("expect"), dict) else {}
    return RipplingCaseStep(
        tool=str(raw["tool"]),
        args=dict(raw.get("args", {})),
        expect_status=str(expect.get("status", "ok")),
        expect_blocked=bool(
            expect.get("blocked", expect.get("status") in {"blocked", "step_up_required"})
        ),
        expect_violations_contain=[str(s) for s in expect.get("violations_contain", [])],
        expect_output_contains=[str(s) for s in expect.get("output_contains", [])],
        expect_output_not_contains=[str(s) for s in expect.get("output_not_contains", [])],
        attach_commit_token=bool(raw.get("attach_commit_token", False)),
        issue_commit_token_as=(
            str(raw["issue_commit_token_as"]) if raw.get("issue_commit_token_as") else None
        ),
        commit_token_ref=str(raw["commit_token_ref"]) if raw.get("commit_token_ref") else None,
        admin=None,
        via=str(raw["via"]) if raw.get("via") else None,
    )


def _load_case(raw: dict[str, Any]) -> RipplingCase:
    name = str(raw.get("name") or "unnamed")
    query_id = raw.get("query_id")
    poison = str(raw.get("poison", "honest"))
    db_path = raw.get("db_path", DEFAULT_DB)
    tenant_id = str(raw.get("tenant_id", "ten_acme"))
    steps_raw = raw.get("steps", [])
    if not isinstance(steps_raw, list) or not steps_raw:
        raise ValueError(f"case {name!r} has no steps")
    steps = [_load_case_step(dict(step)) for step in steps_raw if isinstance(step, dict)]
    return RipplingCase(
        name=name,
        query_id=str(query_id) if query_id is not None else None,
        poison=poison,
        db_path=str(db_path) if db_path else None,
        tenant_id=tenant_id,
        steps=steps,
    )


def _case_paths() -> list[Path]:
    paths: list[Path] = []
    env = os.getenv("AGENT_RECEIPTS_RIPPLING_CASES")
    if env:
        for item in env.split(","):
            item = item.strip()
            if item:
                paths.append(Path(item))
    if DEFAULT_CASES.is_file():
        paths.append(DEFAULT_CASES)
    return paths


def _load_cases() -> list[RipplingCase]:
    cases: list[RipplingCase] = []
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


def _resolve_db_path(db_path: str | None) -> str | None:
    if not db_path:
        return None
    path = Path(db_path)
    if not path.is_absolute():
        path = FIXTURE_MODULE_DIR / path
    if not path.exists():
        builder = FIXTURE_MODULE_DIR / "fixtures" / "build_mock_rippling_db.py"
        if path.name == "mock_rippling.db" and builder.is_file():
            subprocess.run([sys.executable, str(builder)], cwd=str(ROOT), check=True)
    if not path.exists():
        raise FileNotFoundError(path)
    return str(path)


CASES = _load_cases()


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_rippling_case(case: RipplingCase):
    _agent, gateways = build_fixture_agent(
        mode="shadow",
        audit_db=":memory:",
        poison=case.poison,
        db_path=_resolve_db_path(case.db_path),
        tenant_id=case.tenant_id,
        query_id=case.query_id,
    )
    # Commit tokens are only ever issued/verified against the action gateway --
    # that's the only role with commit_signing_key + sandbox_governor configured
    # (read/rag tool calls never require one). See build_fixture_agent().
    action_gw = gateways["action"]

    commit_tokens: dict[str, dict[str, Any]] = {}

    for step in case.steps:
        if step.admin is not None:
            if "set_query_id" in step.admin:
                for gw in gateways.values():
                    gw.set_query_id(step.admin.get("set_query_id"))
            if step.admin.get("revoke_permits"):
                action_gw.revoke_permits(bump_authority_version=False)
            continue

        assert step.tool is not None
        # `via` overrides the tool's home-role gateway -- used to simulate a
        # supervisor routing/confused-deputy failure (e.g. asking the read
        # gateway to call an action tool it never registered).
        gw = gateways[step.via] if step.via else gateway_for_tool(gateways, step.tool)
        args = dict(step.args)
        if step.issue_commit_token_as:
            commit_tokens[step.issue_commit_token_as] = action_gw.issue_commit_token(
                step.tool, args
            )
        if step.commit_token_ref:
            args["_commit_token"] = commit_tokens[step.commit_token_ref]
        elif step.attach_commit_token:
            args["_commit_token"] = action_gw.issue_commit_token(step.tool, args)

        result = gw.call_tool(step.tool, args)
        assert step.expect_status is not None
        assert step.expect_blocked is not None
        assert result.output["status"] == step.expect_status, (
            f"{case.name}: expected status {step.expect_status!r}, got {result.output}"
        )
        assert result.blocked is step.expect_blocked, (
            f"{case.name}: expected blocked={step.expect_blocked}, "
            f"violations={result.policy_violations}"
        )
        for needle in step.expect_violations_contain:
            assert any(needle in v for v in result.policy_violations), (
                f"{case.name}: expected a violation containing {needle!r}, "
                f"got {result.policy_violations}"
            )
        output_blob = json.dumps(result.output, sort_keys=True, default=str).lower()
        for needle in step.expect_output_contains:
            assert needle.lower() in output_blob, (
                f"{case.name}: expected output to contain {needle!r}, got {result.output}"
            )
        for needle in step.expect_output_not_contains:
            assert needle.lower() not in output_blob, (
                f"{case.name}: expected output not to contain {needle!r}, got {result.output}"
            )


@pytest.mark.skipif(CASES, reason="Rippling redteaming backlog already loaded from fixtures/env")
def test_rippling_deepagents_redteaming_backlog_not_configured():
    """
    This test exists to document the harness when no case files are present.

    Provide a JSONL path via `AGENT_RECEIPTS_RIPPLING_CASES` or add
    `python/tests/fixtures/rippling_deepagents_redteaming_backlog.jsonl`.
    """
    pytest.skip("No Rippling cases configured")
