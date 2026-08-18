import json
from pathlib import Path

from agentauth.receipts import AgentWrapper, Policy, ReceiptedMcpGateway
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.policy_engine import YamlPolicyEngine
from agentauth.receipts.proof import DecisionOutcome
from agentauth.core.runtime import ActionDescriptor, AuthorityContext, ExecutionContext
from agentauth.capabilities.task_scope import (
    compile_human_authorization,
    compile_task_scope,
    resource_scope_entries,
)

ROOT = Path(__file__).resolve().parents[2]
AUTH_TEMPLATE = ROOT / "python" / "tests" / "fixtures" / "human-authorization.template.json"


def _tool_policy() -> Policy:
    return Policy.from_dict(
        {
            "version": 1,
            "name": "task-scoped-tools",
            "tier": "tool_trace",
            "capability": "operator_attested",
            "allowed_tools": {"tools": ["write_file", "read_file"]},
            "output_schema": {"fields": ["status", "tool"], "required": []},
        }
    )


def test_authorization_template_round_trips():
    document = json.loads(AUTH_TEMPLATE.read_text())
    scope = compile_human_authorization(document)
    assert scope.mandate_id == "issue-parser-normalize"
    assert scope.source_schema == "agentauth.human_authorization.v1"
    assert "swe_triage/parser.py" in scope.allowed_paths
    assert "swe_triage/auth.py" in scope.denied_paths
    assert scope.task_summary is not None

    entries = resource_scope_entries(scope)
    assert "file:swe_triage/parser.py" in entries
    assert "file:tests/test_parser.py" in entries


def test_policy_engine_denies_out_of_scope_file_path():
    document = json.loads(AUTH_TEMPLATE.read_text())
    scope = compile_task_scope(document)
    policy = _tool_policy()
    engine = YamlPolicyEngine(policy)
    authority = AuthorityContext(
        authority_id="grant-task",
        resource_scope=resource_scope_entries(scope),
    )
    context = ExecutionContext(
        action=ActionDescriptor(
            action_name="mcp.tools/call/write_file",
            resource_ref="file:swe_triage/auth.py",
        ),
        input={"path": "swe_triage/auth.py"},
        authority=authority,
        authorization={"task_scope": scope.to_dict()},
    )

    result = engine.evaluate({"status": "ok"}, execution_context=context)

    assert result.policy_satisfied is False
    assert any("denied path" in item for item in result.violations)


def test_policy_engine_allows_in_scope_file_path():
    document = json.loads(AUTH_TEMPLATE.read_text())
    scope = compile_task_scope(document)
    policy = _tool_policy()
    engine = YamlPolicyEngine(policy)
    authority = AuthorityContext(
        authority_id="grant-task",
        resource_scope=resource_scope_entries(scope),
    )
    context = ExecutionContext(
        action=ActionDescriptor(
            action_name="mcp.tools/call/write_file",
            resource_ref="file:swe_triage/parser.py",
        ),
        input={"path": "swe_triage/parser.py"},
        authority=authority,
        authorization={"task_scope": scope.to_dict()},
    )

    result = engine.evaluate({"status": "ok"}, execution_context=context)

    assert result.policy_satisfied is True
    assert result.outcome == DecisionOutcome.ALLOW


def test_agent_wrapper_task_mandate_blocks_denied_path_in_bounded_auto():
    document = json.loads(AUTH_TEMPLATE.read_text())
    policy = _tool_policy()
    cert = dev_certificate(policy.commitment(), scope=["write_file", "read_file"])
    agent = AgentWrapper(
        model=lambda _inp: {"status": "ok"},
        policy=policy,
        certificate=cert,
        mode="bounded_auto",
        audit_db=":memory:",
        task_mandate=document,
    )
    gw = ReceiptedMcpGateway(agent, server_name="repo", session_id="task-scope")
    gw.register_tool("write_file", lambda _args: {"ok": True})

    blocked = gw.call_tool("write_file", {"path": "swe_triage/auth.py"})
    allowed = gw.call_tool("write_file", {"path": "swe_triage/parser.py"})

    assert blocked.blocked is True
    assert blocked.decision.outcome == DecisionOutcome.DENY
    assert any("denied path" in item for item in blocked.policy_violations)

    assert allowed.blocked is False
    assert allowed.decision.outcome == DecisionOutcome.ALLOW
