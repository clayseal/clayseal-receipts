from __future__ import annotations

from agentauth.receipts import AgentWrapper, Policy, ReceiptedMcpGateway
from agentauth.core.runtime import AuthorityContext


def test_gateway_blocks_out_of_scope_repo_resource_ref() -> None:
    policy = Policy.from_dict(
        {
            "version": 1,
            "name": "scope-test",
            "tier": "structural",
            "capability": "fully_proven",
            "allowed_tools": {"tools": ["write_file"]},
        }
    )
    agent = AgentWrapper(model=lambda _inp: {"ok": True}, policy=policy, mode="shadow")

    def resolve_repo_ref(args: dict[str, object]) -> str | None:
        path = args.get("path")
        if not isinstance(path, str) or not path.strip():
            return None
        return f"repo_write://{path.strip().lstrip('/')}"

    gw = ReceiptedMcpGateway(
        agent,
        resource_ref_resolvers={"write_file": resolve_repo_ref},
    )
    gw.set_authority(
        AuthorityContext(
            authority_id="a",
            authority_version=1,
            resource_scope=["repo_write://allowed/**"],
        )
    )

    def _handler(_args: dict[str, object]) -> object:
        raise AssertionError("handler should not execute when scope blocks")

    gw.register_tool("write_file", _handler)

    result = gw.call_tool("write_file", {"path": "other/file.txt", "content": "hi"})
    assert result.blocked is True
    assert result.output["status"] in {"blocked", "step_up_required"}
    assert any("resource_scope" in v for v in result.policy_violations)


def test_gateway_allows_read_but_blocks_write_when_only_read_scope_present() -> None:
    policy = Policy.from_dict(
        {
            "version": 1,
            "name": "scope-test",
            "tier": "structural",
            "capability": "fully_proven",
            "allowed_tools": {"tools": ["read_file", "write_file"]},
        }
    )
    agent = AgentWrapper(model=lambda _inp: {"ok": True}, policy=policy, mode="shadow")

    def resolve_read(args: dict[str, object]) -> str | None:
        path = args.get("path")
        if not isinstance(path, str) or not path.strip():
            return None
        return f"repo_read://{path.strip().lstrip('/')}"

    def resolve_write(args: dict[str, object]) -> str | None:
        path = args.get("path")
        if not isinstance(path, str) or not path.strip():
            return None
        return f"repo_write://{path.strip().lstrip('/')}"

    gw = ReceiptedMcpGateway(
        agent,
        resource_ref_resolvers={
            "read_file": resolve_read,
            "write_file": resolve_write,
        },
    )
    gw.set_authority(
        AuthorityContext(
            authority_id="a",
            authority_version=1,
            resource_scope=["repo_read://allowed/**"],
        )
    )

    gw.register_tool("read_file", lambda _args: {"ok": True})
    gw.register_tool("write_file", lambda _args: {"ok": True})

    ok_read = gw.call_tool("read_file", {"path": "allowed/x.txt"})
    assert ok_read.blocked is False
    blocked_write = gw.call_tool("write_file", {"path": "allowed/x.txt", "content": "hi"})
    assert blocked_write.blocked is True


def test_gateway_blocks_when_query_id_does_not_match_lease_query_id() -> None:
    policy = Policy.from_dict(
        {
            "version": 1,
            "name": "scope-test",
            "tier": "structural",
            "capability": "fully_proven",
            "allowed_tools": {"tools": ["noop"]},
        }
    )
    agent = AgentWrapper(model=lambda _inp: {"ok": True}, policy=policy, mode="shadow")
    gw = ReceiptedMcpGateway(agent, query_id="q-2")
    gw.register_tool("noop", lambda _args: {"ok": True})
    gw.set_authority(
        AuthorityContext(
            authority_id="a",
            authority_version=1,
            lease_query_id="q-1",
        )
    )

    result = gw.call_tool("noop", {})
    assert result.blocked is True
    assert any("lease_query_id" in v for v in result.policy_violations)
