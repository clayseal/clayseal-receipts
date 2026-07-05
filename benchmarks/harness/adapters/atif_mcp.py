from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from agentauth.receipts import ReceiptedMcpGateway

from harness.agent_setup import apply_agent_policy
from harness.config import AdapterOptions
from harness.paths import CORPUS
from harness.pipeline import mcp_policy
from harness.policy_modes import tight_mcp_policy
from harness.types import BenchmarkCase

ATIF_ROOT = CORPUS / "mcp_agent_trajectory_benchmark"


def _load_trajectories(limit: int | None) -> list[tuple[str, dict[str, Any]]]:
    if not ATIF_ROOT.is_dir():
        return []
    paths = sorted(ATIF_ROOT.glob("*/trajectory.json"))
    if limit is not None:
        paths = paths[:limit]
    loaded: list[tuple[str, dict[str, Any]]] = []
    for path in paths:
        data = json.loads(path.read_text())
        loaded.append((path.parent.name, data))
    return loaded


def _observation_map(step: dict[str, Any]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    observation = step.get("observation") or {}
    for item in observation.get("results") or []:
        call_id = item.get("source_call_id")
        if call_id:
            mapping[str(call_id)] = str(item.get("content", ""))
    return mapping


def _all_tools(steps: list[list[dict[str, Any]]]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for group in steps:
        for call in group:
            fn = str(call["function_name"])
            if fn not in seen:
                seen.add(fn)
                names.append(fn)
    return names


def iter_cases(*, limit: int | None = None, options: AdapterOptions | None = None) -> Iterator[BenchmarkCase]:
    opts = options or AdapterOptions()
    policy_mode = opts.policy_mode
    for agent_name, trajectory in _load_trajectories(limit):
        session_id = str(trajectory.get("session_id") or agent_name)
        tool_steps: list[list[dict[str, Any]]] = []
        for step in trajectory.get("steps") or []:
            calls = step.get("tool_calls") or []
            if calls:
                tool_steps.append(calls)

        if not tool_steps:
            continue

        all_tools = _all_tools(tool_steps)
        case_id = f"atif_{agent_name}"

        def make_execute(
            name: str,
            steps: list[list[dict[str, Any]]],
            sess: str,
            traj: dict[str, Any],
            tools: list[str],
            mode: str,
        ):
            def execute(agent):
                if mode == "tight" and tools:
                    policy = tight_mcp_policy(f"atif_tight_{name}", tools[:1])
                else:
                    policy = mcp_policy()
                apply_agent_policy(agent, policy)
                agent.model = lambda inp: {"decision": "approve", "fraud_score": 0.0}
                gateway = ReceiptedMcpGateway(agent, server_name=name)

                handlers: dict[str, Any] = {}

                def register_from_step(step: dict[str, Any], call: dict[str, Any]) -> None:
                    fn = str(call["function_name"])
                    if fn in handlers:
                        return
                    obs = _observation_map(step)
                    call_id = str(call.get("tool_call_id", ""))

                    def handler(args, _fn=fn, _content=obs.get(call_id, "{}")):
                        return {"replay": True, "tool": _fn, "content": _content, "args": args}

                    handlers[fn] = handler
                    gateway.register_tool(fn, handler)

                for step in traj.get("steps") or []:
                    for call in step.get("tool_calls") or []:
                        register_from_step(step, call)

                last_result = None
                blocked = 0
                allowed = 0
                for call_group in steps:
                    for call in call_group:
                        fn = str(call["function_name"])
                        args = dict(call.get("arguments") or {})
                        last_result = gateway.call_tool(fn, args)
                        if last_result.blocked:
                            blocked += 1
                        else:
                            allowed += 1

                if mode == "tight":
                    allowed_set = set(tools[:1])
                    expected_blocks = sum(
                        1
                        for group in steps
                        for call in group
                        if str(call["function_name"]) not in allowed_set
                    )
                    ok = allowed > 0 and blocked >= expected_blocks
                else:
                    ok = allowed > 0 and blocked == 0
                return {
                    "ok": ok,
                    "run_result": last_result,
                    "require_audit": True,
                    "metadata": {
                        "agent": name,
                        "session_id": sess,
                        "tool_calls_replayed": allowed + blocked,
                        "tool_calls_blocked": blocked,
                        "policy_mode": mode,
                        "allowed_tools": tools[:1] if mode == "tight" else None,
                        "all_tools": tools,
                    },
                    "export_context": {"benchmark_suite": "atif_mcp", "session_id": sess},
                }

            return execute

        yield BenchmarkCase(
            suite="atif_mcp",
            case_id=case_id,
            description=f"Replay ATIF tool trace for {agent_name}",
            metadata={
                "agent": agent_name,
                "session_id": session_id,
                "tool_steps": len(tool_steps),
                "policy_mode": policy_mode,
                "tool_count": len(all_tools),
            },
            execute=make_execute(agent_name, tool_steps, session_id, trajectory, all_tools, policy_mode),
        )
