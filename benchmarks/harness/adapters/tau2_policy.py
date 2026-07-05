from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from agentauth.receipts import ReceiptedMcpGateway

from harness.agent_setup import apply_agent_policy
from harness.config import AdapterOptions
from harness.paths import CORPUS
from harness.pipeline import mcp_policy, tau2_policy
from harness.policy_modes import tight_mcp_policy
from harness.types import BenchmarkCase

TAU2_ROOT = CORPUS / "tau2_bench" / "data" / "tau2" / "domains"

_MOCK_STATE: dict[str, Any] = {"tasks": {}}


def _mock_handler(tool_name: str):
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "create_task":
            task_id = f"task_{len(_MOCK_STATE['tasks']) + 1}"
            _MOCK_STATE["tasks"][task_id] = {
                "user_id": args.get("user_id"),
                "title": args.get("title"),
                "status": "pending",
            }
            return {"task_id": task_id, "status": "created"}
        if tool_name == "list_tasks":
            user_id = args.get("user_id")
            tasks = [
                item
                for item in _MOCK_STATE["tasks"].values()
                if not user_id or item.get("user_id") == user_id
            ]
            return {"tasks": tasks}
        if tool_name == "update_task":
            task_id = str(args.get("task_id", ""))
            task = _MOCK_STATE["tasks"].get(task_id)
            if not task:
                return {"error": "not_found"}
            task.update({k: v for k, v in args.items() if k != "task_id"})
            return {"task_id": task_id, "status": "updated"}
        if tool_name == "delete_task":
            task_id = str(args.get("task_id", ""))
            _MOCK_STATE["tasks"].pop(task_id, None)
            return {"task_id": task_id, "status": "deleted"}
        if tool_name == "get_task":
            task_id = str(args.get("task_id", ""))
            task = _MOCK_STATE["tasks"].get(task_id)
            return {"task": task} if task else {"error": "not_found"}
        if tool_name == "update_task_status":
            task_id = str(args.get("task_id", ""))
            task = _MOCK_STATE["tasks"].get(task_id, {})
            task["status"] = args.get("status", "updated")
            _MOCK_STATE["tasks"][task_id] = task
            return {"task_id": task_id, "status": task.get("status")}
        if tool_name == "transfer_to_human_agents":
            return {"transferred": True, **args}
        if tool_name == "assign_task":
            return {"status": "assigned", **args}
        return {"status": "ok", "tool": tool_name, "args": args}

    return handler


def _generic_handler(tool_name: str):
    def handler(args: dict[str, Any]) -> dict[str, Any]:
        return {"status": "ok", "tool": tool_name, "args": args}

    return handler


def _task_file_for_domain(domain: str, *, telecom_tasks: str = "full") -> str:
    if domain == "telecom" and telecom_tasks == "small":
        return "tasks_small.json"
    return "tasks.json"


def _load_domain_tasks(domain: str, *, telecom_tasks: str = "full") -> list[dict[str, Any]]:
    path = TAU2_ROOT / domain / _task_file_for_domain(domain, telecom_tasks=telecom_tasks)
    if not path.is_file():
        return []
    return json.loads(path.read_text())


def _tools_in_action_order(action_list: list[dict[str, Any]]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for action in action_list:
        name = str(action["name"])
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def iter_cases(*, limit: int | None = None, options: AdapterOptions | None = None) -> Iterator[BenchmarkCase]:
    opts = options or AdapterOptions()
    domains = opts.tau2_domains or ["mock"]
    policy_mode = opts.policy_mode
    total_yielded = 0

    telecom_tasks = opts.tau2_telecom_tasks or "full"

    for domain in domains:
        tasks = _load_domain_tasks(domain, telecom_tasks=telecom_tasks)
        if not tasks:
            continue

        all_tool_names: set[str] = set()
        for task in tasks:
            for action in (task.get("evaluation_criteria") or {}).get("actions") or []:
                all_tool_names.add(str(action["name"]))

        handler_for = _mock_handler if domain == "mock" else _generic_handler

        for task in tasks:
            if limit is not None and total_yielded >= limit:
                return
            task_id = str(task["id"])
            actions = list((task.get("evaluation_criteria") or {}).get("actions") or [])
            if not actions:
                continue

            case_id = f"tau2_{domain}_{task_id}"
            tool_names = set(all_tool_names)
            action_tools = _tools_in_action_order(actions)

            def make_execute(
                domain_name: str,
                tid: str,
                action_list: list[dict[str, Any]],
                tools: set[str],
                ordered_action_tools: list[str],
                mode: str,
            ):
                def execute(agent):
                    if domain_name == "mock":
                        _MOCK_STATE["tasks"].clear()
                    if mode == "tight" and ordered_action_tools:
                        pol = tight_mcp_policy(
                            f"tau2_tight_{domain_name}_{tid}",
                            ordered_action_tools[:1],
                        )
                        allowed_set = set(ordered_action_tools[:1])
                    else:
                        pol = tau2_policy() if domain_name == "mock" else mcp_policy()
                        allowed_set = tools
                    apply_agent_policy(agent, pol)
                    agent.model = lambda inp: {"decision": "approve", "fraud_score": 0.0}
                    gateway = ReceiptedMcpGateway(agent, server_name=f"tau2-{domain_name}")
                    for name in tools:
                        gateway.register_tool(name, handler_for(name))

                    last = None
                    blocked = 0
                    allowed = 0
                    for action in action_list:
                        name = str(action["name"])
                        args = dict(action.get("arguments") or {})
                        last = gateway.call_tool(name, args)
                        if last.blocked:
                            blocked += 1
                        else:
                            allowed += 1

                    if mode == "tight":
                        expected_blocks = sum(
                            1 for action in action_list if str(action["name"]) not in allowed_set
                        )
                        ok = allowed > 0 and blocked >= expected_blocks
                    else:
                        ok = blocked == 0 and last is not None and last.policy_satisfied
                    return {
                        "ok": ok,
                        "run_result": last,
                        "require_audit": True,
                        "metadata": {
                            "domain": domain_name,
                            "tau2_task": tid,
                            "actions_replayed": len(action_list),
                            "blocked": blocked,
                            "allowed": allowed,
                            "policy_mode": mode,
                            "allowed_tools": list(allowed_set) if mode == "tight" else None,
                        },
                        "export_context": {
                            "benchmark_suite": "tau2_policy",
                            "domain": domain_name,
                            "tau2_task": tid,
                        },
                    }

                return execute

            yield BenchmarkCase(
                suite="tau2_policy",
                case_id=case_id,
                description=str((task.get("description") or {}).get("purpose", case_id)),
                metadata={
                    "domain": domain,
                    "actions": len(actions),
                    "policy_mode": policy_mode,
                    "action_tool_count": len(action_tools),
                },
                execute=make_execute(
                    domain,
                    task_id,
                    actions,
                    tool_names,
                    action_tools,
                    policy_mode,
                ),
            )
            total_yielded += 1
