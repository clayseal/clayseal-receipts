from __future__ import annotations

import json
from typing import Iterator

from agentauth.receipts import Policy, ReceiptedMcpGateway

from harness.adapters.mcp_tools import extract_planned_tools
from harness.paths import CORPUS
from harness.types import BenchmarkCase

TASKS_PATH = CORPUS / "mcp_bench" / "tasks" / "mcpbench_tasks_single_runner_format.json"


def iter_cases(*, limit: int | None = None, options: AdapterOptions | None = None) -> Iterator[BenchmarkCase]:
    if not TASKS_PATH.is_file():
        return

    payload = json.loads(TASKS_PATH.read_text())
    server_tasks = payload.get("server_tasks") or []
    count = 0
    for block in server_tasks:
        server_name = str(block.get("server_name", "mcp-bench"))
        for task in block.get("tasks") or []:
            if limit is not None and count >= limit:
                return
            case_id = str(task.get("task_id", f"mcpbench_{count}"))
            description = str(task.get("task_description") or "")
            dependency = str(task.get("dependency_analysis") or "")
            tools = extract_planned_tools(description, dependency)
            if not tools:
                continue
            count += 1

            policy = Policy.from_dict(
                {
                    "version": 1,
                    "name": f"mcpbench_{case_id}",
                    "tier": "tool_trace",
                    "capability": "operator_attested",
                    "allowed_tools": {"tools": tools},
                    "output_schema": {"fields": ["status", "tool"], "required": []},
                }
            )

            def make_execute(tid: str, srv: str, tool_list: list[str], pol: Policy):
                def execute(_agent):
                    agent = _agent
                    agent.policy = pol
                    agent.model = lambda inp: {"decision": "approve", "fraud_score": 0.0}
                    gateway = ReceiptedMcpGateway(agent, server_name=srv)
                    for tool in tool_list:
                        gateway.register_tool(
                            tool,
                            lambda args, t=tool: {"planned": True, "tool": t, "args": args},
                        )

                    last = None
                    for tool in tool_list:
                        last = gateway.call_tool(tool, {"benchmark": True, "task_id": tid})

                    ok = last is not None and not last.blocked
                    return {
                        "ok": ok,
                        "run_result": last,
                        "require_audit": True,
                        "metadata": {
                            "task_id": tid,
                            "tools": tool_list,
                            "tool_count": len(tool_list),
                        },
                        "export_context": {"benchmark_suite": "mcp_bench_tasks", "task_id": tid},
                    }

                return execute

            yield BenchmarkCase(
                suite="mcp_bench_tasks",
                case_id=case_id,
                description=description[:120],
                metadata={"server": server_name, "tools": tools},
                execute=make_execute(case_id, server_name, tools, policy),
            )
