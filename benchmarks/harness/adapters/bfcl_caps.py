from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from agentauth.receipts import ReceiptedMcpGateway

from harness.config import AdapterOptions
from harness.paths import CORPUS
from harness.pipeline import bfcl_policy
from harness.types import BenchmarkCase

BFCL_DIR = (
    CORPUS
    / "gorilla"
    / "berkeley-function-call-leaderboard"
    / "bfcl_eval"
    / "data"
)
QUESTIONS = BFCL_DIR / "BFCL_v4_simple_python.json"
ANSWERS = BFCL_DIR / "possible_answer" / "BFCL_v4_simple_python.json"


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _ground_truth_args(entry: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    gt_list = entry.get("ground_truth") or []
    if not gt_list:
        raise ValueError("missing ground_truth")
    tool_map = gt_list[0]
    tool_name = next(iter(tool_map))
    raw_args = tool_map[tool_name]
    args: dict[str, Any] = {}
    for key, values in raw_args.items():
        if not values:
            continue
        value = values[0]
        if value != "":
            args[key] = value
    return tool_name, args


def iter_cases(*, limit: int | None = None, options: AdapterOptions | None = None) -> Iterator[BenchmarkCase]:
    if not QUESTIONS.is_file() or not ANSWERS.is_file():
        return

    answers = {row["id"]: row for row in _load_jsonl(ANSWERS)}
    questions = _load_jsonl(QUESTIONS)
    if limit is not None:
        questions = questions[:limit]

    for question in questions:
        case_id = str(question["id"])
        answer = answers.get(case_id)
        if not answer:
            continue
        tool_name, args = _ground_truth_args(answer)
        policy = bfcl_policy(tool_name)

        def make_execute(tname: str, targs: dict[str, Any], pol):
            def execute(_agent):
                agent = _agent
                agent.policy = pol
                agent.model = lambda inp: {"decision": "approve", "fraud_score": 0.0}
                gateway = ReceiptedMcpGateway(agent, server_name="bfcl")
                gateway.register_tool(tname, lambda a: {"ok": True, "args": a})

                allowed = gateway.call_tool(tname, targs)
                decoy = gateway.call_tool("decoy_tool", {"x": 1})

                ok = (
                    not allowed.blocked
                    and allowed.policy_satisfied
                    and decoy.blocked
                    and any("allowlist" in v for v in decoy.policy_violations)
                )
                return {
                    "ok": ok,
                    "run_result": allowed,
                    "require_audit": True,
                    "metadata": {
                        "allowed_tool": tname,
                        "decoy_blocked": decoy.blocked,
                    },
                }

            return execute

        yield BenchmarkCase(
            suite="bfcl_caps",
            case_id=case_id,
            description=f"BFCL cap enforcement for {tool_name}",
            metadata={"tool": tool_name, "args": args},
            execute=make_execute(tool_name, args, policy),
        )
