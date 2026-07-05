from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

from harness.config import AdapterOptions
from harness.paths import CORPUS
from harness.pipeline import mcp_policy
from harness.types import BenchmarkCase

SWE_DATA = CORPUS / "swe_agent_trajectories" / "data"


def shard_paths() -> list[Path]:
    if not SWE_DATA.is_dir():
        return []
    return sorted(SWE_DATA.glob("train-*.parquet"))


def shard_count() -> int:
    return len(shard_paths())


def _parquet_rows(
    limit: int | None,
    shards: list[int],
) -> list[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq
    except ImportError:
        return []

    paths = shard_paths()
    if not paths:
        return []

    rows: list[dict[str, Any]] = []
    seen_instances: set[str] = set()
    for shard in shards:
        if shard < 0 or shard >= len(paths):
            continue
        parquet_path = paths[shard]
        table = pq.read_table(
            parquet_path, columns=["instance_id", "trajectory", "exit_status"]
        )
        for index in range(table.num_rows):
            instance_id = str(table["instance_id"][index].as_py())
            if instance_id in seen_instances:
                continue
            seen_instances.add(instance_id)
            rows.append(
                {
                    "instance_id": instance_id,
                    "trajectory": table["trajectory"][index].as_py(),
                    "exit_status": table["exit_status"][index].as_py(),
                    "shard": shard,
                }
            )
            if limit is not None and len(rows) >= limit:
                return rows
    return rows


def iter_cases(*, limit: int | None = None, options: AdapterOptions | None = None) -> Iterator[BenchmarkCase]:
    opts = options or AdapterOptions()
    max_cases = limit if limit is not None else opts.limit
    policy = mcp_policy()
    rows = _parquet_rows(max_cases, shards=opts.swe_shards)
    if not rows:
        return

    for row in rows:
        instance_id = str(row["instance_id"])
        trajectory = list(row.get("trajectory") or [])
        tool_like = [
            msg
            for msg in trajectory
            if str(msg.get("role", "")).lower() in {"assistant", "ai", "user", "tool"}
        ][:12]
        if not tool_like:
            continue

        case_id = f"swe_{instance_id}"

        def make_execute(iid: str, messages: list[dict[str, Any]], row_meta: dict[str, Any]):
            def execute(agent):
                last = None
                for index, msg in enumerate(messages):
                    role = str(msg.get("role", "assistant"))
                    text = str(msg.get("text") or "")[:500]
                    last = agent.record(
                        action=f"swe.{role}",
                        context={
                            "input": {"instance_id": iid, "step": index, "role": role},
                            "session_id": f"swe-{iid}",
                        },
                        output={
                            "status": "logged",
                            "role": role,
                            "text_preview": text,
                            "fraud_score": 0.0,
                            "decision": "approve",
                        },
                        session_id=f"swe-{iid}",
                        check_policy_output=True,
                    )
                ok = last is not None and last.policy_satisfied
                return {
                    "ok": ok,
                    "run_result": last,
                    "require_audit": True,
                    "metadata": {
                        "instance_id": iid,
                        "steps_logged": len(messages),
                        "exit_status": row_meta.get("exit_status"),
                        "shard": row_meta.get("shard", 0),
                    },
                    "export_context": {"benchmark_suite": "swe_session", "instance_id": iid},
                }

            return execute

        yield BenchmarkCase(
            suite="swe_session",
            case_id=case_id,
            description=f"SWE trajectory session {instance_id}",
            metadata={
                "steps": len(tool_like),
                "exit_status": row.get("exit_status"),
                "shard": row.get("shard", 0),
            },
            execute=make_execute(instance_id, tool_like, row),
        )
