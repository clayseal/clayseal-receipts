from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.adapters.mcp_tools import extract_planned_tools, normalize_tool_name
from harness.adapters.registry import iter_cases
from harness.config import AdapterOptions

CORPUS_TASKS = (
    Path(__file__).resolve().parents[1]
    / "corpus"
    / "mcp_bench"
    / "tasks"
    / "mcpbench_tasks_single_runner_format.json"
)


def test_normalize_tool_name_kebab_to_snake():
    assert normalize_tool_name("search-models") == "search_models"


def test_extract_server_colon_tool():
    tools = extract_planned_tools("Call Wikipedia:search_wikipedia with query=test")
    assert "search_wikipedia" in tools


def test_extract_dependency_tools_without_server_prefix():
    desc = "Call get_api_health. Then get_steam_trending."
    dep = "get_steam_trending → get_steam_top_sellers → get_steam_most_played"
    tools = extract_planned_tools(desc, dep)
    assert "get_api_health" in tools
    assert "get_steam_trending" in tools
    assert "get_steam_top_sellers" in tools


@pytest.mark.skipif(not CORPUS_TASKS.is_file(), reason="MCP-Bench corpus not downloaded")
def test_all_single_runner_tasks_yield_tools():
    payload = json.loads(CORPUS_TASKS.read_text())
    for block in payload.get("server_tasks", []):
        for task in block.get("tasks", []):
            tools = extract_planned_tools(
                str(task.get("task_description") or ""),
                str(task.get("dependency_analysis") or ""),
            )
            assert tools, task.get("task_id")


@pytest.mark.skipif(not CORPUS_TASKS.is_file(), reason="MCP-Bench corpus not downloaded")
def test_mcp_bench_adapter_yields_fifty_six_cases():
    cases = list(iter_cases("mcp_bench_tasks", limit=100))
    assert len(cases) == 56


@pytest.mark.skipif(
    not (Path(__file__).resolve().parents[1] / "corpus" / "swe_agent_trajectories").is_dir(),
    reason="SWE corpus not downloaded",
)
def test_swe_adapter_deduplicates_instance_ids():
    cases = list(iter_cases("swe_session", limit=50))
    if not cases:
        pytest.skip("no SWE cases")
    ids = [case.metadata.get("instance_id") or case.case_id for case in cases]
    assert len(ids) == len(set(ids))
