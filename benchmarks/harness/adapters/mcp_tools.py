from __future__ import annotations

import re

_SERVER_TOOL = re.compile(r"([A-Za-z][A-Za-z0-9 _-]*?):([A-Za-z0-9_-]+)")
_CALL_TOOL = re.compile(r"\b[Cc]all\s+(?:[\w ]+?:)?([A-Za-z0-9_-]+)")
_DEP_TOOL = re.compile(r"\b([a-z][a-z0-9]*(?:[-_][a-z0-9_-]+)+)\b")
_CAMEL_TOOL = re.compile(r"\b(get[A-Z][a-zA-Z]+|list[A-Z][a-zA-Z]+|search[A-Z][a-zA-Z]+)\b")

_STOPWORDS = frozenset(
    {
        "e.g",
        "i.e",
        "step",
        "steps",
        "json",
        "null",
        "true",
        "false",
        "api",
        "ids",
        "limit",
        "query",
        "title",
        "name",
        "type",
        "data",
        "output",
        "input",
        "id",
        "max",
        "min",
        "top",
        "all",
        "new",
        "old",
        "key",
        "keys",
        "value",
        "values",
        "decision",
        "point",
        "branch",
        "parallel",
        "sequential",
        "workflow",
        "chain",
        "cross-validation",
        "cross-server",
        "scenario-based",
        "inherent",
        "dependencies",
    }
)

_TOOL_PREFIXES = (
    "get_",
    "search_",
    "list_",
    "convert_",
    "call_",
    "article_",
    "variant_",
    "trial_",
    "think",
    "nixos_",
    "home_manager_",
    "darwin_",
    "summarize_",
    "extract_",
    "download_",
    "read_",
    "openfda_",
    "nci_",
    "disease_",
    "gene_",
    "drug_",
    "server_",
    "i_ching",
    "bibliomantic_",
)


def normalize_tool_name(name: str) -> str:
    cleaned = name.strip().rstrip("*.,;:")
    if "-" in cleaned and "_" not in cleaned:
        return cleaned.replace("-", "_")
    return cleaned


def _looks_like_tool(name: str) -> bool:
    low = name.lower()
    if low in _STOPWORDS:
        return False
    if low.endswith("_based") or low.endswith("_point"):
        return False
    return any(low.startswith(prefix) for prefix in _TOOL_PREFIXES) or "_" in name or "-" in name


def extract_planned_tools(task_description: str, dependency_analysis: str = "") -> list[str]:
    """Extract MCP tool names from MCP-Bench task text."""
    seen: set[str] = set()
    tools: list[str] = []
    text = f"{task_description}\n{dependency_analysis or ''}"

    def add(raw: str) -> None:
        name = normalize_tool_name(raw)
        if len(name) < 3 or not _looks_like_tool(name):
            return
        if name not in seen:
            seen.add(name)
            tools.append(name)

    for _server, tool in _SERVER_TOOL.findall(text):
        add(tool)
    for tool in _CALL_TOOL.findall(text):
        add(tool)
    for tool in _CAMEL_TOOL.findall(text):
        add(tool)
    for tool in _DEP_TOOL.findall(text):
        add(tool)

    return tools
