"""OpenAI Agents SDK adapters for Agent Receipts."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentauth.receipts.frameworks.generic import (
    OutputAdapter,
    default_output_adapter,
    receipted_function,
)


def _missing_openai_agents(exc: ImportError) -> ImportError:
    return ImportError(
        "OpenAI Agents SDK support requires optional dependencies. "
        'Install with: pip install "clayseal-receipts[openai-agents] @ git+https://github.com/clayseal/clayseal-receipts.git.5.2".'
    ).with_traceback(exc.__traceback__)


def receipted_function_tool(
    target: Callable[..., Any],
    policy: Any,
    *,
    output_adapter: OutputAdapter = default_output_adapter,
    action: str | None = None,
    run_kwargs: dict[str, Any] | None = None,
    function_tool_kwargs: dict[str, Any] | None = None,
    **wrapper_kwargs: Any,
) -> Any:
    """Wrap a sync callable as an OpenAI Agents SDK function tool with receipts.

    Pass SDK-specific options such as ``name_override`` or
    ``description_override`` through ``function_tool_kwargs``.
    """
    try:
        from agents import function_tool
    except ImportError as exc:  # pragma: no cover - dependency-free path tested by callers
        raise _missing_openai_agents(exc) from exc

    tool_name = getattr(target, "__name__", "agentauth_tool")
    wrapped = receipted_function(
        target,
        policy,
        output_adapter=output_adapter,
        action=action or f"openai_agents.tool.{tool_name}",
        run_kwargs=run_kwargs,
        **wrapper_kwargs,
    )
    sdk_kwargs = dict(function_tool_kwargs or {})
    if sdk_kwargs:
        return function_tool(**sdk_kwargs)(wrapped)
    return function_tool(wrapped)
