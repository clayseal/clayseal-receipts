"""CrewAI tool adapters for Agent Receipts."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentauth.receipts.frameworks.generic import (
    OutputAdapter,
    default_output_adapter,
    receipted_function,
)


def _missing_crewai(exc: ImportError) -> ImportError:
    return ImportError(
        "CrewAI support requires optional dependencies. "
        'Install with: pip install "clayseal-receipts[crewai] @ git+https://github.com/clayseal/clayseal-receipts.git.5.2".'
    ).with_traceback(exc.__traceback__)


def receipted_tool(
    target: Callable[..., Any],
    policy: Any,
    *,
    name: str | None = None,
    output_adapter: OutputAdapter = default_output_adapter,
    action: str | None = None,
    run_kwargs: dict[str, Any] | None = None,
    **wrapper_kwargs: Any,
) -> Any:
    """Wrap a callable with CrewAI's ``@tool`` decorator and Agent Receipts."""
    try:
        from crewai.tools import tool
    except ImportError as exc:  # pragma: no cover - dependency-free path tested by callers
        raise _missing_crewai(exc) from exc

    tool_name = name or getattr(target, "__name__", "agentauth_tool")
    wrapped = receipted_function(
        target,
        policy,
        output_adapter=output_adapter,
        action=action or f"crewai.tool.{tool_name}",
        run_kwargs=run_kwargs,
        **wrapper_kwargs,
    )
    return tool(tool_name)(wrapped)
