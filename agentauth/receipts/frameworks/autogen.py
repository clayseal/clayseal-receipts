"""AutoGen adapters for Agent Receipts."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentauth.receipts.frameworks.generic import (
    OutputAdapter,
    default_output_adapter,
    receipted_function,
)


def _missing_autogen(exc: ImportError) -> ImportError:
    return ImportError(
        "AutoGen support requires optional dependencies. "
        'Install with: pip install "clayseal-receipts[autogen] @ git+https://github.com/clayseal/clayseal-receipts.git.5.2".'
    ).with_traceback(exc.__traceback__)


def receipted_function_tool(
    target: Callable[..., Any],
    policy: Any,
    *,
    name: str | None = None,
    description: str | None = None,
    output_adapter: OutputAdapter = default_output_adapter,
    action: str | None = None,
    run_kwargs: dict[str, Any] | None = None,
    function_tool_kwargs: dict[str, Any] | None = None,
    **wrapper_kwargs: Any,
) -> Any:
    """Wrap a callable as an AutoGen Core ``FunctionTool`` with receipts."""
    try:
        from autogen_core.tools import FunctionTool
    except ImportError as exc:  # pragma: no cover - dependency-free path tested by callers
        raise _missing_autogen(exc) from exc

    tool_name = name or getattr(target, "__name__", "agentauth_tool")
    tool_description = description or getattr(target, "__doc__", None) or tool_name
    wrapped = receipted_function(
        target,
        policy,
        output_adapter=output_adapter,
        action=action or f"autogen.tool.{tool_name}",
        run_kwargs=run_kwargs,
        **wrapper_kwargs,
    )

    sdk_kwargs = dict(function_tool_kwargs or {})
    sdk_kwargs.setdefault("name", tool_name)
    sdk_kwargs.setdefault("description", tool_description)
    return FunctionTool(wrapped, **sdk_kwargs)
