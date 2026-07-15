"""LlamaIndex tool adapters for Agent Receipts."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentauth.receipts.frameworks.generic import (
    OutputAdapter,
    default_output_adapter,
    receipted_function,
)


def _missing_llamaindex(exc: ImportError) -> ImportError:
    return ImportError(
        "LlamaIndex support requires optional dependencies. "
        'Install with: pip install "clayseal-receipts[llamaindex]".'
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
    **wrapper_kwargs: Any,
) -> Any:
    """Wrap a callable as a LlamaIndex ``FunctionTool`` with receipts."""
    try:
        from llama_index.core.tools import FunctionTool
    except ImportError as exc:  # pragma: no cover - dependency-free path tested by callers
        raise _missing_llamaindex(exc) from exc

    tool_name = name or getattr(target, "__name__", "agentauth_tool")
    wrapped = receipted_function(
        target,
        policy,
        output_adapter=output_adapter,
        action=action or f"llamaindex.tool.{tool_name}",
        run_kwargs=run_kwargs,
        **wrapper_kwargs,
    )
    kwargs: dict[str, Any] = {}
    if name is not None:
        kwargs["name"] = name
    if description is not None:
        kwargs["description"] = description
    return FunctionTool.from_defaults(wrapped, **kwargs)
