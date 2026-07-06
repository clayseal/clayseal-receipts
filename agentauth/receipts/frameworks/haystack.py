"""Haystack adapters for Agent Receipts."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentauth.receipts.frameworks.generic import (
    OutputAdapter,
    default_output_adapter,
    receipted_function,
)


def _missing_haystack(exc: ImportError) -> ImportError:
    return ImportError(
        "Haystack support requires optional dependencies. "
        'Install with: pip install "agentauth-receipts[haystack]".'
    ).with_traceback(exc.__traceback__)


def receipted_tool(
    target: Callable[..., Any],
    policy: Any,
    *,
    name: str | None = None,
    description: str | None = None,
    parameters: dict[str, Any] | None = None,
    output_adapter: OutputAdapter = default_output_adapter,
    action: str | None = None,
    run_kwargs: dict[str, Any] | None = None,
    tool_kwargs: dict[str, Any] | None = None,
    **wrapper_kwargs: Any,
) -> Any:
    """Wrap a callable as a Haystack ``Tool`` with receipts."""
    try:
        from haystack.tools import Tool
    except ImportError as exc:  # pragma: no cover - dependency-free path tested by callers
        raise _missing_haystack(exc) from exc

    tool_name = name or getattr(target, "__name__", "agentauth_tool")
    tool_description = description or getattr(target, "__doc__", None) or tool_name
    wrapped = receipted_function(
        target,
        policy,
        output_adapter=output_adapter,
        action=action or f"haystack.tool.{tool_name}",
        run_kwargs=run_kwargs,
        **wrapper_kwargs,
    )

    sdk_kwargs = dict(tool_kwargs or {})
    sdk_kwargs.setdefault("name", tool_name)
    sdk_kwargs.setdefault("description", tool_description)
    sdk_kwargs.setdefault("function", wrapped)
    if parameters is not None:
        sdk_kwargs.setdefault("parameters", parameters)
    return Tool(**sdk_kwargs)
