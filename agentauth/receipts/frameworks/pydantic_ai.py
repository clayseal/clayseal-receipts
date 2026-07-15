"""Pydantic AI adapters for Agent Receipts.

Use ``receipted_plain_tool`` when registering plain functions directly with a
Pydantic AI agent. Use ``receipted_tool`` when you want a Pydantic AI ``Tool``
object and have installed ``clayseal-receipts[pydantic-ai]``.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentauth.receipts.frameworks.generic import (
    OutputAdapter,
    default_output_adapter,
    receipted_function,
)


def _missing_pydantic_ai(exc: ImportError) -> ImportError:
    return ImportError(
        "Pydantic AI support requires optional dependencies. "
        'Install with: pip install "clayseal-receipts[pydantic-ai] @ git+https://github.com/clayseal/clayseal-receipts.git.5.2".'
    ).with_traceback(exc.__traceback__)


def receipted_plain_tool(
    target: Callable[..., Any],
    policy: Any,
    *,
    output_adapter: OutputAdapter = default_output_adapter,
    action: str | None = None,
    run_kwargs: dict[str, Any] | None = None,
    **wrapper_kwargs: Any,
) -> Callable[..., Any]:
    """Return a receipt-emitting function for ``agent.tool_plain`` or tool lists."""
    return receipted_function(
        target,
        policy,
        output_adapter=output_adapter,
        action=action or f"pydantic_ai.tool.{getattr(target, '__name__', 'tool')}",
        run_kwargs=run_kwargs,
        **wrapper_kwargs,
    )


def receipted_tool(
    target: Callable[..., Any],
    policy: Any,
    *,
    name: str | None = None,
    description: str | None = None,
    output_adapter: OutputAdapter = default_output_adapter,
    action: str | None = None,
    run_kwargs: dict[str, Any] | None = None,
    takes_ctx: bool = False,
    **wrapper_kwargs: Any,
) -> Any:
    """Wrap a callable as a Pydantic AI ``Tool`` that emits receipts.

    Context-taking tools are not receipted here because framework context objects
    are not stable receipt inputs. Wrap the side-effecting inner function instead.
    """
    if takes_ctx:
        raise ValueError(
            "receipted_tool only supports takes_ctx=False; wrap the side-effecting "
            "inner function with receipted_plain_tool instead"
        )
    try:
        from pydantic_ai import Tool
    except ImportError as exc:  # pragma: no cover - dependency-free path tested by callers
        raise _missing_pydantic_ai(exc) from exc

    wrapped = receipted_plain_tool(
        target,
        policy,
        output_adapter=output_adapter,
        action=action,
        run_kwargs=run_kwargs,
        **wrapper_kwargs,
    )
    tool_kwargs: dict[str, Any] = {"takes_ctx": False}
    if name is not None:
        tool_kwargs["name"] = name
    if description is not None:
        tool_kwargs["description"] = description
    return Tool(wrapped, **tool_kwargs)
