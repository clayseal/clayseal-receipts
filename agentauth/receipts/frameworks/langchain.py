"""LangChain adapters for Agent Receipts.

The helpers in this module keep LangChain optional. Install with
``clayseal-receipts[langchain]`` before using them.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentauth.receipts.frameworks.generic import (
    InputAdapter,
    OutputAdapter,
    ReceiptedCallable,
    default_input_adapter,
    default_output_adapter,
)


def _missing_langchain(exc: ImportError) -> ImportError:
    return ImportError(
        "LangChain support requires optional dependencies. "
        'Install with: pip install "clayseal-receipts[langchain]".'
    ).with_traceback(exc.__traceback__)


def receipted_runnable(
    target: Callable[[dict[str, Any]], Any],
    policy: Any,
    *,
    input_adapter: InputAdapter = default_input_adapter,
    output_adapter: OutputAdapter = default_output_adapter,
    action: str = "langchain.runnable.invoke",
    run_kwargs: dict[str, Any] | None = None,
    **wrapper_kwargs: Any,
) -> Any:
    """Wrap a callable as a LangChain ``RunnableLambda`` that emits receipts."""
    try:
        from langchain_core.runnables import RunnableLambda
    except ImportError as exc:  # pragma: no cover - dependency-free path tested by callers
        raise _missing_langchain(exc) from exc

    receipted = ReceiptedCallable.from_target(
        target,
        policy,
        input_adapter=input_adapter,
        output_adapter=output_adapter,
        action=action,
        run_kwargs=run_kwargs,
        **wrapper_kwargs,
    )
    return RunnableLambda(receipted)


def receipted_tool(
    target: Callable[..., Any],
    policy: Any,
    *,
    name: str | None = None,
    description: str | None = None,
    args_schema: Any = None,
    input_adapter: InputAdapter = default_input_adapter,
    output_adapter: OutputAdapter = default_output_adapter,
    action: str | None = None,
    run_kwargs: dict[str, Any] | None = None,
    return_direct: bool = False,
    **wrapper_kwargs: Any,
) -> Any:
    """Wrap a Python callable as a LangChain ``StructuredTool`` with receipts."""
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:  # pragma: no cover - dependency-free path tested by callers
        raise _missing_langchain(exc) from exc

    tool_name = name or getattr(target, "__name__", "agentauth_tool")
    tool_description = description or getattr(target, "__doc__", None) or tool_name
    run_action = action or f"langchain.tool.{tool_name}"

    def tool_target(input_data: dict[str, Any]) -> Any:
        return target(**input_data)

    receipted = ReceiptedCallable.from_target(
        tool_target,
        policy,
        input_adapter=input_adapter,
        output_adapter=output_adapter,
        action=run_action,
        run_kwargs=run_kwargs,
        **wrapper_kwargs,
    )

    def invoke_tool(**kwargs: Any) -> Any:
        return receipted(kwargs)

    invoke_tool.__name__ = tool_name
    invoke_tool.__doc__ = tool_description

    structured_kwargs: dict[str, Any] = {
        "func": invoke_tool,
        "name": tool_name,
        "description": tool_description,
        "return_direct": return_direct,
    }
    if args_schema is not None:
        structured_kwargs["args_schema"] = args_schema
    return StructuredTool.from_function(**structured_kwargs)
