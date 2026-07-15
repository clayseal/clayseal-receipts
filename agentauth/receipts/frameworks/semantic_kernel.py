"""Semantic Kernel adapters for Agent Receipts."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentauth.receipts.frameworks.generic import (
    OutputAdapter,
    default_output_adapter,
    receipted_function,
)


def _missing_semantic_kernel(exc: ImportError) -> ImportError:
    return ImportError(
        "Semantic Kernel support requires optional dependencies. "
        'Install with: pip install "clayseal-receipts[semantic-kernel]".'
    ).with_traceback(exc.__traceback__)


def receipted_kernel_function(
    target: Callable[..., Any],
    policy: Any,
    *,
    name: str | None = None,
    description: str | None = None,
    output_adapter: OutputAdapter = default_output_adapter,
    action: str | None = None,
    run_kwargs: dict[str, Any] | None = None,
    kernel_function_kwargs: dict[str, Any] | None = None,
    **wrapper_kwargs: Any,
) -> Any:
    """Wrap a callable as a Semantic Kernel ``kernel_function`` with receipts."""
    try:
        from semantic_kernel.functions import kernel_function
    except ImportError as exc:  # pragma: no cover - dependency-free path tested by callers
        raise _missing_semantic_kernel(exc) from exc

    tool_name = name or getattr(target, "__name__", "agentauth_tool")
    wrapped = receipted_function(
        target,
        policy,
        output_adapter=output_adapter,
        action=action or f"semantic_kernel.function.{tool_name}",
        run_kwargs=run_kwargs,
        **wrapper_kwargs,
    )

    decorator_kwargs = dict(kernel_function_kwargs or {})
    if name is not None:
        decorator_kwargs.setdefault("name", name)
    if description is not None:
        decorator_kwargs.setdefault("description", description)
    return kernel_function(**decorator_kwargs)(wrapped)
