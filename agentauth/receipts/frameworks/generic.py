"""Framework-neutral adapters for wrapping agent calls with receipts."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import wraps
from inspect import signature
from typing import Any

from agentauth.receipts.wrapper import AgentWrapper, RunResult

InputAdapter = Callable[[Any], dict[str, Any]]
OutputAdapter = Callable[[RunResult], Any]


def default_input_adapter(value: Any) -> dict[str, Any]:
    """Normalize framework inputs into the dict shape expected by AgentWrapper."""
    if isinstance(value, Mapping):
        return dict(value)
    return {"input": value}


def _coerce_output(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {"output": value}


def default_output_adapter(result: RunResult) -> dict[str, Any]:
    """Return only the wrapped callable's output."""
    return result.output


def output_with_receipt_metadata(result: RunResult) -> dict[str, Any]:
    """Return output plus receipt metadata useful for framework callbacks/logs."""
    return {
        **result.output,
        "_agentauth_receipt": {
            "policy_satisfied": result.policy_satisfied,
            "decision_outcome": result.decision_outcome.value,
            "policy_violations": list(result.policy_violations),
            "authority_version": result.authority_version,
            "session_id": result.session_id,
            "proof": result.proof.to_dict(),
        },
    }


@dataclass
class ReceiptedCallable:
    """Callable adapter that executes a target and records an Agent Receipt.

    The target receives normalized dict input. Non-dict target outputs are wrapped
    as ``{"output": value}`` before policy evaluation so simple framework tools can
    be receipted without custom glue.
    """

    target: Callable[[dict[str, Any]], Any]
    wrapper: AgentWrapper
    input_adapter: InputAdapter = default_input_adapter
    output_adapter: OutputAdapter = default_output_adapter
    action: str = "agent.framework.invoke"
    run_kwargs: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_target(
        cls,
        target: Callable[[dict[str, Any]], Any],
        policy: Any,
        *,
        input_adapter: InputAdapter = default_input_adapter,
        output_adapter: OutputAdapter = default_output_adapter,
        action: str = "agent.framework.invoke",
        run_kwargs: dict[str, Any] | None = None,
        **wrapper_kwargs: Any,
    ) -> ReceiptedCallable:
        def model(input_data: dict[str, Any]) -> dict[str, Any]:
            return _coerce_output(target(input_data))

        return cls(
            target=target,
            wrapper=AgentWrapper(model=model, policy=policy, **wrapper_kwargs),
            input_adapter=input_adapter,
            output_adapter=output_adapter,
            action=action,
            run_kwargs=dict(run_kwargs or {}),
        )

    def run_result(self, value: Any, **run_kwargs: Any) -> RunResult:
        merged = {**self.run_kwargs, **run_kwargs}
        action = merged.pop("action", self.action)
        return self.wrapper.run(self.input_adapter(value), action=action, **merged)

    def __call__(self, value: Any, **run_kwargs: Any) -> Any:
        return self.output_adapter(self.run_result(value, **run_kwargs))


def receipted_function(
    target: Callable[..., Any],
    policy: Any,
    *,
    output_adapter: OutputAdapter = default_output_adapter,
    action: str | None = None,
    run_kwargs: dict[str, Any] | None = None,
    **wrapper_kwargs: Any,
) -> Callable[..., Any]:
    """Return a receipt-emitting callable with the target's public signature.

    This is useful for frameworks that already accept normal Python functions as
    tools. Arguments are bound with ``inspect.signature`` and passed to the
    target by keyword, which matches common agent-tool function shapes.
    """
    public_signature = signature(target)
    tool_name = getattr(target, "__name__", "agentauth_function")

    def target_from_bound_args(input_data: dict[str, Any]) -> Any:
        return target(**input_data)

    receipted = ReceiptedCallable.from_target(
        target_from_bound_args,
        policy,
        output_adapter=output_adapter,
        action=action or f"agent.framework.function.{tool_name}",
        run_kwargs=run_kwargs,
        **wrapper_kwargs,
    )

    @wraps(target)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        bound = public_signature.bind(*args, **kwargs)
        bound.apply_defaults()
        return receipted(dict(bound.arguments))

    wrapped.__signature__ = public_signature  # type: ignore[attr-defined]
    wrapped.agentauth_adapter = receipted  # type: ignore[attr-defined]
    return wrapped
