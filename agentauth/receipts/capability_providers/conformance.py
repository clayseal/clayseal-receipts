"""Conformance kit for capability (authorization) providers.

Mirror of ``agentauth.core.conformance.check_identity_provider`` one layer up: validates
that a provider satisfies the ``CapabilityProvider`` contract and produces well-formed
decisions over sample requests. Returns a list of problems, empty when it conforms — so
third-party providers can be validated in their own test suites.

Each sample is ``{"action", "resource", "context"?, "expected"?}``; when ``expected`` is
given, the provider's decision must match it.
"""
from __future__ import annotations

from typing import Any

from agentauth.core.identity_protocol import CapabilityDecision


def check_capability_provider(provider: Any, samples: list[dict[str, Any]]) -> list[str]:
    """Return conformance problems for ``provider`` over ``samples`` ( [] == conforms )."""
    problems: list[str] = []

    name = getattr(provider, "name", None)
    if not name or not isinstance(name, str):
        problems.append("provider.name must be a non-empty string")

    for method in ("authorize", "check_path"):
        if not callable(getattr(provider, method, None)):
            problems.append(f"provider must implement {method}()")

    if not callable(getattr(provider, "authorize", None)):
        return problems

    for i, sample in enumerate(samples):
        action = sample.get("action", "read")
        resource = sample.get("resource", "")
        try:
            decision = provider.authorize(
                action=action, resource=resource, context=sample.get("context")
            )
        except Exception as exc:
            problems.append(f"sample[{i}]: authorize raised {type(exc).__name__}: {exc}")
            continue
        if not isinstance(decision, CapabilityDecision):
            problems.append(
                f"sample[{i}]: authorize returned {type(decision).__name__}, "
                "expected CapabilityDecision"
            )
            continue
        if "expected" in sample and decision.allowed is not sample["expected"]:
            problems.append(
                f"sample[{i}]: expected allowed={sample['expected']} for "
                f"{action!r} on {resource!r}, got {decision.allowed}"
            )

    return problems
