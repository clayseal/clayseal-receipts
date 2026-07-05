"""DP-32: Safe default-deny governor for missing or invalid authority.

Wraps an inner governor and enforces fail-closed behavior: any action whose
side-effect level is above READ_ONLY is denied when the authority context
is missing critical fields (authority_id, expires_at, permit_epoch).

This ensures that a misconfigured or bootstrapping agent cannot perform
mutations without a valid, non-expired authority lease.
"""
from __future__ import annotations

from datetime import datetime, timezone

from agentauth.receipts.behavior_monitor import BehaviorMonitorResult
from agentauth.core.runtime import AuthorityContext, ExecutionContext, SideEffectLevel
from agentauth.receipts.sandbox_governor import (
    NullSandboxGovernor,
    SandboxEnforcement,
    SandboxGovernor,
    SandboxGovernorResult,
)


class DefaultDenySandboxGovernor:
    """Governor that denies non-read actions when authority is missing/invalid (DP-32).

    Checks (in order):
    1. ``authority_id`` must be non-empty.
    2. ``expires_at`` must be present and not expired for side-effecting actions.
    3. ``resource_scope`` must be non-empty when ``require_resource_scope`` is set.

    If all checks pass, delegates to the inner governor.
    """

    def __init__(
        self,
        inner: SandboxGovernor | None = None,
        *,
        require_resource_scope: bool = False,
        allow_read_without_lease: bool = True,
    ) -> None:
        self.inner = inner or NullSandboxGovernor()
        self.require_resource_scope = require_resource_scope
        self.allow_read_without_lease = allow_read_without_lease

    @staticmethod
    def _is_expired(expires_at: str | None) -> bool:
        if not expires_at or not isinstance(expires_at, str):
            return True
        try:
            parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            return True
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc) <= datetime.now(timezone.utc)

    def decide(
        self,
        ctx: ExecutionContext,
        *,
        monitor: BehaviorMonitorResult | None = None,
        structural_violations: list[str] | None = None,
    ) -> SandboxGovernorResult:
        is_read = ctx.action.side_effect_level == SideEffectLevel.READ_ONLY
        violations: list[str] = []

        if not ctx.authority.authority_id:
            violations.append("default_deny: missing authority_id")

        if not is_read or not self.allow_read_without_lease:
            if self._is_expired(ctx.authority.expires_at):
                violations.append(
                    "default_deny: missing or expired authority lease "
                    "(expires_at required for non-read actions)"
                )

        if self.require_resource_scope and not ctx.authority.resource_scope:
            if not is_read:
                violations.append(
                    "default_deny: empty resource_scope "
                    "(required for non-read actions)"
                )

        if violations:
            return SandboxGovernorResult(
                enforcement=SandboxEnforcement.DENY,
                extra_violations=violations,
            )

        return self.inner.decide(
            ctx, monitor=monitor, structural_violations=structural_violations
        )
