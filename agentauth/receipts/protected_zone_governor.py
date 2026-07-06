"""DP-23: Protected-zone governor — broker-level enforcement of protected zones.

Checks the action's resource_ref against a set of protected-zone matchers
and the lease's explicit-allow set.  Denies or requires step-up when
a protected resource is accessed without explicit intent.

This governor sits in the enforcement chain and is composed with an
inner governor (e.g. RuleBasedSandboxGovernor or TighteningGovernor).

Principle: "explicit intent" must come from the trusted control plane
(GoalSpec.allow_resources), never from tool outputs or agent suggestions.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from agentauth.core.runtime import ExecutionContext, SideEffectLevel

from .behavior_monitor import BehaviorMonitorResult
from .instruction_surfaces import (
    INSTRUCTION_SURFACE_REPO_PATTERNS,
    is_agent_memory_path,
)
from .sandbox_governor import (
    NullSandboxGovernor,
    SandboxEnforcement,
    SandboxGovernor,
    SandboxGovernorResult,
)

_DEFAULT_PROTECTED_PATTERNS: tuple[str, ...] = (
    "repo://keys/*",
    "repo://.ssh/*",
    "repo://.env*",
    "repo://*.pem",
    "repo://*.key",
    "repo://auth/*",
    "repo://identity/*",
    "repo://deploy/*",
    "repo://terraform/*",
    "repo://helm/*",
    "repo://k8s/*",
    "repo://.github/workflows/*",
    "repo://.agentauth/*",
    "repo://.devin/*",
    "repo://.cursor/*",
    "repo://.vscode/*",
    *INSTRUCTION_SURFACE_REPO_PATTERNS,
    "secrets://*",
    "net://*",
)


@dataclass
class ProtectedZoneConfig:
    protected_patterns: tuple[str, ...] = _DEFAULT_PROTECTED_PATTERNS
    deny_on_write: bool = True
    step_up_on_read: bool = True
    deny_egress: bool = True


class ProtectedZoneGovernor:
    """Broker-level enforcement of protected zones (DP-23).

    Checks every tool call's ``resource_ref`` against protected-zone
    matchers.  Access is allowed only when:

    1. The resource is in the lease's ``explicit_allow_resources``, OR
    2. The resource is in the authority's ``approval_refs``, OR
    3. The resource doesn't match any protected pattern.

    Otherwise: writes are denied, reads require step-up.

    Usage::

        governor = ProtectedZoneGovernor(
            inner=RuleBasedSandboxGovernor(...),
            explicit_allow={"repo://auth/verify.py"},
        )
    """

    def __init__(
        self,
        inner: SandboxGovernor | None = None,
        *,
        explicit_allow: set[str] | None = None,
        allow_agent_memory_writes: bool = False,
        config: ProtectedZoneConfig | None = None,
    ) -> None:
        self.inner = inner or NullSandboxGovernor()
        self.explicit_allow = set(explicit_allow or set())
        self.allow_agent_memory_writes = allow_agent_memory_writes
        self.config = config or ProtectedZoneConfig()
        self._step_up_approvals: set[str] = set()

    def approve_resource(self, resource_ref: str) -> None:
        """Record a step-up approval for a specific resource (control-plane call)."""
        self._step_up_approvals.add(resource_ref)

    @staticmethod
    def _strip_scheme(ref: str) -> str:
        """Strip scheme to get the bare path for matching."""
        for prefix in ("repo_write://", "repo_read://", "repo://", "file:"):
            if ref.startswith(prefix):
                return ref[len(prefix):]
        return ref

    def _is_protected(self, resource_ref: str) -> bool:
        bare_ref = self._strip_scheme(resource_ref)
        for pattern in self.config.protected_patterns:
            if fnmatch.fnmatch(resource_ref, pattern):
                return True
            bare_pattern = self._strip_scheme(pattern)
            if fnmatch.fnmatch(bare_ref, bare_pattern):
                return True
            # Also match directory-level refs (e.g. "auth" matches "auth/*")
            if bare_pattern.endswith("/*") and bare_ref == bare_pattern[:-2]:
                return True
        # Egress: net:// is always protected
        if resource_ref.startswith("net://"):
            return True
        return False

    def _is_explicitly_allowed(self, resource_ref: str, ctx: ExecutionContext) -> bool:
        bare = self._strip_scheme(resource_ref)
        is_write = resource_ref.startswith("repo_write://")
        all_allowed = self.explicit_allow | self._step_up_approvals | set(ctx.authority.approval_refs)
        for entry in all_allowed:
            if entry == resource_ref:
                return True
            if fnmatch.fnmatch(resource_ref, entry):
                return True
            # Scheme-stripped match — but a read allow must NOT grant write access
            entry_bare = self._strip_scheme(entry)
            if fnmatch.fnmatch(bare, entry_bare):
                entry_is_read_only = entry.startswith("repo_read://")
                if is_write and entry_is_read_only:
                    continue  # read allow does not grant write
                return True
        return False

    def _is_agent_memory_ref(self, resource_ref: str) -> bool:
        bare = self._strip_scheme(resource_ref)
        return is_agent_memory_path(bare) or is_agent_memory_path(resource_ref)

    def decide(
        self,
        ctx: ExecutionContext,
        *,
        monitor: BehaviorMonitorResult | None = None,
        structural_violations: list[str] | None = None,
    ) -> SandboxGovernorResult:
        ref = ctx.action.resource_ref
        is_read = ctx.action.side_effect_level == SideEffectLevel.READ_ONLY
        is_write = not is_read

        if ref and is_write and self._is_agent_memory_ref(ref):
            if not self.allow_agent_memory_writes:
                return SandboxGovernorResult(
                    enforcement=SandboxEnforcement.DENY,
                    extra_violations=[
                        f"protected_zone: agent memory write to '{ref}' denied "
                        f"(requires goal.allow_agent_memory_writes from the control plane)"
                    ],
                )
            if not self._is_explicitly_allowed(ref, ctx):
                return SandboxGovernorResult(
                    enforcement=SandboxEnforcement.DENY,
                    extra_violations=[
                        f"protected_zone: agent memory write to '{ref}' denied "
                        f"(add path to goal.allow_resources when authorizing memory capture)"
                    ],
                )
            return self.inner.decide(
                ctx, monitor=monitor, structural_violations=structural_violations
            )

        if ref and self._is_protected(ref) and not self._is_explicitly_allowed(ref, ctx):
            is_read = ctx.action.side_effect_level == SideEffectLevel.READ_ONLY

            if ref.startswith("net://") and self.config.deny_egress:
                return SandboxGovernorResult(
                    enforcement=SandboxEnforcement.DENY,
                    extra_violations=[
                        f"protected_zone: egress to '{ref}' denied "
                        f"(requires explicit allow)"
                    ],
                )

            if is_read and self.config.step_up_on_read:
                return SandboxGovernorResult(
                    enforcement=SandboxEnforcement.STEP_UP,
                    extra_violations=[
                        f"protected_zone: read access to '{ref}' requires step-up "
                        f"(add to goal.allow_resources or approve via step-up)"
                    ],
                )

            if not is_read and self.config.deny_on_write:
                return SandboxGovernorResult(
                    enforcement=SandboxEnforcement.DENY,
                    extra_violations=[
                        f"protected_zone: write access to '{ref}' denied "
                        f"(requires explicit allow in goal.allow_resources)"
                    ],
                )

        return self.inner.decide(
            ctx, monitor=monitor, structural_violations=structural_violations
        )
