from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from agentauth.receipts.action_monitor import MonitoringPolicy
from agentauth.receipts.egress import EgressPolicy
from agentauth.core.hash_util import hash_canonical_json
from agentauth.receipts.tool_pinning import ToolPinningPolicy
from agentauth.receipts.credential_access import CredentialAccessPolicy
from agentauth.receipts.artifact_guard import ArtifactGuardPolicy
from agentauth.receipts.bootstrap_sandbox import BootstrapPolicy
from agentauth.receipts.model_canary import CanaryPolicy
from agentauth.receipts.governed_runtime import GovernedRuntimePolicy
from agentauth.receipts.session_token import SessionTokenPolicy


class PolicyTier(str, Enum):
    STRUCTURAL = "structural"
    SCHEMA = "schema"
    TOOL_TRACE = "tool_trace"
    SEMANTIC_APPROX = "semantic_approx"


class PolicyCapability(str, Enum):
    FULLY_PROVEN = "fully_proven"
    TEE_ATTESTED = "tee_attested"
    OPERATOR_ATTESTED = "operator_attested"


@dataclass
class NumericRange:
    field: str
    min: float
    max: float


@dataclass
class Policy:
    """Formal policy specification committed in AgentCertificate."""

    version: int
    name: str
    tier: PolicyTier
    capability: PolicyCapability
    numeric_ranges: list[NumericRange] = field(default_factory=list)
    allowed_tools: list[str] | None = None
    output_schema_required: list[str] = field(default_factory=list)
    min_trust_tier: str | None = None
    monitoring: MonitoringPolicy = field(default_factory=MonitoringPolicy)
    egress: EgressPolicy = field(default_factory=EgressPolicy)
    tool_pinning: ToolPinningPolicy = field(default_factory=ToolPinningPolicy)
    credential_access: CredentialAccessPolicy = field(default_factory=CredentialAccessPolicy)
    artifact_guard: ArtifactGuardPolicy = field(default_factory=ArtifactGuardPolicy)
    bootstrap: BootstrapPolicy = field(default_factory=BootstrapPolicy)
    canary: CanaryPolicy = field(default_factory=CanaryPolicy)
    governed_runtime: GovernedRuntimePolicy = field(default_factory=GovernedRuntimePolicy)
    session_token: SessionTokenPolicy = field(default_factory=SessionTokenPolicy)

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        raw = yaml.safe_load(Path(path).read_text())
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Policy:
        ranges = [
            NumericRange(
                field=r["field"],
                min=float(r["min"]),
                max=float(r["max"]),
            )
            for r in raw.get("numeric_ranges", [])
        ]
        tools = raw.get("allowed_tools")
        if isinstance(tools, dict):
            tools = tools.get("tools")
        schema = raw.get("output_schema") or {}
        required = list(schema.get("required", []))
        min_trust_tier = raw.get("min_trust_tier")
        monitoring_raw = raw.get("monitoring")
        monitoring = (
            MonitoringPolicy.from_policy_dict(monitoring_raw)
            if isinstance(monitoring_raw, dict)
            else MonitoringPolicy()
        )
        egress_raw = raw.get("egress")
        egress = (
            EgressPolicy.from_policy_dict(egress_raw)
            if isinstance(egress_raw, dict)
            else EgressPolicy()
        )
        tool_pinning_raw = raw.get("tool_pinning")
        tool_pinning = (
            ToolPinningPolicy.from_policy_dict(tool_pinning_raw)
            if isinstance(tool_pinning_raw, dict)
            else ToolPinningPolicy()
        )
        credential_raw = raw.get("credential_access")
        credential_access = (
            CredentialAccessPolicy.from_policy_dict(credential_raw)
            if isinstance(credential_raw, dict)
            else CredentialAccessPolicy()
        )
        artifact_raw = raw.get("artifact_guard")
        artifact_guard = (
            ArtifactGuardPolicy.from_policy_dict(artifact_raw)
            if isinstance(artifact_raw, dict)
            else ArtifactGuardPolicy()
        )
        bootstrap_raw = raw.get("bootstrap")
        bootstrap = (
            BootstrapPolicy.from_policy_dict(bootstrap_raw)
            if isinstance(bootstrap_raw, dict)
            else BootstrapPolicy()
        )
        canary_raw = raw.get("canary")
        canary = (
            CanaryPolicy.from_policy_dict(canary_raw)
            if isinstance(canary_raw, dict)
            else CanaryPolicy()
        )
        governed_raw = raw.get("governed_runtime")
        governed_runtime = (
            GovernedRuntimePolicy.from_policy_dict(governed_raw)
            if isinstance(governed_raw, dict)
            else GovernedRuntimePolicy()
        )
        session_token_raw = raw.get("session_token")
        session_token = (
            SessionTokenPolicy.from_policy_dict(session_token_raw)
            if isinstance(session_token_raw, dict)
            else SessionTokenPolicy()
        )
        return cls(
            version=int(raw["version"]),
            name=str(raw["name"]),
            tier=PolicyTier(raw["tier"]),
            capability=PolicyCapability(raw["capability"]),
            numeric_ranges=ranges,
            allowed_tools=list(tools) if tools else None,
            output_schema_required=required,
            min_trust_tier=str(min_trust_tier) if min_trust_tier else None,
            monitoring=monitoring,
            egress=egress,
            tool_pinning=tool_pinning,
            credential_access=credential_access,
            artifact_guard=artifact_guard,
            bootstrap=bootstrap,
            canary=canary,
            governed_runtime=governed_runtime,
            session_token=session_token,
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "version": self.version,
            "name": self.name,
            "tier": self.tier.value,
            "capability": self.capability.value,
            "numeric_ranges": [
                {"field": r.field, "min": r.min, "max": r.max} for r in self.numeric_ranges
            ],
        }
        if self.allowed_tools:
            out["allowed_tools"] = {"tools": self.allowed_tools}
        if self.output_schema_required:
            out["output_schema"] = {
                "fields": self.output_schema_required,
                "required": self.output_schema_required,
            }
        if self.min_trust_tier:
            out["min_trust_tier"] = self.min_trust_tier
        if self.monitoring.enabled or self.monitoring.sensitive_keywords:
            out["monitoring"] = {
                "enabled": self.monitoring.enabled,
                "review_threshold": self.monitoring.review_threshold,
                "block_threshold": self.monitoring.block_threshold,
                "sensitive_keywords": list(self.monitoring.sensitive_keywords),
                "history_window": self.monitoring.history_window,
            }
        if self.egress.enabled:
            out["egress"] = {
                "enabled": self.egress.enabled,
                "default_deny": self.egress.default_deny,
                "allowed_hosts": list(self.egress.allowed_hosts),
                "network_tools": list(self.egress.network_tools),
            }
        if self.tool_pinning.enabled:
            out["tool_pinning"] = {
                "enabled": self.tool_pinning.enabled,
                "require_pinned": self.tool_pinning.require_pinned,
                "deny_on_mismatch": self.tool_pinning.deny_on_mismatch,
                "require_witness_tools": list(self.tool_pinning.require_witness_tools),
            }
        if self.credential_access.enabled:
            out["credential_access"] = {
                "enabled": self.credential_access.enabled,
                "default_deny": self.credential_access.default_deny,
                "denied_paths": list(self.credential_access.denied_paths),
                "allowed_paths": list(self.credential_access.allowed_paths),
            }
        if self.artifact_guard.enabled:
            out["artifact_guard"] = {
                "enabled": self.artifact_guard.enabled,
                "redact_logs": self.artifact_guard.redact_logs,
                "deny_secret_in_artifacts": self.artifact_guard.deny_secret_in_artifacts,
                "require_publication_capability": self.artifact_guard.require_publication_capability,
            }
        if self.bootstrap.enabled:
            out["bootstrap"] = {
                "enabled": self.bootstrap.enabled,
                "deny_recursive_submodules": self.bootstrap.deny_recursive_submodules,
                "require_sandbox_for_commands": self.bootstrap.require_sandbox_for_commands,
                "record_command_receipts": self.bootstrap.record_command_receipts,
            }
        if self.canary.enabled:
            out["canary"] = {
                "enabled": self.canary.enabled,
                "expected_tools": list(self.canary.expected_tools),
                "forbidden_tools": list(self.canary.forbidden_tools),
            }
        return out

    def commitment(self) -> str:
        return hash_canonical_json(self.to_dict())

    def check_tool(self, tool_name: str) -> list[str]:
        """Return violations if tool is not on the policy allowlist."""
        if self.allowed_tools is None:
            return []
        if tool_name not in self.allowed_tools:
            return [f"tool {tool_name} not in policy allowlist"]
        return []

    def check_output(self, output: dict[str, Any]) -> list[str]:
        """Software policy check (mirrored by ZK Circuit 2 later)."""
        violations: list[str] = []
        for req in self.output_schema_required:
            if req not in output:
                violations.append(f"missing required field: {req}")
        for r in self.numeric_ranges:
            if r.field not in output:
                violations.append(f"missing numeric field: {r.field}")
                continue
            val = output[r.field]
            if not isinstance(val, (int, float)):
                violations.append(f"field {r.field} is not numeric")
                continue
            n = float(val)
            if n < r.min or n > r.max:
                violations.append(f"{r.field}={n} outside [{r.min}, {r.max}]")
        return violations
