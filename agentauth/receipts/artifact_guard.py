"""Log / artifact / cache exfil guardrails (CI-2 / E8).

Redact known secret formats before logs or artifacts leave the trust boundary,
and treat artifact publication as an explicit capability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agentauth.core.hash_util import hash_canonical_json, sha256_hex
from agentauth.core.runtime import AuthorityContext

REDACTED_SECRET = "[REDACTED-SECRET]"

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("stripe_key", re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|token|secret)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}")),
)

_PUBLISH_TOOL_MARKERS = ("upload", "publish", "artifact", "attach", "release", "deploy", "cache")
_ARTIFACT_ARG_KEYS = ("artifact", "artifact_path", "artifact_name", "destination", "bucket", "cache_key")


@dataclass
class ArtifactGuardPolicy:
    enabled: bool = False
    redact_logs: bool = True
    deny_secret_in_artifacts: bool = True
    require_publication_capability: bool = True
    publication_tools: list[str] = field(default_factory=list)

    @classmethod
    def from_policy_dict(cls, raw: dict[str, Any] | None) -> ArtifactGuardPolicy:
        if not isinstance(raw, dict):
            return cls()
        tools = raw.get("publication_tools") or raw.get("tools")
        return cls(
            enabled=bool(raw.get("enabled", False)),
            redact_logs=bool(raw.get("redact_logs", True)),
            deny_secret_in_artifacts=bool(raw.get("deny_secret_in_artifacts", True)),
            require_publication_capability=bool(raw.get("require_publication_capability", True)),
            publication_tools=[str(item) for item in (tools or [])],
        )


@dataclass
class SecretScanResult:
    redacted_text: str
    findings: list[dict[str, str]]
    content_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_hash": self.content_hash,
            "finding_count": len(self.findings),
            "findings": list(self.findings),
        }


def scan_and_redact_secrets(text: str) -> SecretScanResult:
    findings: list[dict[str, str]] = []
    redacted = text
    for label, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(redacted):
            findings.append({"type": label, "span": f"{match.start()}:{match.end()}"})
        redacted = pattern.sub(REDACTED_SECRET, redacted)
    return SecretScanResult(
        redacted_text=redacted,
        findings=findings,
        content_hash=sha256_hex(text.encode("utf-8")),
    )


def redact_log_lines(lines: list[str]) -> tuple[list[str], list[dict[str, Any]]]:
    """Redact secrets from log lines; return redacted lines + scan metadata."""
    scans: list[dict[str, Any]] = []
    out: list[str] = []
    for line in lines:
        result = scan_and_redact_secrets(line)
        out.append(result.redacted_text)
        if result.findings:
            scans.append(result.to_dict())
    return out, scans


def is_artifact_publication_tool(tool_name: str, *, policy: ArtifactGuardPolicy) -> bool:
    if policy.publication_tools:
        return tool_name in policy.publication_tools
    lowered = tool_name.lower()
    return any(marker in lowered for marker in _PUBLISH_TOOL_MARKERS)


def _authority_allows_publication(authority: AuthorityContext, target: str) -> bool:
    target_lower = target.lower()
    for scope in authority.resource_scope:
        if scope.startswith("artifact:") and (
            scope == "artifact:*" or target_lower in scope.lower()
        ):
            return True
    for capability in authority.capabilities:
        if capability in {"artifact:*", "artifact:publish", "ci:publish"}:
            return True
        if capability.startswith("artifact:") and target_lower in capability.lower():
            return True
    return False


def evaluate_artifact_publication(
    *,
    tool_name: str,
    arguments: dict[str, Any] | None,
    policy: ArtifactGuardPolicy,
    authority: AuthorityContext | None = None,
    payload_text: str | None = None,
) -> tuple[list[str], dict[str, Any] | None]:
    if not policy.enabled:
        return [], None

    if not is_artifact_publication_tool(tool_name, policy=policy):
        return [], None

    args = dict(arguments or {})
    target = next(
        (str(args[key]) for key in _ARTIFACT_ARG_KEYS if isinstance(args.get(key), str)),
        tool_name,
    )

    violations: list[str] = []
    block: dict[str, Any] = {
        "tool": tool_name,
        "target": target,
        "arguments_hash": hash_canonical_json(args),
    }

    if policy.require_publication_capability:
        if authority is None or not _authority_allows_publication(authority, target):
            violations.append(f"artifact publication to {target!r} is not authorized")

    if payload_text is not None and policy.deny_secret_in_artifacts:
        scan = scan_and_redact_secrets(payload_text)
        block["secret_scan"] = scan.to_dict()
        if scan.findings:
            violations.append(
                f"artifact payload contains {len(scan.findings)} secret pattern(s)"
            )

    block["authorized"] = not violations
    return violations, block


def annotate_artifact_publication(
    *,
    tool_name: str,
    arguments: dict[str, Any] | None,
    policy: ArtifactGuardPolicy,
    authority: AuthorityContext | None,
    authorization: dict[str, Any] | None,
    payload_text: str | None = None,
) -> list[str]:
    violations, block = evaluate_artifact_publication(
        tool_name=tool_name,
        arguments=arguments,
        policy=policy,
        authority=authority,
        payload_text=payload_text,
    )
    if block is None:
        return violations
    payload = authorization if authorization is not None else {}
    payload["artifact_publication"] = block
    return violations
