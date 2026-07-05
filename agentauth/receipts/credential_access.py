"""Secret / credential path access as a capability (ID-2 / F6/F8).

Default-deny reads of common credential locations unless the policy or authority
grant permits them. Allowed reads are attested on the receipt (path + content hash).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from agentauth.core.hash_util import hash_canonical_json, sha256_hex
from agentauth.core.runtime import AuthorityContext

_DEFAULT_DENIED_PATTERNS = (
    "~/.ssh/**",
    "~/.ssh/id_*",
    "~/.aws/credentials",
    "~/.config/gh/hosts.yml",
    "~/.netrc",
    "**/id_rsa",
    "**/id_ed25519",
    "**/.env",
    "**/*credentials*",
    "**/*secret*",
    "/etc/shadow",
)

_PATH_ARG_KEYS = (
    "path",
    "file_path",
    "filepath",
    "filename",
    "target",
    "source",
    "credential_path",
    "key_path",
    "private_key_path",
)

_READ_TOOL_MARKERS = ("read", "load", "open", "fetch", "cat", "file", "credential", "secret", "key")


@dataclass
class CredentialAccessPolicy:
    enabled: bool = False
    default_deny: bool = True
    denied_paths: list[str] = field(default_factory=lambda: list(_DEFAULT_DENIED_PATTERNS))
    allowed_paths: list[str] = field(default_factory=list)
    read_tools: list[str] = field(default_factory=list)

    @classmethod
    def from_policy_dict(cls, raw: dict[str, Any] | None) -> CredentialAccessPolicy:
        if not isinstance(raw, dict):
            return cls()
        denied = raw.get("denied_paths") or raw.get("deny_paths")
        allowed = raw.get("allowed_paths") or raw.get("allowlist")
        tools = raw.get("read_tools") or raw.get("tools")
        return cls(
            enabled=bool(raw.get("enabled", False)),
            default_deny=bool(raw.get("default_deny", True)),
            denied_paths=[str(item) for item in (denied or _DEFAULT_DENIED_PATTERNS)],
            allowed_paths=[str(item) for item in (allowed or [])],
            read_tools=[str(item) for item in (tools or [])],
        )


@dataclass
class CredentialAccessAttestation:
    paths: list[dict[str, Any]] = field(default_factory=list)
    authorized: bool = True
    blocked_paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "paths": list(self.paths),
            "authorized": self.authorized,
            "blocked_paths": list(self.blocked_paths),
        }


def _expand_user(path: str) -> str:
    if path.startswith("~/"):
        return path.replace("~/", "/home/user/", 1)
    return path


def path_matches_pattern(path: str, pattern: str) -> bool:
    normalized = _expand_user(path.strip())
    pat = _expand_user(pattern.strip())
    if "**" in pat or "*" in pat or "?" in pat:
        return fnmatch.fnmatchcase(normalized, pat)
    return PurePosixPath(normalized) == PurePosixPath(pat) or normalized.endswith(pat)


def is_credential_read_tool(tool_name: str, *, policy: CredentialAccessPolicy) -> bool:
    if policy.read_tools:
        return tool_name in policy.read_tools
    lowered = tool_name.lower()
    return any(marker in lowered for marker in _READ_TOOL_MARKERS)


def extract_path_candidates(arguments: dict[str, Any] | None) -> list[str]:
    args = dict(arguments or {})
    paths: list[str] = []
    for key in _PATH_ARG_KEYS:
        raw = args.get(key)
        if isinstance(raw, str) and raw.strip():
            paths.append(raw.strip())
    for _key, raw in args.items():
        if isinstance(raw, str) and ("/" in raw or raw.startswith("~")):
            if len(raw) < 512:
                paths.append(raw.strip())
    return list(dict.fromkeys(paths))


def _authority_allows_path(authority: AuthorityContext, path: str) -> bool:
    normalized = path.lower()
    for scope in authority.resource_scope:
        if scope.startswith("credential:") or scope.startswith("file:"):
            if path_matches_pattern(normalized, scope.split(":", 1)[-1]):
                return True
    for capability in authority.capabilities:
        if capability.startswith("credential:") or capability.startswith("file:"):
            if path_matches_pattern(normalized, capability.split(":", 1)[-1]):
                return True
        if capability in {"credential:*", "file:*"}:
            return True
    return False


def evaluate_credential_access(
    *,
    tool_name: str,
    arguments: dict[str, Any] | None,
    policy: CredentialAccessPolicy,
    authority: AuthorityContext | None = None,
    content_bytes: bytes | None = None,
) -> tuple[list[str], CredentialAccessAttestation | None]:
    if not policy.enabled:
        return [], None

    paths = extract_path_candidates(arguments)
    if not paths and not is_credential_read_tool(tool_name, policy=policy):
        return [], None

    attestation = CredentialAccessAttestation()
    violations: list[str] = []

    for path in paths:
        allowed = False
        if policy.allowed_paths and any(
            path_matches_pattern(path, pattern) for pattern in policy.allowed_paths
        ):
            allowed = True
        elif authority is not None and _authority_allows_path(authority, path):
            allowed = True
        elif not policy.default_deny:
            allowed = True
        elif not any(path_matches_pattern(path, pattern) for pattern in policy.denied_paths):
            allowed = True

        entry: dict[str, Any] = {"path": path}
        if content_bytes is not None:
            entry["content_hash"] = sha256_hex(content_bytes)
        attestation.paths.append(entry)

        if not allowed:
            attestation.blocked_paths.append(path)
            violations.append(f"credential path {path!r} is not authorized")

    attestation.authorized = not attestation.blocked_paths
    return violations, attestation


def annotate_credential_access(
    *,
    tool_name: str,
    arguments: dict[str, Any] | None,
    policy: CredentialAccessPolicy,
    authority: AuthorityContext | None,
    authorization: dict[str, Any] | None,
    content_bytes: bytes | None = None,
) -> list[str]:
    violations, attestation = evaluate_credential_access(
        tool_name=tool_name,
        arguments=arguments,
        policy=policy,
        authority=authority,
        content_bytes=content_bytes,
    )
    if attestation is None:
        return violations
    payload = authorization if authorization is not None else {}
    payload["credential_access"] = attestation.to_dict()
    return violations
