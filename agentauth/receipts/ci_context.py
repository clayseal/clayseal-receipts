"""CI prompt/context minimization (CI-1 / SM-22)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentauth.core.hash_util import hash_canonical_json, sha256_hex

DEFAULT_CI_CONTEXT_ALLOWLIST = frozenset(
    {
        "git_diff",
        "mandate",
        "policy",
        "required_tests",
        "workflow_files",
        "issue_template",
        "repository_metadata",
    }
)

DENIED_BY_DEFAULT = frozenset(
    {
        "pr_comment",
        "review_comment",
        "issue_comment",
        "chat_message",
        "retrieval_index",
        "external_url",
    }
)


@dataclass
class CiContextPolicy:
    enabled: bool = False
    allowlist: set[str] = field(default_factory=lambda: set(DEFAULT_CI_CONTEXT_ALLOWLIST))
    deny_by_default: bool = True

    @classmethod
    def from_policy_dict(cls, raw: dict[str, Any] | None) -> CiContextPolicy:
        if not isinstance(raw, dict):
            return cls()
        allow = raw.get("allowlist") or raw.get("allowed_sources")
        return cls(
            enabled=bool(raw.get("enabled", False)),
            allowlist=set(allow) if allow else set(DEFAULT_CI_CONTEXT_ALLOWLIST),
            deny_by_default=bool(raw.get("deny_by_default", True)),
        )


def normalize_ci_source(source_type: str, content: str | bytes, *, ref: str = "") -> dict[str, Any]:
    if isinstance(content, str):
        raw = content.encode("utf-8")
    else:
        raw = content
    return {
        "type": source_type,
        "ref": ref,
        "sha256": sha256_hex(raw),
        "size_bytes": len(raw),
    }


def validate_ci_context(
    sources: list[dict[str, Any]],
    *,
    policy: CiContextPolicy | None = None,
) -> list[str]:
    """Return violations for CI-visible context outside the allowlist."""
    cfg = policy or CiContextPolicy()
    if not cfg.enabled:
        return []
    violations: list[str] = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        source_type = str(source.get("type") or "")
        if not source_type:
            violations.append("ci context source missing type")
            continue
        if source_type in cfg.allowlist:
            continue
        if cfg.deny_by_default or source_type in DENIED_BY_DEFAULT:
            violations.append(
                f"ci context source {source_type!r} is not on the allowlist"
            )
    return violations


def ci_context_block(sources: list[dict[str, Any]]) -> dict[str, Any]:
    """Receipt field enumerating ingested CI context sources."""
    normalized = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        normalized.append(
            {
                "type": source.get("type"),
                "ref": source.get("ref"),
                "sha256": source.get("sha256"),
                "size_bytes": source.get("size_bytes"),
            }
        )
    return {
        "schema": "agent-receipts.ci-context.v1",
        "sources": normalized,
        "commitment": hash_canonical_json(normalized),
    }
