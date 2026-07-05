"""Shared instruction-surface path rules (PR gate + runtime sandbox)."""

from __future__ import annotations

import fnmatch

# Auto-loaded repo instruction surfaces — agent writes require explicit goal/mandate scope.
INSTRUCTION_SURFACE_PATH_PATTERNS: tuple[str, ...] = (
    "AGENTS.md",
    "**/AGENTS.md",
    "CLAUDE.md",
    "**/CLAUDE.md",
    ".cursorrules",
    "**/.cursorrules",
    "**/.windsurf/rules/**",
    "**/*.mdc",
    "DELEGATION.md",
    "**/DELEGATION.md",
)

# Agent-runtime memory — default-deny; writable only with explicit opt-in (see policy / mandate).
AGENT_MEMORY_DENY_PATTERNS: tuple[str, ...] = (
    ".devin/knowledge.md",
    ".devin/**",
    "**/.devin/knowledge.md",
)

# Protected-zone `repo://` matchers aligned with the path patterns above.
INSTRUCTION_SURFACE_REPO_PATTERNS: tuple[str, ...] = (
    "repo://AGENTS.md",
    "repo://*/AGENTS.md",
    "repo://CLAUDE.md",
    "repo://*/CLAUDE.md",
    "repo://.cursorrules",
    "repo://*/.cursorrules",
    "repo://DELEGATION.md",
    "repo://*/DELEGATION.md",
    "repo://**/*.mdc",
)


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip().lstrip("/")


def matches_path_pattern(path: str, patterns: tuple[str, ...]) -> bool:
    normalized = _normalize_path(path)
    bare = normalized
    for prefix in ("repo_write://", "repo_read://", "repo://", "file:"):
        if normalized.startswith(prefix):
            bare = normalized[len(prefix) :].lstrip("/")
            break
    for pattern in patterns:
        pat = pattern.replace("**/", "")
        if fnmatch.fnmatch(bare, pat) or fnmatch.fnmatch(bare, pattern):
            return True
    return False


def is_agent_memory_path(path: str) -> bool:
    return matches_path_pattern(path, AGENT_MEMORY_DENY_PATTERNS)


def is_instruction_surface_path(path: str) -> bool:
    return matches_path_pattern(path, INSTRUCTION_SURFACE_PATH_PATTERNS)
