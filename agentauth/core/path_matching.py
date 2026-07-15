"""Path-pattern matching semantics shared across layers (Seam: file scope).

The canonical home for ``allowed_path`` / ``denied_path`` evaluation. Biscuit-specific
fact extraction stays in ``agentauth.identity.biscuit_scope`` (L1); the *matching*
rules live here so capabilities (L2) and receipts (L3) evaluate scope identically.
"""
from __future__ import annotations

import fnmatch
import posixpath


def normalize_path(path: str) -> str:
    """Canonicalize a path for scope matching: unify separators and collapse ``.`` /
    ``..`` / ``//``. Without this, a denied/allowed pattern can be evaded by a
    non-canonical spelling of the same path (``./secrets/x``, ``a//b``) or escaped with
    traversal (``src/../secrets/x`` matches ``src/*`` but resolves elsewhere)."""
    return posixpath.normpath(path.strip().replace("\\", "/"))


def path_escapes_root(path: str) -> bool:
    """True if the (normalized) path is absolute or climbs above the permitted root."""
    norm = normalize_path(path)
    return norm.startswith("/") or norm == ".." or norm.startswith("../")


def path_matches_any(path: str, patterns: list[str]) -> bool:
    normalized = normalize_path(path)
    for pattern in patterns:
        if fnmatch.fnmatchcase(normalized, pattern.strip()):
            return True
    return False


def evaluate_path_scope(
    file_path: str | None,
    *,
    allowed_paths: list[str],
    denied_paths: list[str],
) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for a file path against token path facts."""
    if file_path is None:
        return True, "no file path presented"
    # A path that resolves outside the permitted root is never in scope, whatever the
    # allow/deny patterns say.
    if path_escapes_root(file_path):
        return False, f"path {file_path!r} escapes the permitted root"
    if denied_paths and path_matches_any(file_path, denied_paths):
        return False, f"path {file_path!r} matches a denied_path pattern"
    if allowed_paths and not path_matches_any(file_path, allowed_paths):
        return False, f"path {file_path!r} is outside allowed_path patterns"
    return True, "path scope satisfied"
