"""Biscuit path-pattern scope helpers (SM-7).

Dynamic L2 file scope is encoded as ``allowed_path`` / ``denied_path`` facts on
attenuated Biscuit tokens. Path matching runs in Python (fnmatch); Datalog still
gates the coarse ``(resource, action)`` capability.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any

FILE_RESOURCE = "file"

_ALLOWED_PATH_RE = re.compile(r'allowed_path\("([^"]+)"\)')
_DENIED_PATH_RE = re.compile(r'denied_path\("([^"]+)"\)')


def path_patterns_from_biscuit_blocks(token: Any) -> tuple[list[str], list[str]]:
    """Extract path patterns from all Biscuit block sources (authority + caveats)."""
    allowed: list[str] = []
    denied: list[str] = []
    block_count_attr = getattr(token, "block_count", 0)
    block_count = int(block_count_attr() if callable(block_count_attr) else block_count_attr)
    for index in range(block_count):
        source = str(token.block_source(index))
        allowed.extend(_ALLOWED_PATH_RE.findall(source))
        denied.extend(_DENIED_PATH_RE.findall(source))
    return list(dict.fromkeys(allowed)), list(dict.fromkeys(denied))


def path_matches_any(path: str, patterns: list[str]) -> bool:
    normalized = path.strip()
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
    if denied_paths and path_matches_any(file_path, denied_paths):
        return False, f"path {file_path!r} matches a denied_path pattern"
    if allowed_paths and not path_matches_any(file_path, allowed_paths):
        return False, f"path {file_path!r} is outside allowed_path patterns"
    return True, "path scope satisfied"
