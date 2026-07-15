from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def scopes_from_claims(raw: dict[str, Any], *keys: str) -> list[str]:
    """Normalize provider scope/permission fields into an ordered string list."""
    scopes: list[str] = []
    for key in keys:
        value = raw.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            scopes.extend(part for part in value.split() if part)
        elif isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, dict)):
            scopes.extend(str(part) for part in value if str(part))
    return list(dict.fromkeys(scopes))


def as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, dict)):
        return [str(item) for item in value]
    return [str(value)]
