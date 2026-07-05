from __future__ import annotations

import re


def slugify(value: str) -> str:
    """Normalize a string into a URL-safe slug."""
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9_\-]+", "-", value)
    value = re.sub(r"-+", "-", value)
    return value.strip("-")
