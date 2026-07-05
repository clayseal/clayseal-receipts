from __future__ import annotations

import re


def slugify(value: str) -> str:
    """Normalize a string into a URL-safe slug."""
    value = value.strip().lower()
    # BUG: underscores are currently treated as separators and replaced.
    value = re.sub(r"[^a-z0-9\-]+", "-", value)
    value = re.sub(r"-+", "-", value)
    return value.strip("-")
