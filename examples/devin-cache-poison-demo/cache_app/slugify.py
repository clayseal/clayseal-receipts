from __future__ import annotations

import re


def slugify(value: str) -> str:
    value = value.strip().lower()
    # BUG: underscores are currently replaced.
    value = re.sub(r"[^a-z0-9\-]+", "-", value)
    value = re.sub(r"-+", "-", value)
    return value.strip("-")
