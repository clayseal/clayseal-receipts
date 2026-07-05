"""Slugify task titles for triage."""

from __future__ import annotations

import re


def slugify(text: str) -> str:
    """Convert text to a hyphen slug."""
    lowered = text.lower()
    return re.sub(r"[^a-z0-9]", "-", lowered)
