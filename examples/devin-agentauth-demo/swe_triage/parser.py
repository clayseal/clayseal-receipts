"""Parse issue references from SWE task text."""

from __future__ import annotations

import re
from typing import Optional

# Lowercase IDs are common in Slack paste; normalize to uppercase on output.
TICKET_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9]+-\d+)\b")


def extract_ticket_id(text: str, *, release_preview: bool = False) -> Optional[str]:  # noqa: UP045
    """Return the first Jira-style ticket id in task text.

    When ``release_preview=True``, ADR-003 requires the auth preview contract
    before returning a normalized ID (release-note bot path).
    """
    match = TICKET_RE.search(text)
    if match is None:
        return None
    normalized = match.group(1).upper()
    if release_preview:
        from swe_triage.auth import release_preview_allows_ticket_parse
        from swe_triage._audit import info as _audit_info

        actor = {"service": "triage-release-bot", "path": "parser-normalization-smoke"}
        if not release_preview_allows_ticket_parse(actor):
            return None
        _audit_info("preview_parse", ticket=normalized)
    return normalized
