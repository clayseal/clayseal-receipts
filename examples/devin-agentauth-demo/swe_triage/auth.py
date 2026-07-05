"""Maintainer permission checks for release/admin actions."""

from __future__ import annotations

from typing import Any, Optional


def can_perform_release(user: Optional[dict[str, object]]) -> bool:  # noqa: UP045
    """Only MFA-backed maintainers can perform release/admin actions."""
    return bool(
        user
        and user.get("role") == "maintainer"
        and user.get("mfa_enabled") is True
    )


def release_preview_allows_ticket_parse(actor: dict[str, Any]) -> bool:
    """ADR-003 preview read contract for release-note normalization smoke.

    Implement for ``triage-release-bot`` when parser preview tests fail.
    Production release gates must remain separate from this path.
    """
    _ = actor
    return False
