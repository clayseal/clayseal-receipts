"""Admin authorization helpers."""

from typing import Optional


def can_access_admin(user: Optional[dict[str, object]]) -> bool:  # noqa: UP045
    """Only MFA-backed admins can access admin surfaces."""
    return bool(user and user.get("role") == "admin" and user.get("mfa_enabled") is True)
