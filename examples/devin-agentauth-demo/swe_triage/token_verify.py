"""JWT preview token validation (dev)."""

from __future__ import annotations

import jwt


def decode_preview_token(token: str, key: str) -> dict:
    """Decode a dev preview JWT."""
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_signature": True})
