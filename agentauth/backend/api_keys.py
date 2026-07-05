"""API key generation and verification helpers."""
from __future__ import annotations

import hashlib
import hmac
import secrets

PBKDF2_ITERATIONS = 200_000
PBKDF2_DIGEST = "sha256"
KEY_PREFIX = "aa_"


def generate_api_key() -> tuple[str, str, str]:
    """Return ``(full_api_key, lookup_prefix, encoded_hash)``."""
    lookup = secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    api_key = f"{KEY_PREFIX}{lookup}.{secret}"
    return api_key, lookup, hash_api_key(api_key)


def api_key_lookup_prefix(api_key: str) -> str | None:
    """Return the public lookup prefix encoded in a modern API key."""
    if not api_key.startswith(KEY_PREFIX):
        return None
    body = api_key[len(KEY_PREFIX):]
    lookup, sep, _secret = body.partition(".")
    if not sep or not lookup:
        return None
    return lookup


def hash_api_key(api_key: str) -> str:
    """Encode an API key with PBKDF2-HMAC for at-rest storage."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        PBKDF2_DIGEST,
        api_key.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return (
        f"pbkdf2_{PBKDF2_DIGEST}${PBKDF2_ITERATIONS}$"
        f"{salt.hex()}${digest.hex()}"
    )


def verify_api_key(api_key: str, encoded_hash: str | None) -> bool:
    """Constant-time verification of an API key against an encoded hash."""
    if not encoded_hash:
        return False
    try:
        method, iterations_text, salt_hex, digest_hex = encoded_hash.split("$", 3)
    except ValueError:
        return False
    if method != f"pbkdf2_{PBKDF2_DIGEST}":
        return False
    try:
        iterations = int(iterations_text)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False

    actual = hashlib.pbkdf2_hmac(
        PBKDF2_DIGEST,
        api_key.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(actual, expected)
