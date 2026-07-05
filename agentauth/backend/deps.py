"""Shared FastAPI dependencies."""
from __future__ import annotations

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .api_keys import api_key_lookup_prefix, hash_api_key, verify_api_key
from .config import get_settings
from .db import get_db
from .errors import InvalidAPIKeyError, InvalidTokenError
from .models import Customer


def get_current_customer(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> Customer:
    """Resolve the calling tenant from the ``X-API-Key`` header."""
    if not x_api_key:
        raise InvalidAPIKeyError(
            "Missing X-API-Key header.",
            suggestion="Send your AgentAuth API key in the 'X-API-Key' header.",
        )
    lookup = api_key_lookup_prefix(x_api_key)
    candidates: list[Customer] = []
    if lookup is not None:
        candidates = list(db.scalars(select(Customer).where(Customer.api_key == lookup)).all())
    if not candidates:
        legacy = db.scalar(select(Customer).where(Customer.api_key == x_api_key))
        if legacy is not None:
            if legacy.api_key_hash and verify_api_key(x_api_key, legacy.api_key_hash):
                return legacy
            if legacy.api_key_hash:
                raise InvalidAPIKeyError(
                    "API key is not recognised.",
                    suggestion="Double-check the key from your AgentAuth dashboard.",
                )
            legacy.api_key_hash = hash_api_key(x_api_key)
            legacy.api_key = lookup or legacy.id[:16]
            db.add(legacy)
            db.commit()
            db.refresh(legacy)
            return legacy
    for customer in candidates:
        if verify_api_key(x_api_key, customer.api_key_hash):
            return customer
    raise InvalidAPIKeyError(
        "API key is not recognised.",
        suggestion="Double-check the key from your AgentAuth dashboard.",
    )


def verify_mtls_binding(request: Request, claims: dict | None = None) -> None:
    """When mTLS is enabled, verify the client cert's public key matches the token's cnf.jkt.

    Reuses keyhash_for_pem from agentauth.workload_keys — same thumbprint scheme as PoP.
    Gracefully degrades (no-op) when mtls_enabled is False.
    """
    settings = get_settings()
    if not settings.mtls_enabled:
        return

    cert_der: bytes | None = getattr(request.state, "client_cert_der", None)
    if cert_der is None:
        if settings.mtls_strict:
            raise InvalidTokenError(
                "mTLS client certificate is required but was not presented.",
                suggestion=(
                    "Configure your client with the SPIRE-managed X.509 SVID "
                    "as the mTLS client certificate."
                ),
            )
        return

    from .mtls import cert_public_key_pem
    from agentauth.workload_keys import keyhash_for_pem

    try:
        cert_keyhash = keyhash_for_pem(cert_public_key_pem(cert_der))
    except Exception as exc:
        raise InvalidTokenError(
            "mTLS client certificate public key could not be extracted.",
            suggestion="Ensure the client certificate is a valid X.509 cert.",
        ) from exc

    expected = (claims or {}).get("cnf", {}).get("jkt")
    if expected and cert_keyhash != expected:
        raise InvalidTokenError(
            "mTLS client certificate public key does not match the token's bound key (cnf.jkt).",
            suggestion=(
                "The presented client certificate does not correspond to the workload key "
                "that was bound to this credential."
            ),
        )
