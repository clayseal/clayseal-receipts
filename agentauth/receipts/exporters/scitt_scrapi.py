"""SCITT exporter: register receipt bundles with any SCRAPI Transparency Service.

Signs the bundle's canonical CBOR (the same payload view
``scitt_bundle.build_scitt_section`` commits to) as an RFC 9943 Signed
Statement, registers it via SCRAPI and returns the RFC 9942 COSE Receipt plus
the combined Transparent Statement. Interop targets include Azure Code
Transparency, DataTrails and self-hosted scitt-ccf-ledger — or our own
verifier server, which mounts the same SCRAPI surface.
"""

from __future__ import annotations

import os
from typing import Any

from agentauth.core.signing import SigningKey

from agentauth.receipts import scitt, scrapi
from agentauth.receipts.scitt_bundle import bundle_to_cbor

BASE_URL_ENV = "AGENTAUTH_SCITT_BASE_URL"
STATEMENT_KEY_ENV = "AGENTAUTH_SCITT_STATEMENT_KEY_HEX"
DEFAULT_ISSUER = "agentauth.receipts"


def _statement_key_from_env() -> SigningKey | None:
    raw = os.getenv(STATEMENT_KEY_ENV, "").strip()
    if not raw:
        return None
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw))
    return SigningKey(private_key=private_key, public_key=private_key.public_key())


class ScittExporter:
    """``ReceiptExporter`` publishing Signed Statements over SCRAPI."""

    name = "scitt"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        signing_key: SigningKey | None = None,
        issuer: str = DEFAULT_ISSUER,
        client: Any | None = None,
        timeout: float = 10.0,
        max_wait: float = 30.0,
    ) -> None:
        self.base_url = base_url if base_url is not None else os.getenv(BASE_URL_ENV, "")
        self.signing_key = signing_key or _statement_key_from_env()
        self.issuer = issuer
        self.client = client
        self.timeout = timeout
        self.max_wait = max_wait

    def export(self, bundle: dict[str, Any], **options: Any) -> dict[str, Any]:
        """Sign + register the bundle. Without a ``base_url`` the statement is
        still built and returned (hex), so callers can register it elsewhere."""
        signing_key = options.get("signing_key") or self.signing_key
        if signing_key is None:
            raise RuntimeError(
                "scitt exporter needs a statement signing key: pass signing_key= or set "
                f"{STATEMENT_KEY_ENV} (32-byte Ed25519 private key hex)"
            )
        issuer = options.get("issuer", self.issuer)
        subject = options.get("subject") or str(
            (bundle.get("execution_proof") or {}).get("proof_id") or "agent-receipt"
        )
        payload = bundle_to_cbor(bundle)
        statement = scitt.sign_statement(payload, signing_key, issuer=issuer, subject=subject)
        result: dict[str, Any] = {
            "exporter": self.name,
            "issuer": issuer,
            "subject": subject,
            "signed_statement": statement.hex(),
            "delivered": False,
        }
        base_url = options.get("base_url", self.base_url)
        if base_url:
            published = scrapi.publish_signed_statement(
                base_url,
                statement,
                client=options.get("client", self.client),
                timeout=options.get("timeout", self.timeout),
                max_wait=options.get("max_wait", self.max_wait),
                headers=options.get("headers"),
            )
            transparent = scitt.transparent_statement(statement, published["receipt"])
            result.update(
                delivered=True,
                entry_id=published["entry_id"],
                location=published["location"],
                receipt=published["receipt"].hex(),
                transparent_statement=transparent.hex(),
            )
        return result
