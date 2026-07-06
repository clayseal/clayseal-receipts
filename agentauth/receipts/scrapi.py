"""SCRAPI: the HTTP face of SCITT (draft-ietf-scitt-scrapi, RFC-editor queue).

Two directions, per the BYO-audit seam:

- **Serve**: :mod:`agentauth.receipts.verifier_server` mounts the SCRAPI
  resources (``POST /entries``, ``GET /entries/{entry_id}``,
  ``GET /.well-known/scitt-keys``) over :class:`agentauth.receipts.scitt.TransparencyService`,
  so any SCITT-aware client can register Signed Statements with us and obtain
  RFC 9942 COSE Receipts.
- **Publish**: :func:`publish_signed_statement` registers one of *our* Signed
  Statements with any external SCITT Transparency Service (Azure Code
  Transparency, DataTrails, scitt-ccf-ledger, …), handling the 201-direct and
  202-poll registration flows.

Wire details tracked from draft-ietf-scitt-scrapi-11 (June 2026): media types
``application/cose`` (statements, receipts), ``application/cbor`` (COSE Key
Sets), and RFC 9290 ``application/concise-problem-details+cbor`` errors with
``title`` (-1) / ``detail`` (-2).
"""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Iterable
from typing import Any
from urllib.parse import urljoin

import cbor2
from agentauth.core.signing import SigningKey, generate_keypair

from agentauth.receipts import scitt

MEDIA_COSE = "application/cose"
MEDIA_CBOR = "application/cbor"
MEDIA_PROBLEM = "application/concise-problem-details+cbor"
SCITT_KEYS_PATH = "/.well-known/scitt-keys"

SERVICE_ID_ENV = "AGENTAUTH_SCITT_SERVICE_ID"
SIGNING_KEY_ENV = "AGENTAUTH_SCITT_SIGNING_KEY_HEX"
DEFAULT_SERVICE_ID = "agentauth-receipts.verifier/log"

# RFC 9290 concise-problem-details standard keys.
_PROBLEM_TITLE = -1
_PROBLEM_DETAIL = -2

# COSE_Key labels (RFC 9052 §7 / RFC 9053).
_KTY = 1
_KID = 2
_KEY_ALG = 3
_KTY_OKP = 1
_ALG_EDDSA = -8
_CRV = -1
_CRV_ED25519 = 6
_X = -2


def entry_id_for_statement(signed_statement: bytes) -> str:
    """Stable EntryID for a Signed Statement: sha256 hex of its bytes."""
    return hashlib.sha256(signed_statement).hexdigest()


def problem_details(title: str, detail: str) -> bytes:
    """RFC 9290 concise problem details, CBOR-encoded."""
    return cbor2.dumps({_PROBLEM_TITLE: title, _PROBLEM_DETAIL: detail})


def decode_problem_details(data: bytes) -> dict[str, str]:
    try:
        decoded = cbor2.loads(data)
        return {
            "title": str(decoded.get(_PROBLEM_TITLE, "")),
            "detail": str(decoded.get(_PROBLEM_DETAIL, "")),
        }
    except (cbor2.CBORError, AttributeError, ValueError):
        return {"title": "", "detail": data[:200].decode("utf-8", "replace")}


def cose_key_set(keys: Iterable[SigningKey]) -> bytes:
    """COSE Key Set (RFC 9052 §7) for ``/.well-known/scitt-keys``: array of COSE_Keys."""
    key_set = [
        {
            _KTY: _KTY_OKP,
            _KID: key.key_id.encode("ascii"),
            _KEY_ALG: _ALG_EDDSA,
            _CRV: _CRV_ED25519,
            _X: key.public_key.public_bytes_raw(),
        }
        for key in keys
    ]
    return cbor2.dumps(key_set)


def load_service_signing_key() -> SigningKey:
    """The Transparency Service signing key: pinned via env, else ephemeral.

    Set ``AGENTAUTH_SCITT_SIGNING_KEY_HEX`` (raw Ed25519 private key, 32-byte
    hex) so receipts stay verifiable across restarts; without it a fresh key is
    generated per process (fine for tests/dev, useless for production trust).
    """
    raw = os.getenv(SIGNING_KEY_ENV, "").strip()
    if raw:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw))
        return SigningKey(private_key=private_key, public_key=private_key.public_key())
    return generate_keypair()


def service_id_from_env() -> str:
    return os.getenv(SERVICE_ID_ENV, "").strip() or DEFAULT_SERVICE_ID


class RegistrationRejected(ValueError):
    """A Signed Statement failed the syntactic registration checks (→ 400)."""

    def __init__(self, title: str, detail: str) -> None:
        super().__init__(f"{title}: {detail}")
        self.title = title
        self.detail = detail


def check_registration_policy(signed_statement: bytes) -> dict[str, Any]:
    """Minimal syntactic registration policy (RFC 9943 §5.2).

    The statement must parse as COSE_Sign1, declare an algorithm, carry CWT
    Claims (label 15) with a non-empty Issuer, and identify its key (``kid``).
    Cryptographic trust in the *issuer* stays with relying parties — a
    transparency log proves inclusion, not issuer authorization.
    """
    try:
        claims = scitt.statement_claims(signed_statement)
    except (ValueError, cbor2.CBORError, TypeError) as exc:
        raise RegistrationRejected(
            "Invalid Signed Statement", f"body is not a COSE_Sign1: {exc}"
        ) from exc
    if claims.get("alg") is None:
        raise RegistrationRejected(
            "Bad Signature Algorithm", "Signed Statement declared no algorithm"
        )
    if not claims.get("issuer"):
        raise RegistrationRejected(
            "Issuer Missing", "Signed Statement carries no CWT Claims issuer (label 15/1)"
        )
    if not claims.get("kid"):
        raise RegistrationRejected(
            "Key Identifier Missing", "Signed Statement protected header carries no kid (label 4)"
        )
    return claims


class ScrapiError(RuntimeError):
    """A SCRAPI registration failed (non-2xx or timed out while polling)."""

    def __init__(self, message: str, *, status: int | None = None,
                 title: str = "", detail: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.title = title
        self.detail = detail


def _raise_for_problem(status: int, content: bytes, context: str) -> None:
    problem = decode_problem_details(content)
    raise ScrapiError(
        f"{context} failed with HTTP {status}: "
        f"{problem['title'] or 'error'} — {problem['detail']}",
        status=status,
        title=problem["title"],
        detail=problem["detail"],
    )


def publish_signed_statement(
    base_url: str,
    signed_statement: bytes,
    *,
    client: Any | None = None,
    timeout: float = 10.0,
    max_wait: float = 30.0,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Register a Signed Statement with any SCRAPI Transparency Service.

    Handles both registration flows: ``201`` (receipt in the response body) and
    ``202`` (poll the ``Location`` resource until ``200``, honoring
    ``Retry-After``, for at most ``max_wait`` seconds).

    Returns ``{"entry_id", "receipt", "location"}`` where ``receipt`` is the
    RFC 9942 COSE Receipt bytes. ``client`` accepts any httpx-compatible
    client (e.g. Starlette's ``TestClient``) — one is created when omitted.
    """
    import httpx

    own_client = client is None
    http = client or httpx.Client(timeout=timeout)
    request_headers = {"Content-Type": MEDIA_COSE, "Accept": MEDIA_COSE, **(headers or {})}
    try:
        response = http.post(
            urljoin(base_url.rstrip("/") + "/", "entries"),
            content=signed_statement,
            headers=request_headers,
        )
        location = urljoin(base_url, response.headers.get("location", ""))
        if response.status_code == 201:
            return {
                "entry_id": location.rsplit("/", 1)[-1]
                or entry_id_for_statement(signed_statement),
                "receipt": response.content,
                "location": location,
            }
        if response.status_code != 202:
            _raise_for_problem(response.status_code, response.content, "SCRAPI registration")

        if not response.headers.get("location"):
            raise ScrapiError("SCRAPI 202 response carried no Location header", status=202)
        deadline = time.monotonic() + max_wait
        while True:
            delay = float(response.headers.get("retry-after", 1) or 1)
            if time.monotonic() + delay > deadline:
                raise ScrapiError(
                    f"receipt not ready within {max_wait}s at {location}", status=202
                )
            time.sleep(delay)
            response = http.get(location, headers={"Accept": MEDIA_COSE})
            if response.status_code == 200:
                return {
                    "entry_id": location.rsplit("/", 1)[-1],
                    "receipt": response.content,
                    "location": location,
                }
            if response.status_code != 204:
                _raise_for_problem(response.status_code, response.content, "SCRAPI receipt poll")
    finally:
        if own_client:
            http.close()
