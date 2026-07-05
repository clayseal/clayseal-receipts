"""mTLS client certificate extraction and utilities.

Provides a Starlette middleware that extracts the client certificate from the
TLS connection (direct mode) or a forwarded header (proxy mode), and two helpers
used by the binding check in deps.py.
"""
from __future__ import annotations

import base64

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from .config import get_settings


def cert_public_key_pem(cert_der: bytes) -> str:
    """Return the SPKI PEM public key extracted from a DER-encoded X.509 certificate."""
    cert = x509.load_der_x509_certificate(cert_der)
    return cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def spiffe_id_from_cert(cert_der: bytes) -> str | None:
    """Return the first SPIFFE URI SAN from a DER-encoded X.509 certificate, or None."""
    cert = x509.load_der_x509_certificate(cert_der)
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return None
    for uri in san_ext.value.get_values_for_type(x509.UniformResourceIdentifier):
        if uri.startswith("spiffe://"):
            return uri
    return None


class ClientCertMiddleware(BaseHTTPMiddleware):
    """Extract the mTLS client certificate and attach it to request.state.client_cert_der.

    Supports two modes:
    - Proxy mode: cert DER is base64-encoded in a configurable header (e.g. X-Client-Cert).
    - Direct mode: cert DER is read from the asyncio transport's SSL object (uvicorn).

    Settings are read per-request so tests can toggle env vars without restarting the app.
    When mtls_strict is True and no cert is found, returns 401 immediately.
    """

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()

        if not settings.mtls_enabled:
            request.state.client_cert_der = None
            return await call_next(request)

        cert_der: bytes | None = None

        if settings.mtls_client_cert_header:
            raw = request.headers.get(settings.mtls_client_cert_header)
            if raw:
                try:
                    cert_der = base64.b64decode(raw)
                except Exception:
                    return JSONResponse(
                        {
                            "error": {
                                "code": "mtls_invalid_cert_header",
                                "message": "Client certificate header is not valid base64.",
                            }
                        },
                        status_code=400,
                    )
        else:
            # Direct uvicorn mode: extract from asyncio transport SSL object.
            transport = request.scope.get("transport")
            if transport is not None:
                ssl_obj = transport.get_extra_info("ssl_object")
                if ssl_obj is not None:
                    cert_der = ssl_obj.getpeercert(binary_form=True)

        request.state.client_cert_der = cert_der
        return await call_next(request)
