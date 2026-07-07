"""``AttestationVerifier`` implementations (TEE-evidence seam, BYO audit).

The canonical result shape is an EAT/JWT-style claims dict, which makes
verifiers interchangeable evidence sources for receipt bundles:

- :class:`NitroAttestationVerifier` — AWS Nitro Enclave attestation documents,
  validated against the Nitro root CA (wraps :mod:`agentauth.receipts.tee_nitro`).
- :class:`EatJwtAttestationVerifier` — the managed-verifier pattern every other
  cloud converged on: Azure MAA, Intel Trust Authority/Tiber and Google Cloud
  Attestation all emit signed JWT/EAT tokens discoverable via JWKS. One
  JWKS-based verifier covers all of them.

Registered under the ``agentauth.attestation_verifiers`` entry-point group
(``nitro``, ``eat_jwt``); third-party verifiers plug in the same way.
"""

from __future__ import annotations

import base64
import os
from typing import Any

from agentauth.receipts.tee import TeeQuote, tee_verification_to_eat, verify_tee_quote

JWKS_URL_ENV = "AGENTAUTH_ATTESTATION_JWKS_URL"
ISSUER_ENV = "AGENTAUTH_ATTESTATION_ISSUER"
AUDIENCE_ENV = "AGENTAUTH_ATTESTATION_AUDIENCE"

# The RS/ES/PS families managed verifiers actually sign with (MAA: RS256,
# ITA: PS384, GCP: RS256). No EdDSA — see the identity-layer crypto matrix.
DEFAULT_JWT_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "PS384")


class NitroAttestationVerifier:
    """Verify AWS Nitro Enclave attestation documents into EAT-shaped claims."""

    name = "nitro"

    def verify(
        self,
        evidence: bytes | str | dict[str, Any],
        *,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        context = context or {}
        if isinstance(evidence, dict):
            quote = TeeQuote.from_dict(evidence)
        else:
            document = (
                base64.standard_b64decode(evidence.encode("ascii"))
                if isinstance(evidence, str)
                else bytes(evidence)
            )
            quote = TeeQuote(
                format="nitro_enclave_v1",  # type: ignore[arg-type]
                quote_b64=base64.standard_b64encode(document).decode("ascii"),
                report_data_hash=context.get("report_data_hash"),
                max_age_seconds=context.get("max_age_seconds", 86400),
            )
        result = verify_tee_quote(quote)
        if not result.get("valid"):
            reasons = "; ".join(str(r) for r in result.get("reasons", [])) or "invalid evidence"
            raise ValueError(f"nitro attestation rejected: {reasons}")
        claims = tee_verification_to_eat(result)
        claims["tee_verification"] = result
        return claims


class EatJwtAttestationVerifier:
    """Verify EAT/JWT attestation tokens from managed verifiers (MAA/ITA/GCP…).

    Keys resolve from (in order) ``context["public_key"]`` (PEM),
    ``context["jwks"]`` (an RFC 7517 JWKS dict), or the configured
    ``jwks_url`` via PyJWT's ``PyJWKClient``. ``issuer`` / ``audience`` are
    enforced when configured.
    """

    name = "eat_jwt"

    def __init__(
        self,
        *,
        jwks_url: str | None = None,
        issuer: str | None = None,
        audience: str | None = None,
        algorithms: tuple[str, ...] = DEFAULT_JWT_ALGORITHMS,
    ) -> None:
        self.jwks_url = jwks_url or os.getenv(JWKS_URL_ENV, "")
        self.issuer = issuer or os.getenv(ISSUER_ENV, "") or None
        self.audience = audience or os.getenv(AUDIENCE_ENV, "") or None
        self.algorithms = list(algorithms)

    def _resolve_key(self, token: str, context: dict[str, Any]) -> Any:
        import jwt

        if context.get("public_key") is not None:
            return context["public_key"]
        jwks = context.get("jwks")
        if jwks is not None:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            keys = jwks.get("keys", [])
            # A token with no 'kid' is only unambiguous against a single-key JWKS; with
            # multiple keys, refuse rather than silently trusting the first entry.
            if kid is None:
                if len(keys) == 1:
                    return jwt.PyJWK(keys[0]).key
                raise ValueError(
                    "token has no 'kid' and the JWKS has multiple keys; cannot select "
                    "a signing key unambiguously"
                )
            for entry in keys:
                if entry.get("kid") == kid:
                    return jwt.PyJWK(entry).key
            raise ValueError(f"no JWKS key matches kid {kid!r}")
        if self.jwks_url:
            from agentauth.core.safe_http import safe_http_get_json

            jwks = safe_http_get_json(self.jwks_url, timeout=10.0)
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            keys = jwks.get("keys", [])
            if kid is None:
                if len(keys) == 1:
                    return jwt.PyJWK(keys[0]).key
                raise ValueError(
                    "token has no 'kid' and the JWKS has multiple keys; cannot select "
                    "a signing key unambiguously"
                )
            for entry in keys:
                if entry.get("kid") == kid:
                    return jwt.PyJWK(entry).key
            raise ValueError(f"no JWKS key matches kid {kid!r}")
        raise ValueError(
            "eat_jwt verifier has no key source: pass context['public_key'] / "
            f"context['jwks'] or configure {JWKS_URL_ENV}"
        )

    def verify(
        self,
        evidence: bytes | str | dict[str, Any],
        *,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        import jwt

        context = context or {}
        if isinstance(evidence, dict):
            raise ValueError("eat_jwt verifier expects a compact JWT string")
        token = evidence.decode("ascii") if isinstance(evidence, bytes) else str(evidence)

        # Fail closed on the insecure-by-default case: verifying against a *remote* JWKS
        # (no pinned key in context) with no issuer configured would accept any token
        # that JWKS can sign, from any issuer. Require a pinned issuer for that path.
        uses_remote_jwks = (
            context.get("public_key") is None
            and context.get("jwks") is None
            and bool(self.jwks_url)
        )
        if uses_remote_jwks and not self.issuer:
            raise ValueError(
                f"eat_jwt verifier resolving keys from a remote JWKS ({JWKS_URL_ENV}) "
                f"must pin an issuer ({ISSUER_ENV}); otherwise it would accept tokens "
                "from any signer in that key set."
            )
        if uses_remote_jwks and not self.audience:
            from agentauth.core.production import is_production

            if is_production():
                raise ValueError(
                    f"eat_jwt verifier resolving keys from a remote JWKS ({JWKS_URL_ENV}) "
                    f"must pin an audience ({AUDIENCE_ENV}) in production"
                )

        key = self._resolve_key(token, context)
        options = {"verify_aud": self.audience is not None}
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=self.algorithms,
                issuer=self.issuer,
                audience=self.audience,
                options=options,
            )
        except jwt.PyJWTError as exc:
            raise ValueError(f"attestation token rejected: {exc}") from exc
        return dict(claims)


# Default instances advertised via the plugin entry points, so
# get_plugin("attestation_verifiers", ...) hands consumers a ready verifier.
# Construct the classes directly to configure jwks_url / issuer / audience.
NITRO_VERIFIER = NitroAttestationVerifier()
EAT_JWT_VERIFIER = EatJwtAttestationVerifier()
