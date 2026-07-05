"""Runtime configuration, sourced from environment variables with sane defaults.

Everything is overridable via env so tests can point at temp files and a
deployment can point at real infrastructure without code changes.
"""
from __future__ import annotations

import os
from functools import lru_cache


class Settings:
    def __init__(self) -> None:
        self.database_url: str = os.getenv(
            "AGENTAUTH_DATABASE_URL", "sqlite:///./agents.db"
        )
        # The identity event log (issuance / revocation / rotation) is now a
        # hash-chained table in the database above (see backend/audit.py), not a
        # flat file, so there is no separate audit-log path to configure.

        # TTL bounds (seconds). Spec: minimum 5 minutes, maximum 24 hours.
        self.min_ttl_seconds: int = int(os.getenv("AGENTAUTH_MIN_TTL", str(5 * 60)))
        self.max_ttl_seconds: int = int(os.getenv("AGENTAUTH_MAX_TTL", str(24 * 60 * 60)))
        self.default_ttl_seconds: int = int(os.getenv("AGENTAUTH_DEFAULT_TTL", str(60 * 60)))

        # SPIFFE trust domain. Every issued JWT-SVID's subject is a SPIFFE ID
        # under this domain (spiffe://{trust_domain}/customer/{id}/agent/{type}),
        # and it doubles as the JWT issuer (`iss`).
        self.trust_domain: str = os.getenv("AGENTAUTH_TRUST_DOMAIN", "agentauth.io")
        self.jwt_issuer: str = os.getenv("AGENTAUTH_ISSUER", self.trust_domain)
        self.jwt_algorithm: str = "EdDSA"
        # Minimum key size for the prototype node-attestation RSA trust anchor.
        # AgentAuth-issued credentials use Ed25519.
        self.rsa_key_size: int = int(os.getenv("AGENTAUTH_RSA_KEY_SIZE", "2048"))

        # 32-byte hex key for AES-GCM (local) or KMS envelope encryption at rest.
        self.signing_key_encryption_key: str | None = os.getenv(
            "AGENTAUTH_SIGNING_KEY_ENCRYPTION_KEY"
        )
        self.secret_encryption_provider: str = os.getenv(
            "AGENTAUTH_SECRET_ENCRYPTION_PROVIDER", "local"
        )
        self.aws_kms_key_id: str | None = os.getenv("AGENTAUTH_AWS_KMS_KEY_ID")
        self.gcp_kms_key_name: str | None = os.getenv("AGENTAUTH_GCP_KMS_KEY_NAME")

        # CORS: comma-separated allowed origins for the browser dashboard.
        # Defaults to the Vite dev server. Use "*" to allow any origin.
        self.cors_origins: list[str] = [
            o.strip()
            for o in os.getenv(
                "AGENTAUTH_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
            ).split(",")
            if o.strip()
        ]

        # mTLS transport settings — paths to SPIRE-rotated X.509 SVID material in prod.
        self.mtls_enabled: bool = os.getenv("AGENTAUTH_MTLS_ENABLED", "0").lower() in {
            "1", "true", "yes"
        }
        self.tls_cert_file: str | None = os.getenv("AGENTAUTH_TLS_CERT_FILE")
        self.tls_key_file: str | None = os.getenv("AGENTAUTH_TLS_KEY_FILE")
        self.tls_ca_bundle: str | None = os.getenv("AGENTAUTH_TLS_CA_BUNDLE")
        # When True, missing/mismatched cert → 401; False = extract if present, skip if absent.
        self.mtls_strict: bool = os.getenv("AGENTAUTH_MTLS_STRICT", "1").lower() in {
            "1", "true", "yes"
        }
        # Proxy mode: DER cert forwarded as base64 in this header (e.g. by nginx/Envoy).
        # Also used by tests to inject certs without a real TLS handshake.
        self.mtls_client_cert_header: str | None = os.getenv("AGENTAUTH_MTLS_CLIENT_CERT_HEADER")


@lru_cache
def get_settings() -> Settings:
    return Settings()
