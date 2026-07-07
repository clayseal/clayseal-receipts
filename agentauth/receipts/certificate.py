from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.signing import SigningKey, load_or_create_key, verify

TRUSTED_CERTIFICATE_ISSUER_PUBLIC_KEYS_ENV = "AGENT_RECEIPTS_TRUSTED_CERTIFICATE_ISSUER_PUBLIC_KEYS"
TRUSTED_CERTIFICATE_ISSUER_KEY_IDS_ENV = "AGENT_RECEIPTS_TRUSTED_CERTIFICATE_ISSUER_KEY_IDS"
ALLOW_UNSIGNED_CERTIFICATE_ENV = "AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE"
CERTIFICATE_ISSUER_KEY_PATH_ENV = "AGENT_RECEIPTS_CERTIFICATE_ISSUER_KEY_PATH"
REQUIRE_KEY_ENCRYPTION_ENV = "AGENT_RECEIPTS_REQUIRE_KEY_ENCRYPTION"


def _split_env_list(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def _env_truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def trusted_certificate_issuer_policy_from_env() -> dict[str, set[str]]:
    return {
        "public_keys": _split_env_list(TRUSTED_CERTIFICATE_ISSUER_PUBLIC_KEYS_ENV),
        "key_ids": _split_env_list(TRUSTED_CERTIFICATE_ISSUER_KEY_IDS_ENV),
    }


def certificate_signing_document(certificate: AgentCertificate) -> dict[str, Any]:
    """Canonical certificate payload signed by the issuer (excludes signature field)."""
    document = certificate.to_dict()
    document.pop("issuer_signature", None)
    return document


def sign_certificate(certificate: AgentCertificate, key: SigningKey) -> AgentCertificate:
    """Return a copy of ``certificate`` with an Ed25519 issuer signature descriptor."""
    document = certificate_signing_document(certificate)
    return replace(certificate, issuer_signature=key.sign(document))


def load_managed_certificate_issuer_key(
    explicit_path: str | Path | None = None,
) -> SigningKey | None:
    """Load the configured certificate issuer key, if one is configured."""
    path = explicit_path or os.environ.get(CERTIFICATE_ISSUER_KEY_PATH_ENV, "").strip() or None
    if path is None:
        return None
    return load_or_create_key(
        path,
        require_encryption=_env_truthy(REQUIRE_KEY_ENCRYPTION_ENV),
    )


def sign_with_managed_issuer(
    certificate: AgentCertificate,
    *,
    issuer_key_path: str | Path | None = None,
) -> AgentCertificate:
    """Sign ``certificate`` with the configured issuer key when available."""
    if certificate.issuer_signature is not None:
        return certificate
    key = load_managed_certificate_issuer_key(issuer_key_path)
    if key is None:
        return certificate
    return sign_certificate(certificate, key)


def verify_certificate_issuer(certificate: AgentCertificate) -> list[str]:
    """Return violations for certificate issuer signature and trust policy."""
    trust = trusted_certificate_issuer_policy_from_env()
    trust_configured = bool(trust["public_keys"] or trust["key_ids"])
    signature = certificate.issuer_signature

    if signature is None:
        if trust_configured:
            return ["certificate is unsigned"]
        if os.environ.get(ALLOW_UNSIGNED_CERTIFICATE_ENV, "0") == "1":
            return []
        return ["certificate is unsigned"]

    if not isinstance(signature, dict):
        return ["certificate issuer_signature must be an Ed25519 signature descriptor"]

    document = certificate_signing_document(certificate)
    if not verify(document, signature):
        return ["certificate issuer signature is invalid"]

    if trust_configured:
        public_key = signature.get("public_key")
        key_id = signature.get("key_id")
        trusted = (isinstance(public_key, str) and public_key in trust["public_keys"]) or (
            isinstance(key_id, str) and key_id in trust["key_ids"]
        )
        if not trusted:
            return ["certificate issuer is not from a trusted key"]

    return []


@dataclass
class PrincipalRef:
    principal_id: str
    organization: str
    scope: list[str] = field(default_factory=list)


@dataclass
class AgentCertificate:
    agent_id: UUID
    model_provenance_hash: str
    policy_commitment: str
    principal: PrincipalRef
    not_before: datetime
    not_after: datetime
    issuer_signature: dict[str, str] | None = None

    def is_valid_at(self, at: datetime | None = None) -> bool:
        at = at or datetime.now(timezone.utc)
        return self.not_before <= at < self.not_after

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": str(self.agent_id),
            "model_provenance_hash": self.model_provenance_hash,
            "policy_commitment": self.policy_commitment,
            "principal": {
                "principal_id": self.principal.principal_id,
                "organization": self.principal.organization,
                "scope": self.principal.scope,
            },
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "issuer_signature": self.issuer_signature,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> AgentCertificate:
        p = raw["principal"]
        sig = raw.get("issuer_signature")
        issuer_signature: dict[str, str] | None
        if sig is None:
            issuer_signature = None
        elif isinstance(sig, dict):
            issuer_signature = {str(key): str(value) for key, value in sig.items()}
        else:
            raise TypeError("issuer_signature must be an Ed25519 signature descriptor dict or null")
        return cls(
            agent_id=UUID(raw["agent_id"]),
            model_provenance_hash=raw["model_provenance_hash"],
            policy_commitment=raw["policy_commitment"],
            principal=PrincipalRef(
                principal_id=p["principal_id"],
                organization=p["organization"],
                scope=list(p.get("scope", [])),
            ),
            not_before=datetime.fromisoformat(raw["not_before"]),
            not_after=datetime.fromisoformat(raw["not_after"]),
            issuer_signature=issuer_signature,
        )


def load_certificate(path: str | Path) -> AgentCertificate:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return AgentCertificate.from_dict(raw)


def save_certificate(path: str | Path, certificate: AgentCertificate) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps(certificate.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return dest


def load_or_create_partner_certificate(
    path: str | Path,
    *,
    policy_commitment: str,
    model_hash: str,
    organization: str,
    principal_id: str,
    scope: list[str] | None = None,
    days_valid: int = 90,
    issuer_key_path: str | Path | None = None,
) -> AgentCertificate:
    """
    Load stable agent certificate from disk, or create and persist a new one.

    Raises ValueError if an existing certificate's policy_commitment does not match.
    """
    dest = Path(path)
    if dest.is_file():
        cert = load_certificate(dest)
        if cert.policy_commitment != policy_commitment:
            raise ValueError(
                f"certificate at {dest} has policy_commitment {cert.policy_commitment!r} "
                f"but policy requires {policy_commitment!r}; issue a new cert after policy change"
            )
        if cert.model_provenance_hash != model_hash:
            raise ValueError(
                f"certificate model_provenance_hash mismatch at {dest}; "
                "update certificate after model upgrade"
            )
        return cert

    cert = dev_certificate(
        policy_commitment,
        model_hash=model_hash,
        organization=organization,
        principal_id=principal_id,
        scope=scope,
        days_valid=days_valid,
    )
    cert = sign_with_managed_issuer(cert, issuer_key_path=issuer_key_path)
    save_certificate(dest, cert)
    return cert


def dev_certificate(
    policy_commitment: str,
    *,
    model_hash: str = "sha256:model-dev-v1",
    organization: str = "dev-org",
    principal_id: str = "dev-principal",
    scope: list[str] | None = None,
    days_valid: int = 30,
) -> AgentCertificate:
    """Development certificate — not PKI-signed."""
    now = datetime.now(timezone.utc)
    return AgentCertificate(
        agent_id=uuid4(),
        model_provenance_hash=model_hash,
        policy_commitment=policy_commitment,
        principal=PrincipalRef(
            principal_id=principal_id,
            organization=organization,
            scope=scope or ["agent.run"],
        ),
        not_before=now,
        not_after=now + timedelta(days=days_valid),
    )


def certificate_ref_hash(certificate: AgentCertificate) -> str:
    return hash_canonical_json(certificate.to_dict())
