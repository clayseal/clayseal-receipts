"""Pluggable at-rest secret encryption for signing and capability root keys."""

from __future__ import annotations

import base64
import os
import secrets
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOCAL_ENC_PREFIX = "enc_v1$"
AWS_KMS_PREFIX = "kms_aws_v1$"
GCP_KMS_PREFIX = "kms_gcp_v1$"

PROVIDER_ENV = "AGENTAUTH_SECRET_ENCRYPTION_PROVIDER"
LOCAL_MASTER_KEY_ENV = "AGENTAUTH_SIGNING_KEY_ENCRYPTION_KEY"
AWS_KMS_KEY_ID_ENV = "AGENTAUTH_AWS_KMS_KEY_ID"
GCP_KMS_KEY_NAME_ENV = "AGENTAUTH_GCP_KMS_KEY_NAME"
REQUIRE_ENCRYPTION_ENV = "AGENTAUTH_REQUIRE_SECRET_ENCRYPTION"


class SecretEncryptionProvider(Protocol):
    def encrypt(self, plaintext: bytes, *, context: str) -> str: ...
    def decrypt(self, stored: str, *, context: str) -> bytes: ...


def encryption_enabled() -> bool:
    return get_encryption_provider() is not None


def _env_truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def secret_encryption_required(database_url: str | None = None) -> bool:
    """Return whether private key encryption must be configured for this process."""
    if _env_truthy(REQUIRE_ENCRYPTION_ENV):
        return True
    if database_url is None:
        return False
    return not database_url.startswith("sqlite")


def validate_secret_encryption_config(database_url: str | None = None) -> None:
    """Fail startup when durable/non-local stores would persist private keys in plaintext."""
    if not secret_encryption_required(database_url):
        return
    if get_encryption_provider() is None:
        raise RuntimeError(
            "secret encryption is required for this database configuration; set "
            f"{PROVIDER_ENV}=local with {LOCAL_MASTER_KEY_ENV}, or configure aws_kms/gcp_kms"
        )


def is_encrypted_value(stored: str) -> bool:
    return (
        stored.startswith(LOCAL_ENC_PREFIX)
        or stored.startswith(AWS_KMS_PREFIX)
        or stored.startswith(GCP_KMS_PREFIX)
    )


def get_encryption_provider() -> SecretEncryptionProvider | None:
    name = os.getenv(PROVIDER_ENV, "local").strip().lower()
    if name in ("", "none", "off", "disabled"):
        return None
    if name == "local":
        key = _local_master_key()
        return LocalAesGcmProvider(key) if key is not None else None
    if name == "aws_kms":
        key_id = os.getenv(AWS_KMS_KEY_ID_ENV, "").strip()
        if not key_id:
            raise ValueError(f"{AWS_KMS_KEY_ID_ENV} is required when {PROVIDER_ENV}=aws_kms")
        return AwsKmsProvider(key_id)
    if name == "gcp_kms":
        key_name = os.getenv(GCP_KMS_KEY_NAME_ENV, "").strip()
        if not key_name:
            raise ValueError(f"{GCP_KMS_KEY_NAME_ENV} is required when {PROVIDER_ENV}=gcp_kms")
        return GcpKmsProvider(key_name)
    raise ValueError(f"unsupported {PROVIDER_ENV}={name!r}; expected local, aws_kms, or gcp_kms")


def _local_master_key() -> bytes | None:
    raw = os.getenv(LOCAL_MASTER_KEY_ENV, "").strip()
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError(
            f"{LOCAL_MASTER_KEY_ENV} must be a 64-character hex-encoded 32-byte key."
        ) from exc
    if len(key) != 32:
        raise ValueError(f"{LOCAL_MASTER_KEY_ENV} must decode to exactly 32 bytes.")
    return key


class LocalAesGcmProvider:
    def __init__(self, master_key: bytes) -> None:
        self._master_key = master_key

    def encrypt(self, plaintext: bytes, *, context: str) -> str:
        nonce = secrets.token_bytes(12)
        aad = context.encode("utf-8")
        ciphertext = AESGCM(self._master_key).encrypt(nonce, plaintext, aad)
        return f"{LOCAL_ENC_PREFIX}{nonce.hex()}${ciphertext.hex()}"

    def decrypt(self, stored: str, *, context: str) -> bytes:
        if not stored.startswith(LOCAL_ENC_PREFIX):
            raise ValueError("expected local enc_v1 secret")
        _prefix, payload = stored.split(LOCAL_ENC_PREFIX, 1)
        nonce_hex, ciphertext_hex = payload.split("$", 1)
        aad = context.encode("utf-8")
        try:
            return AESGCM(self._master_key).decrypt(
                bytes.fromhex(nonce_hex),
                bytes.fromhex(ciphertext_hex),
                aad,
            )
        except (ValueError, TypeError, InvalidTag) as exc:
            raise ValueError("failed to decrypt local secret") from exc


class AwsKmsProvider:
    def __init__(self, key_id: str) -> None:
        self._key_id = key_id

    def _client(self):
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError(
                "boto3 is required when AGENTAUTH_SECRET_ENCRYPTION_PROVIDER=aws_kms"
            ) from exc
        return boto3.client("kms")

    def encrypt(self, plaintext: bytes, *, context: str) -> str:
        response = self._client().encrypt(
            KeyId=self._key_id,
            Plaintext=plaintext,
            EncryptionContext={"secret_context": context},
        )
        blob = base64.b64encode(response["CiphertextBlob"]).decode("ascii")
        return f"{AWS_KMS_PREFIX}{blob}"

    def decrypt(self, stored: str, *, context: str) -> bytes:
        if not stored.startswith(AWS_KMS_PREFIX):
            raise ValueError("expected kms_aws_v1 secret")
        blob = base64.b64decode(stored[len(AWS_KMS_PREFIX) :])
        response = self._client().decrypt(
            CiphertextBlob=blob,
            EncryptionContext={"secret_context": context},
        )
        return response["Plaintext"]


class GcpKmsProvider:
    def __init__(self, key_name: str) -> None:
        self._key_name = key_name

    def _client(self):
        try:
            from google.cloud import kms
        except ImportError as exc:
            raise RuntimeError(
                "google-cloud-kms is required when AGENTAUTH_SECRET_ENCRYPTION_PROVIDER=gcp_kms"
            ) from exc
        return kms.KeyManagementServiceClient()

    def encrypt(self, plaintext: bytes, *, context: str) -> str:
        client = self._client()
        response = client.encrypt(
            request={
                "name": self._key_name,
                "plaintext": plaintext,
                "additional_authenticated_data": context.encode("utf-8"),
            }
        )
        blob = base64.b64encode(response.ciphertext).decode("ascii")
        return f"{GCP_KMS_PREFIX}{blob}"

    def decrypt(self, stored: str, *, context: str) -> bytes:
        if not stored.startswith(GCP_KMS_PREFIX):
            raise ValueError("expected kms_gcp_v1 secret")
        blob = base64.b64decode(stored[len(GCP_KMS_PREFIX) :])
        client = self._client()
        response = client.decrypt(
            request={
                "name": self._key_name,
                "ciphertext": blob,
                "additional_authenticated_data": context.encode("utf-8"),
            }
        )
        return response.plaintext


def encrypt_secret(plaintext: str, *, context: str) -> str:
    provider = get_encryption_provider()
    if provider is None:
        return plaintext
    return provider.encrypt(plaintext.encode("utf-8"), context=context)


def decrypt_secret(stored: str, *, context: str) -> str:
    provider = get_encryption_provider()
    if not is_encrypted_value(stored):
        if provider is not None:
            raise ValueError("refusing to load plaintext secret while secret encryption is enabled")
        return stored
    if provider is None:
        raise ValueError(f"encrypted secret requires {PROVIDER_ENV} to decrypt")
    return provider.decrypt(stored, context=context).decode("utf-8")
