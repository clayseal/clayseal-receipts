"""Tests for pluggable secret encryption providers."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest

from agentauth.backend.secret_encryption import (
    LOCAL_ENC_PREFIX,
    AwsKmsProvider,
    GcpKmsProvider,
    LocalAesGcmProvider,
    decrypt_secret,
    encrypt_secret,
    get_encryption_provider,
    is_encrypted_value,
    secret_encryption_required,
    validate_secret_encryption_config,
)


def test_local_provider_uses_encryption_context():
    provider = LocalAesGcmProvider(
        bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    )
    stored = provider.encrypt(b"secret", context="ctx-a")
    assert provider.decrypt(stored, context="ctx-a") == b"secret"
    with pytest.raises(ValueError, match="decrypt"):
        provider.decrypt(stored, context="ctx-b")


def test_encrypt_secret_roundtrip_with_local_provider():
    stored = encrypt_secret("hello", context="test-context")
    assert is_encrypted_value(stored)
    assert decrypt_secret(stored, context="test-context") == "hello"


def test_decrypt_secret_refuses_plaintext_when_provider_enabled():
    with pytest.raises(ValueError, match="refusing to load plaintext secret"):
        decrypt_secret("plain", context="test-context")


@patch.dict("os.environ", {"AGENTAUTH_SECRET_ENCRYPTION_PROVIDER": "none"}, clear=False)
def test_encrypt_secret_passthrough_when_provider_disabled():
    assert encrypt_secret("plain", context="ctx") == "plain"
    assert decrypt_secret("plain", context="ctx") == "plain"


@patch.dict("os.environ", {"AGENTAUTH_SECRET_ENCRYPTION_PROVIDER": "none"}, clear=False)
def test_decrypt_encrypted_secret_requires_provider():
    stored = f"{LOCAL_ENC_PREFIX}{'00' * 12}$deadbeef"
    with pytest.raises(ValueError, match="requires AGENTAUTH_SECRET_ENCRYPTION_PROVIDER"):
        decrypt_secret(stored, context="ctx")


@pytest.mark.parametrize(
    ("raw_key", "message"),
    [
        ("not-hex", "64-character hex"),
        ("00", "exactly 32 bytes"),
    ],
)
def test_local_master_key_validation(raw_key, message):
    with patch.dict(
        "os.environ",
        {
            "AGENTAUTH_SECRET_ENCRYPTION_PROVIDER": "local",
            "AGENTAUTH_SIGNING_KEY_ENCRYPTION_KEY": raw_key,
        },
        clear=False,
    ):
        with pytest.raises(ValueError, match=message):
            get_encryption_provider()


@patch.dict("os.environ", {"AGENTAUTH_SECRET_ENCRYPTION_PROVIDER": "magic"}, clear=False)
def test_get_encryption_provider_rejects_unknown_provider():
    with pytest.raises(ValueError, match="unsupported"):
        get_encryption_provider()


def test_secret_encryption_required_for_non_sqlite(monkeypatch):
    monkeypatch.delenv("AGENTAUTH_REQUIRE_SECRET_ENCRYPTION", raising=False)
    assert secret_encryption_required("sqlite:///local.db") is False
    assert secret_encryption_required("postgresql://db/agentauth") is True


def test_validate_secret_encryption_config_fails_without_provider(monkeypatch):
    monkeypatch.delenv("AGENTAUTH_SECRET_ENCRYPTION_PROVIDER", raising=False)
    monkeypatch.delenv("AGENTAUTH_SIGNING_KEY_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError, match="secret encryption is required"):
        validate_secret_encryption_config("postgresql://db/agentauth")


@pytest.mark.parametrize(
    ("provider", "env"),
    [
        ("aws_kms", "AGENTAUTH_AWS_KMS_KEY_ID"),
        ("gcp_kms", "AGENTAUTH_GCP_KMS_KEY_NAME"),
    ],
)
def test_kms_provider_requires_key_configuration(provider, env, monkeypatch):
    monkeypatch.setenv("AGENTAUTH_SECRET_ENCRYPTION_PROVIDER", provider)
    monkeypatch.delenv(env, raising=False)
    with pytest.raises(ValueError, match=env):
        get_encryption_provider()


@patch.dict(
    "os.environ",
    {
        "AGENTAUTH_SECRET_ENCRYPTION_PROVIDER": "aws_kms",
        "AGENTAUTH_AWS_KMS_KEY_ID": "arn:aws:kms:us-east-1:1:key/abc",
    },
    clear=False,
)
def test_aws_kms_provider_roundtrip():
    provider = AwsKmsProvider("arn:aws:kms:us-east-1:1:key/abc")
    mock_client = MagicMock()
    plaintext = b"private-key-material"
    ciphertext = b"kms-ciphertext"
    mock_client.encrypt.return_value = {"CiphertextBlob": ciphertext}
    mock_client.decrypt.return_value = {"Plaintext": plaintext}

    with patch.object(provider, "_client", return_value=mock_client):
        stored = provider.encrypt(plaintext, context="signing_ed25519_pem_v1")
        assert stored.startswith("kms_aws_v1$")
        assert provider.decrypt(stored, context="signing_ed25519_pem_v1") == plaintext
        mock_client.encrypt.assert_called_once()
        mock_client.decrypt.assert_called_once()
        assert mock_client.encrypt.call_args.kwargs["EncryptionContext"] == {
            "secret_context": "signing_ed25519_pem_v1"
        }


def test_aws_kms_rejects_wrong_prefix():
    with pytest.raises(ValueError, match="expected kms_aws_v1"):
        AwsKmsProvider("key").decrypt("enc_v1$nonce$ciphertext", context="ctx")


def test_gcp_kms_provider_roundtrip():
    provider = GcpKmsProvider("projects/p/locations/l/keyRings/r/cryptoKeys/k")
    mock_client = MagicMock()
    plaintext = b"private-key-material"
    ciphertext = b"gcp-ciphertext"
    mock_client.encrypt.return_value = MagicMock(ciphertext=ciphertext)
    mock_client.decrypt.return_value = MagicMock(plaintext=plaintext)

    with patch.object(provider, "_client", return_value=mock_client):
        stored = provider.encrypt(plaintext, context="biscuit_root_key_v1")
        assert stored == "kms_gcp_v1$" + base64.b64encode(ciphertext).decode("ascii")
        assert provider.decrypt(stored, context="biscuit_root_key_v1") == plaintext
        encrypt_request = mock_client.encrypt.call_args.kwargs["request"]
        decrypt_request = mock_client.decrypt.call_args.kwargs["request"]
        assert encrypt_request["additional_authenticated_data"] == b"biscuit_root_key_v1"
        assert decrypt_request["additional_authenticated_data"] == b"biscuit_root_key_v1"


def test_gcp_kms_rejects_wrong_prefix():
    with pytest.raises(ValueError, match="expected kms_gcp_v1"):
        GcpKmsProvider("key").decrypt("kms_aws_v1$blob", context="ctx")


@patch.dict("os.environ", {"AGENTAUTH_SECRET_ENCRYPTION_PROVIDER": "none"}, clear=False)
def test_get_encryption_provider_none_when_disabled():
    assert get_encryption_provider() is None
