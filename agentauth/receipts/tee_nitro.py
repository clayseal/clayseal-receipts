"""AWS Nitro Enclaves attestation document verification (SOTA-2)."""

from __future__ import annotations

import base64
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ObjectIdentifier

COSE_ALG_ES384 = -35
COSE_SIG_STRUCTURE = "Signature1"
NITRO_DIGEST_SHA384 = "SHA384"


class NitroAttestationError(Exception):
    """Attestation document failed validation."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_nitro_root_pem_path() -> Path:
    env = os.environ.get("AGENT_RECEIPTS_NITRO_ROOT_PEM")
    if env:
        return Path(env)
    return _repo_root() / "config" / "certs" / "aws_nitro_enclaves_root_g1.pem"


def load_nitro_root_certificate() -> x509.Certificate:
    path = default_nitro_root_pem_path()
    if not path.is_file():
        raise NitroAttestationError(
            f"AWS Nitro root certificate not found at {path}; "
            "download from https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"
        )
    return x509.load_pem_x509_certificate(path.read_bytes())


def _decode_cose_sign1(document: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    try:
        cose = cbor2.loads(document)
    except cbor2.CBORError as exc:
        raise NitroAttestationError(f"invalid COSE/CBOR attestation document: {exc}") from exc
    if not isinstance(cose, list) or len(cose) != 4:
        raise NitroAttestationError("COSE_Sign1 must be a 4-element CBOR array")
    protected, _unprotected, payload, signature = cose
    if not isinstance(protected, bytes):
        raise NitroAttestationError("COSE protected headers must be bytes")
    if not isinstance(payload, bytes):
        raise NitroAttestationError("COSE payload must be bytes")
    if not isinstance(signature, bytes):
        raise NitroAttestationError("COSE signature must be bytes")
    return protected, payload, signature


def _certificate_validity(cert: x509.Certificate, now: datetime) -> None:
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if not_before > now:
        raise NitroAttestationError(f"certificate not yet valid: {cert.subject}")
    if not_after < now:
        raise NitroAttestationError(f"certificate expired: {cert.subject}")


def _cose_algorithm(protected: bytes) -> int:
    try:
        headers = cbor2.loads(protected)
    except cbor2.CBORError as exc:
        raise NitroAttestationError(f"invalid COSE protected headers: {exc}") from exc
    if not isinstance(headers, dict) or 1 not in headers:
        raise NitroAttestationError("COSE protected headers missing algorithm")
    return int(headers[1])


def _raw_ecdsa_der(signature: bytes, key_size_bits: int) -> bytes:
    size = (key_size_bits + 7) // 8
    if len(signature) != size * 2:
        raise NitroAttestationError("invalid raw ECDSA signature length")
    r = int.from_bytes(signature[:size], "big")
    s = int.from_bytes(signature[size:], "big")
    return encode_dss_signature(r, s)


def _verify_cose_signature(
    protected: bytes,
    payload: bytes,
    signature: bytes,
    public_key: ec.EllipticCurvePublicKey | rsa.RSAPublicKey,
) -> None:
    sig_input = cbor2.dumps([COSE_SIG_STRUCTURE, protected, b"", payload])
    algorithm = _cose_algorithm(protected)
    if algorithm != COSE_ALG_ES384:
        raise NitroAttestationError(f"unsupported COSE algorithm {algorithm}; expected ES384")
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise NitroAttestationError("Nitro attestation leaf certificate must use EC keys")
    der_sig = _raw_ecdsa_der(signature, public_key.curve.key_size)
    try:
        public_key.verify(der_sig, sig_input, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature as exc:
        raise NitroAttestationError("COSE signature verification failed") from exc


def _validate_attestation_document(doc: dict[str, Any]) -> None:
    required = ("module_id", "digest", "timestamp", "pcrs", "certificate", "cabundle")
    for key in required:
        if key not in doc or doc[key] is None:
            raise NitroAttestationError(f"attestation document missing required field {key!r}")
    if not isinstance(doc["module_id"], str) or not doc["module_id"]:
        raise NitroAttestationError("module_id must be a non-empty string")
    if doc["digest"] != NITRO_DIGEST_SHA384:
        raise NitroAttestationError(f"unsupported attestation digest {doc['digest']!r}")
    timestamp = doc["timestamp"]
    if not isinstance(timestamp, int) or timestamp <= 0:
        raise NitroAttestationError("timestamp must be a positive integer")
    pcrs = doc["pcrs"]
    if not isinstance(pcrs, dict) or not pcrs:
        raise NitroAttestationError("pcrs must be a non-empty map")
    for index, value in pcrs.items():
        if not isinstance(index, int) or index < 0 or index >= 32:
            raise NitroAttestationError(f"invalid PCR index {index!r}")
        if not isinstance(value, bytes) or len(value) not in {32, 48, 64}:
            raise NitroAttestationError(f"invalid PCR value length for index {index}")
    cabundle = doc["cabundle"]
    if not isinstance(cabundle, list) or not cabundle:
        raise NitroAttestationError("cabundle must be a non-empty array")
    certificate = doc["certificate"]
    if not isinstance(certificate, bytes) or not certificate:
        raise NitroAttestationError("certificate must be non-empty DER bytes")


def _load_certificates(
    doc: dict[str, Any],
) -> tuple[x509.Certificate, list[x509.Certificate], x509.Certificate]:
    leaf = x509.load_der_x509_certificate(doc["certificate"])
    cabundle = [
        x509.load_der_x509_certificate(item)
        for item in doc["cabundle"]
        if isinstance(item, bytes) and item
    ]
    if not cabundle:
        raise NitroAttestationError("cabundle must contain at least the root certificate")
    root = cabundle[0]
    intermediates = list(reversed(cabundle[1:]))
    return leaf, intermediates, root


def _verify_basic_constraints(cert: x509.Certificate, *, is_ca: bool) -> None:
    try:
        bc = cert.extensions.get_extension_for_oid(
            ObjectIdentifier("2.5.29.19")
        ).value
    except x509.ExtensionNotFound as exc:
        raise NitroAttestationError(
            f"certificate missing basic constraints: {cert.subject}"
        ) from exc
    if bc.ca != is_ca:
        raise NitroAttestationError(f"unexpected CA flag on certificate {cert.subject}")


def _verify_key_usage(cert: x509.Certificate, *, require: set[str]) -> None:
    try:
        usage = cert.extensions.get_extension_for_oid(
            ObjectIdentifier("2.5.29.15")
        ).value
    except x509.ExtensionNotFound as exc:
        raise NitroAttestationError(f"certificate missing key usage: {cert.subject}") from exc
    mapping = {
        "digital_signature": usage.digital_signature,
        "key_cert_sign": usage.key_cert_sign,
    }
    for name in require:
        if not mapping.get(name):
            raise NitroAttestationError(f"certificate missing key usage {name}: {cert.subject}")


def _verify_signed_by(child: x509.Certificate, issuer: x509.Certificate) -> None:
    public_key = issuer.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,  # type: ignore[arg-type]
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),  # type: ignore[arg-type]
            )
        else:
            raise NitroAttestationError("unsupported issuer public key type")
    except InvalidSignature as exc:
        raise NitroAttestationError(
            f"certificate chain break: {child.subject} not signed by {issuer.subject}"
        ) from exc


def _verify_certificate_chain(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    root: x509.Certificate,
    *,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(timezone.utc)
    chain = [leaf, *intermediates, root]
    for cert in chain:
        _certificate_validity(cert, now)

    _verify_basic_constraints(leaf, is_ca=False)
    _verify_key_usage(leaf, require={"digital_signature"})

    for cert in intermediates:
        _verify_basic_constraints(cert, is_ca=True)
        _verify_key_usage(cert, require={"key_cert_sign"})

    _verify_basic_constraints(root, is_ca=True)
    _verify_key_usage(root, require={"key_cert_sign"})

    ordered = [leaf, *intermediates]
    for index, cert in enumerate(ordered):
        issuer = intermediates[index] if index < len(intermediates) else root
        _verify_signed_by(cert, issuer)

    if leaf.issuer != (intermediates[0].subject if intermediates else root.subject):
        raise NitroAttestationError("leaf issuer does not match certificate chain")


def _pcrs_hex(doc: dict[str, Any]) -> dict[int, str]:
    pcrs = doc.get("pcrs", {})
    return {int(k): v.hex() for k, v in pcrs.items() if isinstance(v, bytes)}


def _check_user_data_binding(
    doc: dict[str, Any],
    report_data_hash: str | None,
) -> list[str]:
    warnings: list[str] = []
    if not report_data_hash:
        return warnings
    user_data = doc.get("user_data")
    if not isinstance(user_data, bytes):
        raise NitroAttestationError(
            "report_data_hash provided but attestation user_data is absent"
        )
    from agentauth.core.hash_util import sha256_hex

    actual = sha256_hex(user_data)
    expected = report_data_hash.removeprefix("sha256:")
    if actual != expected and user_data.hex() != expected:
        raise NitroAttestationError("attestation user_data does not match report_data_hash")
    return warnings


def attestation_to_eat_claims(
    doc: dict[str, Any],
    *,
    module_id: str,
    timestamp_ms: int,
    pcrs: dict[int, str],
) -> dict[str, Any]:
    """Map a verified Nitro attestation document to an EAT-shaped claim set."""
    pcr0 = pcrs.get(0)
    return {
        "iss": "aws.nitro-enclaves",
        "sub": module_id,
        "iat": datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc).isoformat(),
        "eat_profile": "agent-receipts.eat-tee-v1",
        "ver": "1.0.0",
        "cnf": {"tee.kind": "aws-nitro-enclave"},
        "meas": {"pcr0": pcr0} if pcr0 else {},
        "pcrs": {str(k): v for k, v in pcrs.items()},
        "digest_alg": doc.get("digest"),
    }


def verify_nitro_attestation_document(
    document: bytes,
    *,
    report_data_hash: str | None = None,
    max_age_seconds: int | None = 86400,
    root: x509.Certificate | None = None,
) -> dict[str, Any]:
    """
    Verify an AWS Nitro Enclaves COSE_Sign1 attestation document.

    Returns a dict with ``valid=True``, PCR measurements, and EAT-shaped claims.
    """
    reasons: list[str] = []
    warnings: list[str] = []
    try:
        protected, payload, signature = _decode_cose_sign1(document)
        doc = cbor2.loads(payload)
        if not isinstance(doc, dict):
            raise NitroAttestationError("attestation payload must be a CBOR map")
        _validate_attestation_document(doc)
        leaf, intermediates, bundle_root = _load_certificates(doc)
        trusted_root = root or load_nitro_root_certificate()
        if bundle_root.subject != trusted_root.subject or bundle_root.public_bytes(
            encoding=Encoding.DER
        ) != trusted_root.public_bytes(encoding=Encoding.DER):
            raise NitroAttestationError(
                "attestation cabundle root does not match trusted Nitro root"
            )
        _verify_certificate_chain(leaf, intermediates, trusted_root)
        public_key = leaf.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise NitroAttestationError("leaf certificate must contain an EC public key")
        _verify_cose_signature(protected, payload, signature, public_key)
        warnings.extend(_check_user_data_binding(doc, report_data_hash))

        timestamp_ms = int(doc["timestamp"])
        if max_age_seconds is not None:
            age = datetime.now(timezone.utc).timestamp() - (timestamp_ms / 1000)
            if age > max_age_seconds:
                raise NitroAttestationError(
                    f"attestation timestamp is older than {max_age_seconds}s"
                )
            if age < -300:
                raise NitroAttestationError("attestation timestamp is in the future")

        pcrs = _pcrs_hex(doc)
        module_id = str(doc["module_id"])
        eat = attestation_to_eat_claims(
            doc,
            module_id=module_id,
            timestamp_ms=timestamp_ms,
            pcrs=pcrs,
        )
        if pcrs.get(0) == "00" * 96:
            warnings.append("pcr0 is all zeros: enclave may be in debug mode")

        return {
            "valid": True,
            "stub": False,
            "format": "nitro_enclave_v1",
            "module_id": module_id,
            "timestamp_ms": timestamp_ms,
            "pcrs": pcrs,
            "digest": doc.get("digest"),
            "public_key_b64": (
                base64.standard_b64encode(doc["public_key"]).decode("ascii")
                if isinstance(doc.get("public_key"), bytes)
                else None
            ),
            "user_data_b64": (
                base64.standard_b64encode(doc["user_data"]).decode("ascii")
                if isinstance(doc.get("user_data"), bytes)
                else None
            ),
            "eat": eat,
            "reasons": reasons,
            "warnings": warnings,
        }
    except NitroAttestationError as exc:
        return {
            "valid": False,
            "stub": False,
            "format": "nitro_enclave_v1",
            "reasons": [str(exc)],
            "warnings": warnings,
        }
