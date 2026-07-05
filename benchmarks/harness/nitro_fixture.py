"""Test Nitro attestation document builder for synthetic assurance cases."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import BasicConstraints, KeyUsage, Name, NameAttribute, SubjectKeyIdentifier
from cryptography.x509.oid import NameOID


def build_test_nitro_quote(*, user_data: bytes | None = None) -> tuple[bytes, x509.Certificate]:
    root_key = ec.generate_private_key(ec.SECP384R1())
    intermediate_key = ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.now(timezone.utc)

    def _cert(
        subject: str,
        issuer: str,
        public_key,
        signing_key,
        *,
        ca: bool,
        digital_signature: bool,
    ) -> x509.Certificate:
        builder = (
            x509.CertificateBuilder()
            .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(Name([NameAttribute(NameOID.COMMON_NAME, issuer)]))
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(BasicConstraints(ca=ca, path_length=None), critical=True)
            .add_extension(
                KeyUsage(
                    digital_signature=digital_signature,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=ca,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )
        if ca:
            builder = builder.add_extension(
                SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
        return builder.sign(signing_key, hashes.SHA384())

    root = _cert(
        "test.nitro-enclaves",
        "test.nitro-enclaves",
        root_key.public_key(),
        root_key,
        ca=True,
        digital_signature=False,
    )
    intermediate = _cert(
        "test.nitro-signing",
        "test.nitro-enclaves",
        intermediate_key.public_key(),
        root_key,
        ca=True,
        digital_signature=False,
    )
    leaf = _cert(
        "test.enclave",
        "test.nitro-signing",
        leaf_key.public_key(),
        intermediate_key,
        ca=False,
        digital_signature=True,
    )

    pcr0 = b"\x01" * 48
    doc = {
        "module_id": "test-enclave-module",
        "timestamp": int(now.timestamp() * 1000),
        "digest": "SHA384",
        "pcrs": {0: pcr0, 1: b"\x02" * 48},
        "certificate": leaf.public_bytes(encoding=Encoding.DER),
        "cabundle": [
            root.public_bytes(encoding=Encoding.DER),
            intermediate.public_bytes(encoding=Encoding.DER),
        ],
    }
    if user_data is not None:
        doc["user_data"] = user_data

    payload = cbor2.dumps(doc)
    protected = cbor2.dumps({1: -35})
    sig_input = cbor2.dumps(["Signature1", protected, b"", payload])
    der_sig = leaf_key.sign(sig_input, ec.ECDSA(hashes.SHA384()))
    r, s = decode_dss_signature(der_sig)
    size = (leaf_key.curve.key_size + 7) // 8
    raw_sig = r.to_bytes(size, "big") + s.to_bytes(size, "big")
    cose = cbor2.dumps([protected, {}, payload, raw_sig])
    return cose, root


_PROCESS_NITRO_ROOT: Path | None = None
_PROCESS_NITRO_QUOTE: bytes | None = None


def process_nitro_assets() -> tuple[Path, bytes]:
    """Stable test Nitro root + quote for the benchmark process."""
    global _PROCESS_NITRO_ROOT, _PROCESS_NITRO_QUOTE
    if _PROCESS_NITRO_ROOT is None or _PROCESS_NITRO_QUOTE is None:
        document, root = build_test_nitro_quote()
        directory = Path(tempfile.mkdtemp(prefix="bench-nitro-root-"))
        pem_path = directory / "root.pem"
        pem_path.write_bytes(root.public_bytes(encoding=Encoding.PEM))
        os.environ["AGENT_RECEIPTS_NITRO_ROOT_PEM"] = str(pem_path)
        _PROCESS_NITRO_ROOT = pem_path
        _PROCESS_NITRO_QUOTE = document
    return _PROCESS_NITRO_ROOT, _PROCESS_NITRO_QUOTE


def process_nitro_root_pem() -> Path:
    root, _document = process_nitro_assets()
    return root


def process_nitro_quote_bytes() -> bytes:
    _root, document = process_nitro_assets()
    return document


def write_test_nitro_root_pem(path: Path) -> Path:
    _document, root = build_test_nitro_quote()
    path.write_bytes(root.public_bytes(encoding=Encoding.PEM))
    return path
