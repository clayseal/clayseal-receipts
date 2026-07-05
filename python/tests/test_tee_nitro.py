"""SOTA-2: AWS Nitro TEE attestation verification tests."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import BasicConstraints, KeyUsage, Name, NameAttribute, SubjectKeyIdentifier
from cryptography.x509.oid import NameOID

from agentauth.receipts.assurance import AssuranceLevel, assurance_from_proof
from agentauth.receipts.certificate import dev_certificate
from agentauth.core.hash_util import sha256_hex
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof
from agentauth.receipts.tee import TeeQuote, TeeQuoteFormat, verify_tee_quote
from agentauth.receipts.tee_nitro import verify_nitro_attestation_document


def _build_test_nitro_quote(*, user_data: bytes | None = None) -> tuple[bytes, x509.Certificate]:
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


def test_tdx_quote_remains_explicit_stub():
    quote = TeeQuote(format=TeeQuoteFormat.TDX_V1, quote_b64="deadbeef")
    result = verify_tee_quote(quote)
    assert result["valid"] is False
    assert result["stub"] is True
    assert result["tee_assurance"] == "tee_hybrid_claimed"


def test_nitro_verifier_rejects_garbage():
    result = verify_nitro_attestation_document(b"not-cbor")
    assert result["valid"] is False
    assert result["stub"] is False


def test_nitro_verifier_rejects_report_data_hash_without_user_data():
    document, root = _build_test_nitro_quote()
    result = verify_nitro_attestation_document(
        document,
        report_data_hash="sha256:" + ("ab" * 32),
        root=root,
        max_age_seconds=None,
    )
    assert result["valid"] is False
    assert any("user_data is absent" in reason for reason in result["reasons"])


def test_nitro_verifier_accepts_test_quote_with_test_root():
    document, root = _build_test_nitro_quote()
    result = verify_nitro_attestation_document(document, root=root, max_age_seconds=None)
    assert result["valid"] is True
    assert result["stub"] is False
    assert result["eat"]["sub"] == "test-enclave-module"
    assert result["pcrs"][0] == ("01" * 48)


def test_nitro_verifier_accepts_matching_report_data_hash():
    user_data = b"receipt-binding"
    document, root = _build_test_nitro_quote(user_data=user_data)
    result = verify_nitro_attestation_document(
        document,
        report_data_hash="sha256:" + sha256_hex(user_data),
        root=root,
        max_age_seconds=None,
    )

    assert result["valid"] is True
    assert result["user_data_b64"] == base64.standard_b64encode(user_data).decode("ascii")
    assert result["warnings"] == []


def test_nitro_verifier_rejects_tampered_signature():
    document, root = _build_test_nitro_quote()
    tampered = bytearray(document)
    tampered[-1] ^= 0xFF
    result = verify_nitro_attestation_document(bytes(tampered), root=root, max_age_seconds=None)
    assert result["valid"] is False


def test_assurance_elevates_on_verified_nitro_quote(monkeypatch, tmp_path):
    document, root = _build_test_nitro_quote()
    pem = tmp_path / "test-root.pem"
    pem.write_bytes(root.public_bytes(encoding=Encoding.PEM))
    monkeypatch.setenv("AGENT_RECEIPTS_NITRO_ROOT_PEM", str(pem))

    proof = ExecutionProof.from_action(
        dev_certificate("pol"),
        {"input": {}},
        {"decision": "approve"},
        policy_satisfied=True,
        path=AttestationPath.TEE_HYBRID,
        decision_outcome=DecisionOutcome.ALLOW,
    )
    proof.bundle.tee_quote = TeeQuote(
        format=TeeQuoteFormat.NITRO_ENCLAVE_V1,
        quote_b64=base64.standard_b64encode(document).decode("ascii"),
        max_age_seconds=None,
    ).to_dict()

    summary = assurance_from_proof(proof)
    assert summary.level == AssuranceLevel.TEE_ATTESTED
    assert summary.tee_verified is True
    assert summary.tier.value == "tee_attested"
    assert summary.eat is not None

    check = proof.verify()
    assert check["tee"]["valid"] is True
    assert check["valid"] is True


def test_assurance_stays_claimed_for_invalid_quote(monkeypatch, tmp_path):
    document, root = _build_test_nitro_quote()
    pem = tmp_path / "test-root.pem"
    pem.write_bytes(root.public_bytes(encoding=Encoding.PEM))
    monkeypatch.setenv("AGENT_RECEIPTS_NITRO_ROOT_PEM", str(pem))

    proof = ExecutionProof.from_action(
        dev_certificate("pol"),
        {"input": {}},
        {"decision": "approve"},
        policy_satisfied=True,
        path=AttestationPath.TEE_HYBRID,
        decision_outcome=DecisionOutcome.ALLOW,
    )
    proof.bundle.tee_quote = TeeQuote(
        format=TeeQuoteFormat.NITRO_ENCLAVE_V1,
        quote_b64=base64.standard_b64encode(document[:-4] + b"xxxx").decode("ascii"),
        max_age_seconds=None,
    ).to_dict()

    summary = assurance_from_proof(proof)
    assert summary.level == AssuranceLevel.TEE_HYBRID_CLAIMED
    assert summary.tee_verified is False
    assert summary.tier.value == "signed"
