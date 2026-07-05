"""SCITT / C2SP bundle integration (SOTA-11 + SOTA-14).

Embeds COSE Signed Statements, COSE Receipts, C2SP checkpoints, optional HPKE
confidential payloads, and CBOR-canonical artifacts into receipt bundles.
"""

from __future__ import annotations

from typing import Any

import hashlib

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentauth.receipts import c2sp, hpke, scitt
from agentauth.receipts.audit import AuditChain
from agentauth.core.signing import SigningKey

DEFAULT_SCITT_SERVICE_ID = "agent-receipts.local/log"
DEFAULT_C2SP_ORIGIN = "agent-receipts.local/audit"


def bundle_without_scitt(bundle: dict[str, Any]) -> dict[str, Any]:
    """Receipt JSON with the ``scitt`` section removed (canonical signed payload view)."""
    return {key: value for key, value in bundle.items() if key != "scitt"}


def bundle_to_cbor(bundle: dict[str, Any], *, exclude_scitt: bool = True) -> bytes:
    """Canonical CBOR encoding of a receipt bundle."""
    payload = bundle_without_scitt(bundle) if exclude_scitt else dict(bundle)
    return cbor2.dumps(payload, canonical=True)


def bundle_from_cbor(data: bytes) -> dict[str, Any]:
    """Decode a canonical CBOR receipt bundle."""
    value = cbor2.loads(data)
    if not isinstance(value, dict):
        raise ValueError("CBOR receipt bundle must decode to a map")
    return value


def bundle_cbor_hex(bundle: dict[str, Any]) -> str:
    return bundle_to_cbor(bundle).hex()


def build_scitt_section(
    bundle: dict[str, Any],
    *,
    issuer_key: SigningKey,
    issuer: str,
    subject: str,
    audit_chain: AuditChain | None = None,
    service_id: str = DEFAULT_SCITT_SERVICE_ID,
    c2sp_origin: str = DEFAULT_C2SP_ORIGIN,
    confidential_recipient_public_key: bytes | None = None,
    confidential_info: bytes = b"agent-receipts/confidential/v1",
    confidential_aad: bytes = b"",
    mandate_section: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the ``scitt`` section for a receipt bundle.

    The signed statement covers the canonical CBOR of the bundle (excluding ``scitt``).
    When ``audit_chain`` is supplied and the bundle carries ``audit_record``, a COSE
    Receipt proves the record hash is included in the log's RFC 6962 tree. An optional
    HPKE seal encrypts the same CBOR for confidential distribution (SOTA-9 / SOTA-16).
    """
    cbor_bytes = bundle_to_cbor(bundle)
    section: dict[str, Any] = {
        "service_id": service_id,
        "issuer": issuer,
        "subject": subject,
        "issuer_public_key": issuer_key.public_key_hex,
        "cbor_sha256": hashlib.sha256(cbor_bytes).hexdigest(),
        "cbor_hex": cbor_bytes.hex(),
        "signed_statement": scitt.sign_statement(
            cbor_bytes, issuer_key, issuer=issuer, subject=subject
        ).hex(),
    }

    if confidential_recipient_public_key is not None:
        if mandate_section is not None:
            from agentauth.capabilities.mandate import mandated_hpke_recipient_bytes

            fake_bundle = {"mandate": mandate_section}
            mandated = mandated_hpke_recipient_bytes(fake_bundle)
            if mandated is not None and mandated != confidential_recipient_public_key:
                raise ValueError(
                    "confidential_recipient_public_key does not match mandate owner_hpke_pk"
                )
        enc, ciphertext = hpke.seal_base(
            confidential_recipient_public_key,
            cbor_bytes,
            info=confidential_info,
            aad=confidential_aad,
        )
        section["confidential"] = {
            "enc": enc.hex(),
            "ciphertext": ciphertext.hex(),
            "info": confidential_info.hex(),
            "aad": confidential_aad.hex(),
            "recipient_public_key": confidential_recipient_public_key.hex(),
        }

    audit_record = bundle.get("audit_record")
    if audit_chain is not None and isinstance(audit_record, dict):
        record_hash = audit_record.get("record_hash")
        if isinstance(record_hash, str) and record_hash:
            if audit_chain.signing_key is None:
                raise ValueError("audit_chain signing key required for SCITT receipts")
            receipt = audit_chain.scitt_receipt(record_hash, service_id=service_id)
            section["service_public_key"] = audit_chain.signing_key.public_key_hex
            section["audit_inclusion_receipt"] = receipt.hex()
            section["c2sp_checkpoint"] = audit_chain.c2sp_checkpoint(c2sp_origin)
            section["c2sp_origin"] = c2sp_origin
            section["audit_log_tiles_origin"] = c2sp_origin

    return section


def open_confidential_payload(
    section: dict[str, Any],
    recipient_private_key,
) -> bytes:
    """HPKE-open the confidential CBOR payload from a ``scitt`` section."""
    sealed = section.get("confidential")
    if not isinstance(sealed, dict):
        raise ValueError("scitt section has no confidential payload")
    enc = bytes.fromhex(str(sealed["enc"]))
    ciphertext = bytes.fromhex(str(sealed["ciphertext"]))
    info = bytes.fromhex(str(sealed.get("info", "")))
    aad = bytes.fromhex(str(sealed.get("aad", "")))
    return hpke.open_base(enc, recipient_private_key, ciphertext, info=info, aad=aad)


def scitt_section_issues(bundle: dict[str, Any]) -> list[str]:
    """Validate the optional ``scitt`` section against the JSON bundle."""
    section = bundle.get("scitt")
    if not isinstance(section, dict):
        return []

    issues: list[str] = []

    confidential = section.get("confidential")
    if isinstance(confidential, dict):
        recipient_hex = confidential.get("recipient_public_key")
        mandated = mandated_hpke_recipient_bytes(bundle)
        if mandated is not None:
            if not isinstance(recipient_hex, str):
                issues.append(
                    "scitt confidential payload requires recipient_public_key "
                    "bound in mandate owner_hpke_pk"
                )
            elif bytes.fromhex(recipient_hex) != mandated:
                issues.append(
                    "scitt confidential recipient_public_key does not match "
                    "mandate owner_hpke_pk"
                )

    signed_hex = section.get("signed_statement")
    issuer_pk_hex = section.get("issuer_public_key")
    if not isinstance(signed_hex, str) or not isinstance(issuer_pk_hex, str):
        issues.append("scitt section missing signed_statement or issuer_public_key")
        return issues

    try:
        issuer_pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(issuer_pk_hex))
        payload = scitt.verify_statement(bytes.fromhex(signed_hex), issuer_pk)
    except (ValueError, TypeError):
        issues.append("scitt signed statement is malformed")
        return issues
    if payload is None:
        issues.append("scitt signed statement signature is invalid")
        return issues

    expected_cbor = bundle_to_cbor(bundle)
    if payload != expected_cbor:
        issues.append("scitt signed statement payload does not match canonical bundle CBOR")

    cbor_hex = section.get("cbor_hex")
    if isinstance(cbor_hex, str) and bytes.fromhex(cbor_hex) != expected_cbor:
        issues.append("scitt.cbor_hex does not match canonical bundle CBOR")

    audit_record = bundle.get("audit_record")
    receipt_hex = section.get("audit_inclusion_receipt")
    service_pk_hex = section.get("service_public_key")
    if receipt_hex is not None:
        if not isinstance(audit_record, dict):
            issues.append("scitt audit inclusion receipt requires audit_record")
        else:
            record_hash = audit_record.get("record_hash")
            if not isinstance(record_hash, str) or not record_hash:
                issues.append("audit_record.record_hash required for scitt audit receipt")
            elif not isinstance(service_pk_hex, str):
                issues.append("scitt.service_public_key required with audit_inclusion_receipt")
            else:
                try:
                    service_pk = Ed25519PublicKey.from_public_bytes(
                        bytes.fromhex(service_pk_hex)
                    )
                    ok = scitt.verify_receipt(
                        bytes.fromhex(record_hash),
                        bytes.fromhex(receipt_hex),
                        service_pk,
                    )
                except (ValueError, TypeError):
                    ok = False
                if not ok:
                    issues.append(
                        "scitt audit inclusion receipt does not verify for audit_record"
                    )

    checkpoint = section.get("c2sp_checkpoint")
    origin = section.get("c2sp_origin")
    if isinstance(checkpoint, str) and isinstance(origin, str) and service_pk_hex:
        try:
            service_pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(service_pk_hex))
            if not c2sp.verify_note(checkpoint, origin, service_pk):
                issues.append("scitt c2sp checkpoint signature is invalid")
        except (ValueError, TypeError):
            issues.append("scitt c2sp checkpoint is malformed")

    return issues


def mandated_hpke_recipient_bytes(bundle: dict[str, Any]) -> bytes | None:
    from agentauth.capabilities.mandate import mandated_hpke_recipient_bytes as _from_mandate

    return _from_mandate(bundle)
