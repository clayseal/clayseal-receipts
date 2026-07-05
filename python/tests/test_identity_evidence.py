"""Identity authenticity: the embedded JWT-SVID is verified and its claims are bound
to the receipt authority block, so identity swaps fail (L1/L2 ↔ L4 seam)."""

from __future__ import annotations

import copy
import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from agentauth.receipts.identity_evidence import build_identity_section, identity_issues

SPIFFE = "spiffe://agentauth.io/customer/abc/agent/worker"
ISSUER = "agentauth.io"
CNF_JKT = "3UcNDmQrPwJxHfuLnKVAqVZHsdehssx7VccJKGBfz_U"


def _signed_bundle() -> dict:
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode()
    jwk = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "k1", "use": "sig", "alg": "EdDSA"})
    # exp and expires_at must denote the same instant (EV-101b binds them).
    exp_epoch = 1893456000  # 2030-01-01T00:00:00Z
    token = jwt.encode(
        {"iss": ISSUER, "sub": SPIFFE, "cnf": {"jkt": CNF_JKT}, "exp": exp_epoch},
        private_pem,
        algorithm="EdDSA",
        headers={"kid": "k1"},
    )
    credential = {
        "token": token,
        "spiffe_id": SPIFFE,
        "bound_keyhash": CNF_JKT,
        "expires_at": "2030-01-01T00:00:00Z",
    }
    section = build_identity_section(credential, {"keys": [jwk]})
    authority = {
        "workload_principal": SPIFFE,
        "subject_id": SPIFFE,
        "issuer": ISSUER,
        "presenter_key_hash": CNF_JKT,
    }
    return {"identity": section, "authority": authority}


def test_valid_identity_evidence_has_no_issues():
    assert identity_issues(_signed_bundle()) == []


def test_no_identity_section_is_noop():
    assert identity_issues({"authority": {"issuer": "x"}}) == []


def test_corrupted_svid_signature_fails():
    bundle = _signed_bundle()
    token = bundle["identity"]["jwt_svid"]
    bundle["identity"]["jwt_svid"] = token[:-6] + "AAAAAA"
    codes = [issue.code.value for issue in identity_issues(bundle)]
    assert "signature_invalid" in codes


@pytest.mark.parametrize(
    "path",
    ["workload_principal", "subject_id", "issuer", "presenter_key_hash"],
)
def test_swapping_a_bound_authority_field_fails(path):
    bundle = _signed_bundle()
    bundle["authority"][path] = "tampered-value"
    codes = [issue.code.value for issue in identity_issues(bundle)]
    assert "authority_mismatch" in codes, f"{path} swap not caught"


def test_extending_stated_expiry_is_caught():
    """EV-101b: the credential's displayed expiry is bound to the signed SVID exp, so
    an attacker can't make an expired credential look long-lived."""
    bundle = _signed_bundle()
    bundle["identity"]["expires_at"] = "2099-01-01T00:00:00Z"
    codes = [issue.code.value for issue in identity_issues(bundle)]
    assert "authority_mismatch" in codes


def test_swapping_svid_for_another_subject_fails():
    """An attacker who substitutes a *validly signed* SVID for a different agent is
    caught because its sub no longer matches the (proof-bound) authority block."""
    legit = _signed_bundle()
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode()
    jwk = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "k1", "use": "sig", "alg": "EdDSA"})
    other = jwt.encode(
        {"iss": ISSUER, "sub": "spiffe://agentauth.io/customer/abc/agent/evil",
         "cnf": {"jkt": CNF_JKT}, "exp": 9999999999},
        private_pem, algorithm="EdDSA", headers={"kid": "k1"},
    )
    bundle = copy.deepcopy(legit)
    bundle["identity"]["jwt_svid"] = other
    bundle["identity"]["issuer_jwks"] = {"keys": [jwk]}
    codes = [issue.code.value for issue in identity_issues(bundle)]
    assert "authority_mismatch" in codes
