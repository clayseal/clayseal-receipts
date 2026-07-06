"""SCRAPI Transparency Service surface + publish client (Phase 3 BYO audit)."""

from __future__ import annotations

import pytest

pytest.importorskip("starlette")
cbor2 = pytest.importorskip("cbor2")

from agentauth.core.signing import generate_keypair  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from agentauth.receipts import scitt, scrapi  # noqa: E402
from agentauth.receipts.verifier_server import (  # noqa: E402
    _reset_transparency_service,
    create_app,
)


@pytest.fixture
def client() -> TestClient:
    _reset_transparency_service()
    return TestClient(create_app())


def _statement(payload: bytes = b"receipt-claim") -> bytes:
    key = generate_keypair()
    return scitt.sign_statement(payload, key, issuer="issuer.example", subject="agent-42")


def _service_public_key(client: TestClient) -> Ed25519PublicKey:
    response = client.get(scrapi.SCITT_KEYS_PATH)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(scrapi.MEDIA_CBOR)
    keys = cbor2.loads(response.content)
    assert isinstance(keys, (list, tuple)) and len(keys) == 1
    key = keys[0]
    assert key[1] == 1  # kty: OKP
    assert key[3] == -8  # alg: EdDSA
    assert key[-1] == 6  # crv: Ed25519
    return Ed25519PublicKey.from_public_bytes(key[-2])


def test_register_returns_201_with_verifiable_receipt(client: TestClient):
    stmt = _statement()
    response = client.post(
        "/entries", content=stmt, headers={"Content-Type": scrapi.MEDIA_COSE}
    )
    assert response.status_code == 201
    assert response.headers["content-type"].startswith(scrapi.MEDIA_COSE)
    entry_id = scrapi.entry_id_for_statement(stmt)
    assert response.headers["location"] == f"/entries/{entry_id}"
    assert scitt.verify_receipt(stmt, response.content, _service_public_key(client))


def test_reregistration_is_idempotent(client: TestClient):
    stmt = _statement()
    first = client.post("/entries", content=stmt, headers={"Content-Type": scrapi.MEDIA_COSE})
    second = client.post("/entries", content=stmt, headers={"Content-Type": scrapi.MEDIA_COSE})
    assert first.headers["location"] == second.headers["location"]
    service_key = _service_public_key(client)
    assert scitt.verify_receipt(stmt, second.content, service_key)
    # Registering the same statement twice did not grow the log.
    other = _statement(payload=b"other")
    client.post("/entries", content=other, headers={"Content-Type": scrapi.MEDIA_COSE})
    _p, unprotected, _payload, _sig = cbor2.loads(client.post(
        "/entries", content=other, headers={"Content-Type": scrapi.MEDIA_COSE}
    ).content).value
    tree_size, _index, _path = cbor2.loads(unprotected[396][-1][0])
    assert tree_size == 2


def test_resolve_receipt_stays_fresh_as_log_grows(client: TestClient):
    stmt = _statement()
    location = client.post(
        "/entries", content=stmt, headers={"Content-Type": scrapi.MEDIA_COSE}
    ).headers["location"]
    for i in range(3):
        client.post(
            "/entries",
            content=_statement(payload=f"s{i}".encode()),
            headers={"Content-Type": scrapi.MEDIA_COSE},
        )
    response = client.get(location)
    assert response.status_code == 200
    # The fresh receipt proves inclusion under the *current* (size-4) root.
    assert scitt.verify_receipt(stmt, response.content, _service_public_key(client))


def test_resolve_unknown_entry_returns_404_problem_details(client: TestClient):
    response = client.get("/entries/deadbeef")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith(scrapi.MEDIA_PROBLEM)
    problem = scrapi.decode_problem_details(response.content)
    assert problem["title"] == "Not Found"


def test_register_rejects_wrong_content_type(client: TestClient):
    response = client.post(
        "/entries", content=_statement(), headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert scrapi.decode_problem_details(response.content)["title"] == "Unsupported Content Type"


def test_register_rejects_non_cose_body(client: TestClient):
    response = client.post(
        "/entries", content=b"not cbor at all", headers={"Content-Type": scrapi.MEDIA_COSE}
    )
    assert response.status_code == 400
    assert scrapi.decode_problem_details(response.content)["title"] == "Invalid Signed Statement"


def test_register_rejects_statement_without_issuer(client: TestClient):
    key = generate_keypair()
    # Hand-rolled COSE_Sign1 with no CWT Claims header.
    protected = cbor2.dumps({1: -8, 4: key.key_id.encode()})
    sig = key.private_key.sign(cbor2.dumps(["Signature1", protected, b"", b"payload"]))
    stmt = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, b"payload", sig]))
    response = client.post(
        "/entries", content=stmt, headers={"Content-Type": scrapi.MEDIA_COSE}
    )
    assert response.status_code == 400
    assert scrapi.decode_problem_details(response.content)["title"] == "Issuer Missing"


# --- publish client -------------------------------------------------------- #


def test_publish_signed_statement_against_own_service(client: TestClient):
    stmt = _statement()
    result = scrapi.publish_signed_statement("http://testserver", stmt, client=client)
    assert result["entry_id"] == scrapi.entry_id_for_statement(stmt)
    assert scitt.verify_receipt(stmt, result["receipt"], _service_public_key(client))
    # The receipt embeds into a Transparent Statement any SCITT party can check.
    transparent = scitt.transparent_statement(stmt, result["receipt"])
    assert scitt.verify_transparent_statement(transparent, _service_public_key(client))


def test_publish_raises_scrapi_error_with_problem_details(client: TestClient):
    with pytest.raises(scrapi.ScrapiError) as excinfo:
        scrapi.publish_signed_statement("http://testserver", b"garbage", client=client)
    assert excinfo.value.status == 400
    assert excinfo.value.title == "Invalid Signed Statement"


class _Response:
    def __init__(self, status_code: int, *, content: bytes = b"", headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}


class _AsyncRegistrationService:
    """Fake SCRAPI service: 202 on POST, then 204 (pending) and finally 200."""

    def __init__(self, receipt: bytes):
        self.receipt = receipt
        self.polls = 0

    def post(self, url, *, content=None, headers=None):
        return _Response(
            202, headers={"Location": "/entries/abc123", "Retry-After": "0"}
        )

    def get(self, url, *, headers=None):
        assert url.endswith("/entries/abc123")
        self.polls += 1
        if self.polls < 3:
            return _Response(204, headers={"Retry-After": "0"})
        return _Response(200, content=self.receipt)


def test_publish_polls_202_flow_until_receipt():
    fake = _AsyncRegistrationService(receipt=b"receipt-bytes")
    result = scrapi.publish_signed_statement(
        "https://ts.example", _statement(), client=fake, max_wait=5.0
    )
    assert result == {
        "entry_id": "abc123",
        "receipt": b"receipt-bytes",
        "location": "https://ts.example/entries/abc123",
    }
    assert fake.polls == 3
