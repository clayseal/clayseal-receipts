"""Focused attestation selector and failure-path tests."""
from __future__ import annotations

import pytest

from agentauth.backend.attestation import derive_workload_selectors, verify_node_attestation
from agentauth.backend.db import SessionLocal
from agentauth.backend.errors import AttestationDeniedError
from agentauth.backend.models import Customer, NodeAttestor, new_id
from tests.attest import NODE_PUBLIC_PEM, sign_attestation


def test_derive_workload_selectors_sorts_labels_and_keeps_zero_uid():
    selectors = derive_workload_selectors(
        {
            "k8s_ns": "payments",
            "k8s_sa": "risk-agent",
            "pod_labels": {"z": "last", "a": "first"},
            "image_digest": "sha256:abc",
            "unix_uid": 0,
        }
    )

    assert selectors == [
        "k8s:ns:payments",
        "k8s:sa:risk-agent",
        "k8s:pod-label:a:first",
        "k8s:pod-label:z:last",
        "docker:image-digest:sha256:abc",
        "unix:uid:0",
    ]


@pytest.mark.parametrize(
    ("attestor_type", "node", "expected"),
    [
        (
            "aws_iid",
            {"account": "123456789012", "region": "us-west-2", "instance_id": "i-abc"},
            [
                "aws_iid:account:123456789012",
                "aws_iid:region:us-west-2",
                "aws_iid:instance-id:i-abc",
            ],
        ),
        (
            "gcp_iit",
            {"project_id": "risk-prod", "zone": "us-central1-a"},
            ["gcp_iit:project-id:risk-prod", "gcp_iit:zone:us-central1-a"],
        ),
    ],
)
def test_verify_node_attestation_derives_cloud_node_selectors(
    customer, attestor_type, node, expected
):
    with SessionLocal() as db:
        cust = db.get(Customer, customer["customer_id"])
        assert cust is not None
        db.add(
            NodeAttestor(
                id=new_id(),
                customer_id=cust.id,
                type=attestor_type,
                public_pem=NODE_PUBLIC_PEM,
            )
        )
        db.commit()

        document = sign_attestation(
            attestor_type=attestor_type,
            node=node,
            aud=customer["customer_id"],
        )
        payload, selectors = verify_node_attestation(db, cust, document)

    assert payload["type"] == attestor_type
    assert selectors == expected


def test_verify_node_attestation_rejects_unparseable_jws(customer):
    with SessionLocal() as db:
        cust = db.get(Customer, customer["customer_id"])
        assert cust is not None
        with pytest.raises(AttestationDeniedError, match="could not be parsed"):
            verify_node_attestation(db, cust, "bad.header.signature")
