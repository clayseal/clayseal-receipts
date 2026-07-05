"""Attestation: turning *verified evidence* into selectors.

This is the prototype's stand-in for SPIRE's two attestation stages. In
production a SPIRE Agent proves a workload's environment to the SPIRE Server in
two steps:

1. **Node attestation** — the agent proves which node/environment it runs on
   (Kubernetes projected SA token, AWS instance identity document, GCP metadata
   token). The server verifies this cryptographically and derives *node
   selectors*.
2. **Workload attestation** — the (now-trusted) agent reports the calling
   process's attributes (service account, pod labels, container image digest,
   process UID), from which the server derives *workload selectors*.

We cannot call a live Kubernetes TokenReview or AWS IID endpoint from an
in-process service, so the workload presents a **signed attestation document**
(a JWT). The signature is verified against a node trust anchor an admin
registered for the tenant (``NodeAttestor``) — that *is* the node attestation,
and it is real cryptography: forging provenance requires the anchor's private
key. The verified document's ``workload`` block then feeds workload selector
derivation. The transport is simulated; the trust decision is not.

A caller never hands us a selector directly. Selectors are always *derived from
verified evidence*, which is the whole point: an agent cannot claim an identity,
only prove one.
"""
from __future__ import annotations

from datetime import datetime

import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from .errors import AttestationDeniedError
from .models import AttestationUse, Customer, NodeAttestor, utcnow

SUPPORTED_ATTESTOR_TYPES = {"k8s_psat", "aws_iid", "gcp_iit"}


# --------------------------------------------------------------------------- #
# Node selectors -- derived from the verified `node` block, per attestor type.
# --------------------------------------------------------------------------- #
def _node_selectors(attestor_type: str, node: dict) -> list[str]:
    sel: list[str] = []
    if attestor_type == "k8s_psat":
        if node.get("cluster"):
            sel.append(f"k8s_psat:cluster:{node['cluster']}")
        if node.get("agent_ns"):
            sel.append(f"k8s_psat:agent_ns:{node['agent_ns']}")
        if node.get("agent_sa"):
            sel.append(f"k8s_psat:agent_sa:{node['agent_sa']}")
    elif attestor_type == "aws_iid":
        if node.get("account"):
            sel.append(f"aws_iid:account:{node['account']}")
        if node.get("region"):
            sel.append(f"aws_iid:region:{node['region']}")
        if node.get("instance_id"):
            sel.append(f"aws_iid:instance-id:{node['instance_id']}")
    elif attestor_type == "gcp_iit":
        if node.get("project_id"):
            sel.append(f"gcp_iit:project-id:{node['project_id']}")
        if node.get("zone"):
            sel.append(f"gcp_iit:zone:{node['zone']}")
    return sel


# --------------------------------------------------------------------------- #
# Workload selectors -- derived from the verified `workload` block.
# --------------------------------------------------------------------------- #
def derive_workload_selectors(workload: dict) -> list[str]:
    """Map workload evidence to SPIRE-style workload selectors.

    These describe the *process*: which namespace/service-account it runs as,
    its pod labels, container image digest, and UID.
    """
    sel: list[str] = []
    if workload.get("k8s_ns"):
        sel.append(f"k8s:ns:{workload['k8s_ns']}")
    if workload.get("k8s_sa"):
        sel.append(f"k8s:sa:{workload['k8s_sa']}")
    for key, value in sorted((workload.get("pod_labels") or {}).items()):
        sel.append(f"k8s:pod-label:{key}:{value}")
    if workload.get("image_digest"):
        sel.append(f"docker:image-digest:{workload['image_digest']}")
    if workload.get("unix_uid") is not None:
        sel.append(f"unix:uid:{workload['unix_uid']}")
    return sel


def record_attestation_use(
    db: Session,
    customer_id: str,
    *,
    jti: str,
    expires_at: datetime,
) -> None:
    """Reject attestation documents that have already minted a credential."""
    existing = db.scalar(
        select(AttestationUse).where(
            AttestationUse.customer_id == customer_id,
            AttestationUse.jti == jti,
        )
    )
    if existing is not None:
        raise AttestationDeniedError(
            "Attestation document has already been used to mint a credential.",
            suggestion="Fetch a fresh attestation document from the node agent and call identify() again.",
            attestation_jti=jti,
        )
    db.add(
        AttestationUse(
            customer_id=customer_id,
            jti=jti,
            expires_at=expires_at,
        )
    )
    db.flush()


# --------------------------------------------------------------------------- #
# Node attestation -- verify the signed document against a trust anchor.
# --------------------------------------------------------------------------- #
def verify_node_attestation(
    db: Session, customer: Customer, attestation_document: str
) -> tuple[dict, list[str]]:
    """Verify a signed attestation document and return ``(payload, selectors)``.

    Tries the customer's registered node attestors; the first whose public key
    verifies the document's RS256 signature wins (that proves the node). Raises
    :class:`AttestationDeniedError` if the document is malformed, signed by an
    unregistered key, or stale.
    """
    if not attestation_document or attestation_document.count(".") != 2:
        raise AttestationDeniedError(
            "Attestation document is missing or not a signed JWT.",
            suggestion=(
                "Present the signed attestation document your node agent issues "
                "(a JWS with node + workload evidence)."
            ),
        )

    # Read the declared type (unverified) so we only try anchors of that type.
    try:
        unverified = jwt.decode(attestation_document, options={"verify_signature": False})
    except jwt.InvalidTokenError as exc:
        raise AttestationDeniedError(
            "Attestation document could not be parsed.",
            suggestion="Ensure the document is a well-formed JWS.",
        ) from exc

    declared_type = unverified.get("type")
    anchors = list(
        db.scalars(
            select(NodeAttestor).where(NodeAttestor.customer_id == customer.id)
        ).all()
    )
    if not anchors:
        raise AttestationDeniedError(
            "No node attestors are registered for this tenant.",
            suggestion=(
                "Register a node trust anchor at POST /v1/node-attestors before "
                "any workload can attest."
            ),
        )

    candidates = [a for a in anchors if declared_type is None or a.type == declared_type]
    expired = False
    for anchor in candidates:
        try:
            payload = jwt.decode(
                attestation_document,
                anchor.public_pem,
                algorithms=["RS256"],
                audience=customer.id,
                options={"require": ["jti", "exp"]},
            )
        except jwt.ExpiredSignatureError:
            expired = True
            continue
        except jwt.InvalidTokenError:
            continue
        # Verified: this anchor proves the node.
        node = payload.get("node") or {}
        selectors = _node_selectors(anchor.type, node)
        return payload, selectors

    if expired:
        raise AttestationDeniedError(
            "Attestation document has expired.",
            suggestion="Node evidence is short-lived; re-fetch it and attest again.",
        )
    raise AttestationDeniedError(
        "Attestation document is not signed by any registered node attestor.",
        suggestion=(
            "The signing key must match a node trust anchor registered for this "
            "tenant. A stolen workload credential cannot forge node provenance."
        ),
    )
