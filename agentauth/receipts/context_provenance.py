"""Context provenance graph for cross-surface propagation tracing (CHAIN-2 / SM-21)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentauth.core.hash_util import hash_canonical_json


@dataclass
class ProvenanceSurface:
    surface_type: str
    ref: str
    content_hash: str
    trusted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "surface_type": self.surface_type,
            "ref": self.ref,
            "content_hash": self.content_hash,
            "trusted": self.trusted,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ProvenanceSurface:
        return cls(
            surface_type=str(raw["surface_type"]),
            ref=str(raw.get("ref") or ""),
            content_hash=str(raw["content_hash"]),
            trusted=bool(raw.get("trusted", False)),
        )


@dataclass
class ProvenanceGraph:
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": list(self.nodes), "edges": list(self.edges)}


def build_context_provenance(
    surfaces: list[ProvenanceSurface | dict[str, Any]],
    *,
    receipt_id: str | None = None,
) -> dict[str, Any]:
    normalized = [
        item.to_dict() if isinstance(item, ProvenanceSurface) else dict(item)
        for item in surfaces
    ]
    block: dict[str, Any] = {
        "schema": "agent-receipts.context-provenance.v1",
        "surfaces": normalized,
        "commitment": hash_canonical_json(normalized),
    }
    if receipt_id:
        block["receipt_id"] = receipt_id
    return block


def provenance_graph_from_receipts(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    """Reconstruct a propagation graph from chained gate / agent receipts."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()

    for receipt in receipts:
        receipt_id = str(receipt.get("receipt_id") or receipt.get("execution_proof", {}).get("proof_id") or "")
        if receipt_id and receipt_id not in seen:
            seen.add(receipt_id)
            nodes.append(
                {
                    "id": receipt_id,
                    "kind": "receipt",
                    "outcome": (receipt.get("decision") or {}).get("outcome"),
                }
            )

        prov = receipt.get("context_provenance") or {}
        for surface in prov.get("surfaces") or []:
            if not isinstance(surface, dict):
                continue
            node_id = f"{surface.get('surface_type')}:{surface.get('content_hash')}"
            if node_id not in seen:
                seen.add(node_id)
                nodes.append(
                    {
                        "id": node_id,
                        "kind": "surface",
                        "surface_type": surface.get("surface_type"),
                        "ref": surface.get("ref"),
                        "trusted": surface.get("trusted"),
                    }
                )
            if receipt_id:
                edges.append(
                    {
                        "from": node_id,
                        "to": receipt_id,
                        "relation": "surfaced_in",
                    }
                )

        chain = receipt.get("receipt_chain") or {}
        for link in chain.get("links") or []:
            if not isinstance(link, dict):
                continue
            cause = str(link.get("cause_receipt_id") or "")
            effect = str(link.get("effect_receipt_id") or receipt_id)
            if cause and effect:
                edges.append(
                    {
                        "from": cause,
                        "to": effect,
                        "relation": "causal_chain",
                        "effect_path": link.get("effect_path"),
                    }
                )

        ci_ctx = receipt.get("ci_context") or {}
        for source in ci_ctx.get("sources") or []:
            if not isinstance(source, dict):
                continue
            node_id = f"ci:{source.get('type')}:{source.get('sha256')}"
            if node_id not in seen:
                seen.add(node_id)
                nodes.append({"id": node_id, "kind": "ci_context", **source})
            if receipt_id:
                edges.append({"from": node_id, "to": receipt_id, "relation": "ingested"})

    return ProvenanceGraph(nodes=nodes, edges=edges).to_dict()


def verify_context_provenance(
    receipt: dict[str, Any],
    *,
    trusted_surface_types: set[str] | None = None,
) -> dict[str, Any]:
    """Flag untrusted surfaces that influenced an allow decision."""
    issues: list[str] = []
    prov = receipt.get("context_provenance") or {}
    surfaces = prov.get("surfaces") or []
    trusted = trusted_surface_types or {"mandate", "policy", "git_diff", "issue_template"}
    outcome = (receipt.get("decision") or {}).get("outcome")
    for surface in surfaces:
        if not isinstance(surface, dict):
            continue
        surface_type = str(surface.get("surface_type") or "")
        if (
            outcome in {"allow", "allow_with_review"}
            and surface_type
            and surface_type not in trusted
            and not surface.get("trusted")
        ):
            issues.append(
                f"untrusted context surface {surface_type!r} present on {outcome} receipt"
            )
    return {"valid": not issues, "issues": issues, "surface_count": len(surfaces)}
