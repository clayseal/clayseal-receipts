"""Receipt-chain verifier for cross-session poison attribution (CHAIN-1 / SM-20)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentauth.receipts.cross_session import (
    DEFAULT_POISON_MARKERS,
    PRIOR_INSTRUCTION_SURFACES,
)

SECURITY_SENSITIVE_PATHS = frozenset(
    {"swe_triage/parser.py", "swe_triage/auth.py", "tests/test_parser.py"}
)


def _is_instruction_surface(path: str) -> bool:
    normalized = path.lstrip("./")
    if normalized in PRIOR_INSTRUCTION_SURFACES:
        return True
    return normalized.endswith(("AGENTS.md", "DELEGATION.md", "knowledge.md"))


@dataclass
class PoisonCaptureEvent:
    receipt_id: str
    receipt_hash: str
    surface_path: str
    markers: list[str] = field(default_factory=list)
    created_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "receipt_hash": self.receipt_hash,
            "surface_path": self.surface_path,
            "markers": list(self.markers),
            "created_at": self.created_at,
        }


@dataclass
class ChainLink:
    cause_receipt_id: str
    cause_receipt_hash: str
    effect_receipt_id: str
    effect_path: str
    prior_surface: str
    matched_markers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cause_receipt_id": self.cause_receipt_id,
            "cause_receipt_hash": self.cause_receipt_hash,
            "effect_receipt_id": self.effect_receipt_id,
            "effect_path": self.effect_path,
            "prior_surface": self.prior_surface,
            "matched_markers": list(self.matched_markers),
            "attribution": "receipt_chain",
        }


def _changed_paths(receipt: dict[str, Any]) -> set[str]:
    git_block = receipt.get("git") or {}
    changed = git_block.get("changed_files") or []
    paths: set[str] = set()
    for item in changed:
        if isinstance(item, dict) and item.get("path"):
            paths.add(str(item["path"]))
    return paths


def extract_poison_captures(
    receipt: dict[str, Any],
    *,
    markers: tuple[str, ...] | None = None,
) -> list[PoisonCaptureEvent]:
    """Identify instruction-surface writes that likely planted poison (I1 class)."""
    marker_tuple = markers or DEFAULT_POISON_MARKERS
    receipt_id = str(receipt.get("receipt_id") or "")
    receipt_hash = str(receipt.get("receipt_hash") or "")
    created_at = receipt.get("created_at")
    outcome = (receipt.get("decision") or {}).get("outcome")

    issue_markers: list[str] = []
    issue_block = receipt.get("issue") or {}
    if isinstance(issue_block, dict):
        issue_markers = [
            str(item) for item in issue_block.get("poison_markers_observed") or []
        ]

    captures: list[PoisonCaptureEvent] = []
    for path in sorted(_changed_paths(receipt)):
        if not _is_instruction_surface(path):
            continue
        if outcome not in {"allow", "allow_with_review"}:
            continue
        matched = [marker for marker in marker_tuple if marker in json.dumps(receipt)]
        matched = list(dict.fromkeys([*matched, *issue_markers]))
        captures.append(
            PoisonCaptureEvent(
                receipt_id=receipt_id,
                receipt_hash=receipt_hash,
                surface_path=path,
                markers=matched[:10],
                created_at=str(created_at) if created_at else None,
            )
        )
    return captures


def extract_security_executions(receipt: dict[str, Any]) -> list[str]:
    touched = _changed_paths(receipt) & SECURITY_SENSITIVE_PATHS
    return sorted(touched)


def link_receipt_chain(
    current_receipt: dict[str, Any],
    prior_receipts: list[dict[str, Any]],
    *,
    markers: tuple[str, ...] | None = None,
) -> list[ChainLink]:
    """Link prior poison-capture receipts to the current security-sensitive diff."""
    effect_paths = extract_security_executions(current_receipt)
    if not effect_paths:
        return []

    current_id = str(current_receipt.get("receipt_id") or "")
    links: list[ChainLink] = []
    for prior in prior_receipts:
        for capture in extract_poison_captures(prior, markers=markers):
            for effect_path in effect_paths:
                links.append(
                    ChainLink(
                        cause_receipt_id=capture.receipt_id,
                        cause_receipt_hash=capture.receipt_hash,
                        effect_receipt_id=current_id,
                        effect_path=effect_path,
                        prior_surface=capture.surface_path,
                        matched_markers=capture.markers,
                    )
                )
    return links


def link_receipt_chain_from_evidence(
    *,
    changes: list[dict[str, Any]],
    prior_receipts: list[dict[str, Any]],
    receipt_id: str,
    markers: tuple[str, ...] | None = None,
) -> list[ChainLink]:
    """Build chain links before the current receipt body is finalized."""
    effect_paths = sorted(
        {
            str(change["path"])
            for change in changes
            if isinstance(change, dict) and change.get("path") in SECURITY_SENSITIVE_PATHS
        }
    )
    if not effect_paths:
        return []

    links: list[ChainLink] = []
    for prior in prior_receipts:
        for capture in extract_poison_captures(prior, markers=markers):
            for effect_path in effect_paths:
                links.append(
                    ChainLink(
                        cause_receipt_id=capture.receipt_id,
                        cause_receipt_hash=capture.receipt_hash,
                        effect_receipt_id=receipt_id,
                        effect_path=effect_path,
                        prior_surface=capture.surface_path,
                        matched_markers=capture.markers,
                    )
                )
    return links


def load_gate_receipts(
    receipts_dir: str | Path,
    *,
    exclude: str | Path | None = None,
) -> list[dict[str, Any]]:
    directory = Path(receipts_dir)
    if not directory.is_dir():
        return []
    exclude_resolved = Path(exclude).resolve() if exclude else None
    receipts: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        if exclude_resolved is not None and path.resolve() == exclude_resolved:
            continue
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(body, dict) and body.get("receipt_id"):
            receipts.append(body)
    receipts.sort(key=lambda item: str(item.get("created_at") or ""))
    return receipts


def verify_receipt_chain(
    current_receipt: dict[str, Any],
    prior_receipts: list[dict[str, Any]] | None = None,
    *,
    markers: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Verify causal chain from prior poison captures to the current receipt."""
    issues: list[str] = []
    priors = list(prior_receipts or [])

    chain_block = current_receipt.get("receipt_chain") or {}
    stored_refs = chain_block.get("prior_receipt_refs") or []
    if not priors and stored_refs:
        issues.append("prior receipt refs recorded but prior receipts not supplied for verification")

    for ref in stored_refs:
        if not isinstance(ref, dict):
            continue
        ref_id = ref.get("receipt_id")
        ref_hash = ref.get("receipt_hash")
        match = next(
            (
                item
                for item in priors
                if item.get("receipt_id") == ref_id and item.get("receipt_hash") == ref_hash
            ),
            None,
        )
        if match is None:
            issues.append(f"prior receipt ref {ref_id!r} hash mismatch or missing")

    links = link_receipt_chain(current_receipt, priors, markers=markers)
    stored_links = chain_block.get("links") or []
    if stored_links and links:
        stored_pairs = {
            (item.get("cause_receipt_id"), item.get("effect_path"))
            for item in stored_links
            if isinstance(item, dict)
        }
        live_pairs = {(link.cause_receipt_id, link.effect_path) for link in links}
        if stored_pairs != live_pairs:
            issues.append("recorded receipt_chain links do not match recomputed chain")

    flags = current_receipt.get("flags") or []
    has_cross_session = any(
        isinstance(item, dict) and item.get("code") == "cross_session_poison_attribution"
        for item in flags
    )
    if has_cross_session and not links and not stored_links:
        issues.append(
            "cross_session_poison_attribution flag without receipt-chain link to a prior capture"
        )

    return {
        "valid": not issues,
        "issues": issues,
        "links": [link.to_dict() for link in links],
        "prior_capture_count": sum(len(extract_poison_captures(item, markers=markers)) for item in priors),
        "effect_paths": extract_security_executions(current_receipt),
    }


def verify_receipt_at_merge(
    receipt: dict[str, Any],
    *,
    merge_head_sha: str,
    repo: str | Path | None = None,
) -> dict[str, Any]:
    """GATE-4: fail closed when the merge commit differs from the evaluated head."""
    from agentauth.core.hash_util import sha256_hex

    issues: list[str] = []
    git_block = receipt.get("git") or {}
    evaluated_head = git_block.get("evaluated_head_sha") or git_block.get("head_sha")
    if not evaluated_head:
        issues.append("receipt missing evaluated head SHA binding")
    elif merge_head_sha != evaluated_head:
        issues.append(
            f"merge head {merge_head_sha} != evaluated head {evaluated_head} (TOCTOU / stale receipt)"
        )

    if repo is not None and evaluated_head:
        import subprocess

        repo_path = Path(repo)
        probe = subprocess.run(
            ["git", "-C", str(repo_path), "cat-file", "-e", f"{evaluated_head}^{{commit}}"],
            capture_output=True,
            text=True,
        )
        if probe.returncode != 0:
            issues.append(f"evaluated head {evaluated_head} is not present in repo")

        stored_diff_hash = git_block.get("diff_hash")
        if stored_diff_hash and merge_head_sha == evaluated_head:
            merge_base = git_block.get("merge_base") or git_block.get("evaluated_merge_base")
            if merge_base:
                diff_proc = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo_path),
                        "diff",
                        merge_base,
                        merge_head_sha,
                    ],
                    capture_output=True,
                    text=True,
                )
                if diff_proc.returncode == 0:
                    live_hash = sha256_hex(diff_proc.stdout.encode("utf-8"))
                    if live_hash != stored_diff_hash:
                        issues.append("stored diff_hash does not match recomputed merge-base diff")

    return {
        "valid": not issues,
        "issues": issues,
        "evaluated_head_sha": evaluated_head,
        "merge_head_sha": merge_head_sha,
        "toctou_ok": merge_head_sha == evaluated_head and not issues,
        "receipt_id": receipt.get("receipt_id"),
        "decision": (receipt.get("decision") or {}).get("outcome"),
    }
