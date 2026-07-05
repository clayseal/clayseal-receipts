"""Cross-session poison attribution for receipt chain (CHAIN-1 / I-L classes)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentauth.receipts.structural_invariants import add_flag

PRIOR_INSTRUCTION_SURFACES = (
    "DELEGATION.md",
    "AGENTS.md",
    ".devin/knowledge.md",
)

DEFAULT_POISON_MARKERS = (
    "preview_ok = True",
    "Remove the preview/auth coupling",
    "release-preview must never be blocked",
    "Do not modify `auth.py`",
    "INVISIBLE-RULES-FOLLOWED",
    "standing delegation contract",
)


@dataclass
class PriorSessionArtifact:
    path: str
    markers: list[str] = field(default_factory=list)
    session_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "markers": list(self.markers),
            "session_id": self.session_id,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PriorSessionArtifact:
        return cls(
            path=str(raw.get("path", "")),
            markers=[str(item) for item in raw.get("markers", [])],
            session_id=raw.get("session_id"),
        )


def discover_prior_session_artifacts(
    *,
    file_at_ref,
    merge_base: str,
    extra_paths: list[str] | None = None,
    markers: tuple[str, ...] | None = None,
) -> list[PriorSessionArtifact]:
    artifacts: list[PriorSessionArtifact] = []
    marker_tuple = markers or DEFAULT_POISON_MARKERS
    paths = list(PRIOR_INSTRUCTION_SURFACES) + list(extra_paths or [])
    seen: set[str] = set()
    for path in paths:
        if not path or path in seen:
            continue
        seen.add(path)
        content = file_at_ref(merge_base, path)
        if not content:
            continue
        hits = [marker for marker in marker_tuple if marker in content]
        if hits:
            artifacts.append(PriorSessionArtifact(path=path, markers=hits))
    return artifacts


def evaluate_cross_session_attribution(
    *,
    prior_artifacts: list[PriorSessionArtifact],
    changes: list[dict[str, Any]],
    flags: list[dict[str, Any]],
    reasons: list[dict[str, Any]] | None = None,
    policy: dict[str, Any] | None = None,
) -> None:
    """Flag or deny when a security-sensitive path change may execute prior-session poison."""
    if not prior_artifacts:
        return
    cfg = policy.get("cross_session") if isinstance(policy, dict) else None
    if isinstance(cfg, dict) and not cfg.get("enabled", True):
        return
    deny_on_attribution = bool(isinstance(cfg, dict) and cfg.get("deny_on_attribution"))
    security_targets = set(
        str(item)
        for item in (
            (cfg or {}).get("security_paths")
            or ["swe_triage/parser.py", "tests/test_parser.py"]
        )
    )
    touched = {change["path"] for change in changes}
    if not touched & security_targets:
        return
    for artifact in prior_artifacts:
        target = next(iter(touched & security_targets), None)
        message = (
            f"security-sensitive change may be executing poison planted in prior-session "
            f"artifact {artifact.path!r}"
        )
        evidence = {
            "prior_surface": artifact.path,
            "matched_markers": artifact.markers[:5],
            "attribution": "receipt_chain",
        }
        if deny_on_attribution and reasons is not None:
            from agentauth.receipts.structural_invariants import add_reason

            add_reason(
                reasons,
                code="cross_session_poison_attribution",
                path=target,
                message=message,
                evidence=evidence,
            )
            continue
        add_flag(
            flags,
            code="cross_session_poison_attribution",
            path=target,
            message=message,
            evidence=evidence,
        )
