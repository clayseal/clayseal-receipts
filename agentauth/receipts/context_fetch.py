"""Gated external context fetch with provenance (I3 / CHAIN-2)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from agentauth.receipts.context_provenance import ProvenanceSurface, build_context_provenance
from agentauth.core.hash_util import sha256_hex


@dataclass
class ContextSourcePolicy:
    """Which external surfaces may be read and how they are trusted."""

    enabled: bool = True
    allowed_source_types: list[str] = field(
        default_factory=lambda: ["wiki", "docs", "issue", "slack"]
    )
    allowed_hosts: list[str] = field(default_factory=list)
    default_trusted: bool = False
    require_gateway_fetch: bool = True

    @classmethod
    def from_policy_dict(cls, raw: dict[str, Any] | None) -> ContextSourcePolicy:
        if not isinstance(raw, dict):
            return cls()
        types = raw.get("allowed_source_types") or raw.get("allowed_types")
        hosts = raw.get("allowed_hosts") or raw.get("allowlist")
        return cls(
            enabled=bool(raw.get("enabled", True)),
            allowed_source_types=[str(item) for item in (types or ["wiki", "docs"])],
            allowed_hosts=[str(item) for item in (hosts or [])],
            default_trusted=bool(raw.get("default_trusted", False)),
            require_gateway_fetch=bool(raw.get("require_gateway_fetch", True)),
        )


def fetch_external_context(
    url: str,
    *,
    source_type: str = "wiki",
    policy: ContextSourcePolicy | None = None,
    timeout: float = 15.0,
) -> tuple[str, ProvenanceSurface, list[str]]:
    """Fetch URL content and return body + provenance surface + violations."""
    cfg = policy or ContextSourcePolicy()
    violations: list[str] = []
    if not cfg.enabled:
        violations.append(f"external context fetch disabled for {source_type!r}")
        return "", ProvenanceSurface(source_type, url, "", trusted=False), violations

    if source_type not in cfg.allowed_source_types:
        violations.append(
            f"context source type {source_type!r} not in allowed_source_types"
        )

    from urllib.parse import urlparse

    host = urlparse(url).hostname or ""
    if not cfg.allowed_hosts:
        violations.append(
            "context fetch requires allowed_hosts allowlist when external fetch is enabled"
        )
    elif not any(host == item or host.endswith(f".{item}") for item in cfg.allowed_hosts):
        violations.append(f"context host {host!r} not in allowed_hosts")

    try:
        request = urllib.request.Request(url, headers={"Accept": "text/plain, text/markdown"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError) as exc:
        violations.append(f"context fetch failed: {exc}")
        body = ""

    content_hash = sha256_hex(body.encode("utf-8")) if body else ""
    surface = ProvenanceSurface(
        surface_type=source_type,
        ref=url,
        content_hash=content_hash,
        trusted=cfg.default_trusted and not violations,
    )
    return body, surface, violations


def attach_context_provenance(
    surfaces: list[ProvenanceSurface | dict[str, Any]],
    *,
    receipt_id: str | None = None,
) -> dict[str, Any]:
    return build_context_provenance(surfaces, receipt_id=receipt_id)


def context_violations_from_surfaces(
    surfaces: list[ProvenanceSurface],
    *,
    policy: ContextSourcePolicy | None = None,
) -> list[str]:
    """Flag untrusted external surfaces that steered into security-sensitive tasks."""
    cfg = policy or ContextSourcePolicy()
    violations: list[str] = []
    for surface in surfaces:
        if surface.trusted:
            continue
        if surface.surface_type not in cfg.allowed_source_types:
            violations.append(
                f"untrusted context surface {surface.surface_type!r} from {surface.ref!r}"
            )
    return violations


def wiki_poison_markers(body: str, markers: tuple[str, ...]) -> list[str]:
    return [marker for marker in markers if marker.lower() in body.lower()]


def summarize_fetch_for_receipt(
    url: str,
    body: str,
    surface: ProvenanceSurface,
    violations: list[str],
) -> dict[str, Any]:
    return {
        "url": url,
        "content_sha256": surface.content_hash,
        "surface": surface.to_dict(),
        "violations": list(violations),
        "body_preview": body[:500],
        "provenance": build_context_provenance([surface]),
    }
