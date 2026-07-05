"""Runtime egress capability checks (RT-1 / SM-17).

Default-deny outbound network destinations at tool-call time unless the policy
allowlist or authority grants permit the destination. Attestations are recorded
on the audit authorization context for receipt export.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.runtime import ActionDescriptor, AuthorityContext

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_NETWORK_TOOL_MARKERS = (
    "http",
    "fetch",
    "post",
    "webhook",
    "curl",
    "request",
    "egress",
    "exfil",
)
_URL_ARG_KEYS = (
    "url",
    "uri",
    "endpoint",
    "webhook_url",
    "webhook",
    "destination",
    "target_url",
    "callback_url",
)
_HOST_ARG_KEYS = ("host", "hostname", "domain")


@dataclass
class EgressPolicy:
    """Policy block for outbound network capability."""

    enabled: bool = False
    default_deny: bool = True
    allowed_hosts: list[str] = field(default_factory=list)
    network_tools: list[str] = field(default_factory=list)

    @classmethod
    def from_policy_dict(cls, raw: dict[str, Any] | None) -> EgressPolicy:
        if not isinstance(raw, dict):
            return cls()
        allowed = raw.get("allowed_hosts") or raw.get("allowlist") or []
        tools = raw.get("network_tools") or raw.get("tools") or []
        return cls(
            enabled=bool(raw.get("enabled", False)),
            default_deny=bool(raw.get("default_deny", True)),
            allowed_hosts=[str(item) for item in allowed],
            network_tools=[str(item) for item in tools],
        )


@dataclass
class NetworkDestination:
    host: str
    scheme: str | None = None
    port: int | None = None
    path: str | None = None
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "scheme": self.scheme,
            "port": self.port,
            "path": self.path,
            "source": self.source,
        }


@dataclass
class EgressAttestation:
    """Recorded on tool-time receipts when egress policy is active."""

    destinations: list[dict[str, Any]] = field(default_factory=list)
    arguments_hash: str | None = None
    authorized: bool = True
    default_deny: bool = True
    blocked_hosts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "destinations": list(self.destinations),
            "arguments_hash": self.arguments_hash,
            "authorized": self.authorized,
            "default_deny": self.default_deny,
            "blocked_hosts": list(self.blocked_hosts),
        }


def _normalize_host(value: str) -> str | None:
    text = value.strip().lower()
    if not text:
        return None
    if text.startswith("http://") or text.startswith("https://"):
        parsed = urlparse(text)
        return parsed.hostname.lower() if parsed.hostname else None
    if "://" in text:
        parsed = urlparse(text)
        return parsed.hostname.lower() if parsed.hostname else None
    if "/" in text:
        return None
    if text.startswith("[") and "]" in text:
        return text[1 : text.index("]")].lower()
    host = text.split(":", 1)[0]
    return host.lower() if host else None


def _host_from_url(value: str) -> NetworkDestination | None:
    parsed = urlparse(value.strip())
    if not parsed.hostname:
        return None
    port = parsed.port
    return NetworkDestination(
        host=parsed.hostname.lower(),
        scheme=(parsed.scheme or None),
        port=port,
        path=parsed.path or None,
        source="url",
    )


def _collect_string_values(value: Any, *, prefix: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, str):
        found.append((prefix or "value", value))
    elif isinstance(value, dict):
        for key, item in value.items():
            key_text = f"{prefix}.{key}" if prefix else str(key)
            found.extend(_collect_string_values(item, prefix=key_text))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_collect_string_values(item, prefix=f"{prefix}[{index}]"))
    return found


def is_network_tool(tool_name: str, *, policy: EgressPolicy | None = None) -> bool:
    if policy and policy.network_tools:
        return tool_name in policy.network_tools
    lowered = tool_name.lower()
    return any(marker in lowered for marker in _NETWORK_TOOL_MARKERS)


def extract_network_destinations(
    tool_name: str,
    arguments: dict[str, Any] | None,
    *,
    policy: EgressPolicy | None = None,
) -> list[NetworkDestination]:
    args = dict(arguments or {})
    destinations: list[NetworkDestination] = []
    seen: set[str] = set()

    def add(dest: NetworkDestination) -> None:
        key = dest.host
        if key and key not in seen:
            seen.add(key)
            destinations.append(dest)

    for key in _URL_ARG_KEYS:
        raw = args.get(key)
        if isinstance(raw, str) and (_URL_RE.match(raw) or "://" in raw):
            dest = _host_from_url(raw)
            if dest is not None:
                dest.source = str(key)
                add(dest)

    for key in _HOST_ARG_KEYS:
        raw = args.get(key)
        if isinstance(raw, str):
            host = _normalize_host(raw)
            if host:
                add(NetworkDestination(host=host, source=str(key)))

    if is_network_tool(tool_name, policy=policy) or not destinations:
        for arg_key, raw in _collect_string_values(args):
            if not isinstance(raw, str):
                continue
            if _URL_RE.match(raw) or ("://" in raw and "." in raw):
                dest = _host_from_url(raw)
                if dest is not None:
                    dest.source = arg_key
                    add(dest)
            elif arg_key.split(".")[-1] in _HOST_ARG_KEYS:
                host = _normalize_host(raw)
                if host:
                    add(NetworkDestination(host=host, source=arg_key))

    return destinations


def host_matches_allowlist(host: str, patterns: list[str]) -> bool:
    host_lower = host.lower()
    for pattern in patterns:
        candidate = pattern.lower()
        if candidate.startswith("network:"):
            candidate = candidate.removeprefix("network:")
        if fnmatch.fnmatchcase(host_lower, candidate):
            return True
    return False


def _authority_allows_network(
    authority: AuthorityContext,
    *,
    tool_name: str,
    host: str,
) -> bool:
    host_lower = host.lower()
    network_scopes = [
        scope.removeprefix("network:")
        for scope in authority.resource_scope
        if scope.startswith("network:")
    ]
    if network_scopes and host_matches_allowlist(host_lower, network_scopes):
        return True

    for scope in authority.scope_claims:
        if scope.startswith("network:"):
            if host_matches_allowlist(host_lower, [scope]):
                return True
        if scope in {tool_name, f"network:{host_lower}", "network:*"}:
            return True

    resource_names = {"network", "egress", "http", "mcp_tool"}
    action_names = {tool_name, "call", "http_request", "*"}
    if authority.capability_rules:
        for item in authority.capability_rules:
            resource = str(item.get("resource", "")).strip()
            action = str(item.get("action", "")).strip()
            if resource not in resource_names:
                continue
            allowed_hosts = item.get("allowed_hosts") or item.get("hosts") or []
            if allowed_hosts and not host_matches_allowlist(
                host_lower, [str(entry) for entry in allowed_hosts]
            ):
                continue
            if action in action_names or action == "*":
                return True

    for capability in authority.capabilities:
        if capability.startswith("network:"):
            if host_matches_allowlist(host_lower, [capability]):
                return True
        if capability in {"network:*", "egress:*"}:
            return True

    return False


def evaluate_egress(
    *,
    tool_name: str,
    arguments: dict[str, Any] | None,
    policy: EgressPolicy,
    authority: AuthorityContext | None = None,
) -> tuple[list[str], EgressAttestation | None]:
    if not policy.enabled:
        return [], None

    destinations = extract_network_destinations(tool_name, arguments, policy=policy)
    attestation = EgressAttestation(
        destinations=[item.to_dict() for item in destinations],
        arguments_hash=hash_canonical_json(dict(arguments or {})),
        default_deny=policy.default_deny,
    )

    if not destinations:
        attestation.authorized = True
        return [], attestation

    violations: list[str] = []
    blocked: list[str] = []
    for dest in destinations:
        host = dest.host
        allowed = False
        if policy.allowed_hosts and host_matches_allowlist(host, policy.allowed_hosts):
            allowed = True
        elif authority is not None and _authority_allows_network(
            authority, tool_name=tool_name, host=host
        ):
            allowed = True
        elif not policy.default_deny:
            allowed = True

        if not allowed:
            blocked.append(host)
            violations.append(f"egress to {host!r} is not authorized")

    attestation.blocked_hosts = blocked
    attestation.authorized = not blocked
    return violations, attestation


def annotate_egress(
    *,
    tool_name: str,
    arguments: dict[str, Any] | None,
    policy: EgressPolicy,
    authority: AuthorityContext | None,
    authorization: dict[str, Any] | None,
) -> list[str]:
    """Evaluate egress, attach attestation to authorization, return violations."""
    violations, attestation = evaluate_egress(
        tool_name=tool_name,
        arguments=arguments,
        policy=policy,
        authority=authority,
    )
    if attestation is None:
        return violations
    payload = authorization if authorization is not None else {}
    payload["egress"] = attestation.to_dict()
    return violations


def network_action_descriptor(
    tool_name: str,
    arguments: dict[str, Any] | None,
    *,
    policy: EgressPolicy | None,
    fallback_resource_ref: str,
) -> ActionDescriptor:
    from agentauth.core.runtime import ActionDescriptor, SideEffectLevel

    destinations = extract_network_destinations(tool_name, arguments, policy=policy)
    if destinations:
        host = destinations[0].host
        return ActionDescriptor(
            action_name=f"mcp.tools/call/{tool_name}",
            action_category="network_egress",
            resource_type="network",
            resource_ref=f"network:{host}",
            side_effect_level=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
        )
    return ActionDescriptor(
        action_name=f"mcp.tools/call/{tool_name}",
        action_category="mcp_tool_call",
        resource_type="mcp_tool",
        resource_ref=fallback_resource_ref,
        side_effect_level=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
    )
