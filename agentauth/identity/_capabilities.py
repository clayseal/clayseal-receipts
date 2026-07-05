"""Offline capability operations: PoP signing, attenuation, and authorization.

This is the SDK-side mirror of ``agentauth/backend/capabilities.py``. The SDK
does not import backend internals, so the Datalog policy and request-bound
proof-of-possession contract are mirrored here. A parity test signs with this
module and verifies with the backend to keep them in lockstep.

Everything here is offline: given a token, the customer's Biscuit root public
key (hex), and the workload's private key, the SDK can attenuate, sign
proof-of-possession, and reach an authorization decision with no server.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass

from biscuit_auth import (
    Algorithm,
    AuthorizerBuilder,
    Biscuit,
    BlockBuilder,
    Check,
    Fact,
    PublicKey,
    Rule,
)
from agentauth.biscuit_scope import (
    FILE_RESOURCE,
    evaluate_path_scope,
    path_patterns_from_biscuit_blocks,
)
from agentauth.workload_keys import (
    keyhash_for_pem,
    sign_request_pop,
    token_hash,
    verify_request_pop,
)

__all__ = [
    "PopProof",
    "attenuate_biscuit",
    "authorize_biscuit",
    "issue_challenge",
    "keyhash_for_pem",
    "sign_request_pop",
    "token_hash",
    "verify_request_pop",
]

# MUST stay byte-identical to agentauth/backend/capabilities.py::_AUTHORIZER_POLICY.
_AUTHORIZER_POLICY = """
    operation({resource}, {action});
    allow if capability($r, $a), operation($r, $a);
    allow if capability($r, "*"), operation($r, $_);
    deny if true;
"""


@dataclass
class PopProof:
    challenge: str
    signature_b64: str
    pubkey_pem: str
    htm: str
    htu: str
    ath: str
    iat: int
    jti: str


def issue_challenge() -> str:
    return secrets.token_urlsafe(32)


def _public_key(public_hex: str) -> PublicKey:
    return PublicKey.from_bytes(bytes.fromhex(public_hex), Algorithm.Ed25519)


def _parse(token_b64: str, root_public_hex: str) -> Biscuit:
    return Biscuit.from_base64(token_b64, _public_key(root_public_hex))


def _normalize(capabilities) -> list[dict]:
    out = []
    for cap in capabilities or []:
        resource = str(cap.get("resource", "")).strip()
        action = str(cap.get("action", "")).strip()
        if resource and action:
            out.append({"resource": resource, "action": action})
    return out


def read_bound_keys(token_b64: str, root_public_hex: str) -> list[str]:
    token = _parse(token_b64, root_public_hex)
    facts = AuthorizerBuilder("").build(token).query(Rule("k($k) <- bound_key($k)"))
    return [f.terms[0] for f in facts]


def read_path_scope(token_b64: str, root_public_hex: str) -> tuple[list[str], list[str]]:
    token = _parse(token_b64, root_public_hex)
    return path_patterns_from_biscuit_blocks(token)


def attenuate_biscuit(
    *,
    token_b64: str,
    root_public_hex: str,
    capabilities=None,
    path_patterns: list[str] | None = None,
    denied_paths: list[str] | None = None,
    expires_at=None,
) -> str:
    """Append an offline caveat block narrowing rights and/or shortening life."""
    token = _parse(token_b64, root_public_hex)
    block = BlockBuilder("")
    caps = _normalize(capabilities)
    if caps:
        for cap in caps:
            block.add_fact(
                Fact("allowed_cap({r}, {a})", {"r": cap["resource"], "a": cap["action"]})
            )
        block.add_check(Check("check if operation($r, $a), allowed_cap($r, $a)"))
    for pattern in path_patterns or []:
        block.add_fact(Fact("allowed_path({p})", {"p": str(pattern)}))
    for pattern in denied_paths or []:
        block.add_fact(Fact("denied_path({p})", {"p": str(pattern)}))
    if expires_at is not None:
        block.add_check(Check("check if time($t), $t <= {exp}", {"exp": expires_at}))
    return token.append(block).to_base64()


def authorize_biscuit(
    *,
    token_b64: str,
    root_public_hex: str,
    operation: tuple[str, str],
    pop: PopProof | None = None,
    expected_htm: str | None = None,
    expected_htu: str | None = None,
    file_path: str | None = None,
) -> dict:
    """Offline authorization decision. Returns ``{"allowed": bool, "reason": str}``."""
    token = _parse(token_b64, root_public_hex)
    bound = read_bound_keys(token_b64, root_public_hex)

    if operation[0] == FILE_RESOURCE or file_path is not None:
        allowed_paths, denied_paths = read_path_scope(token_b64, root_public_hex)
        if allowed_paths or denied_paths:
            path_ok, path_reason = evaluate_path_scope(
                file_path,
                allowed_paths=allowed_paths,
                denied_paths=denied_paths,
            )
            if not path_ok:
                return {"allowed": False, "reason": path_reason}

    valid_pop = False
    reason = "no proof-of-possession presented"
    if pop is not None:
        try:
            keyhash = keyhash_for_pem(pop.pubkey_pem)
        except ValueError:
            keyhash = ""
        if bound and keyhash not in bound:
            reason = "presented key is not the token's bound workload key"
        elif verify_request_pop(
            pop.pubkey_pem,
            keyhash,
            pop.challenge,
            htm=pop.htm,
            htu=pop.htu,
            ath=pop.ath,
            iat=pop.iat,
            jti=pop.jti,
            signature_b64=pop.signature_b64,
            operation=operation,
            expected_htm=expected_htm,
            expected_htu=expected_htu,
            expected_ath=token_hash(token_b64),
        ):
            valid_pop = True
        else:
            reason = "request-bound proof-of-possession signature is invalid"

    builder = AuthorizerBuilder(
        _AUTHORIZER_POLICY, {"resource": operation[0], "action": operation[1]}
    )
    if valid_pop:
        builder.add_fact(Fact("valid_pop(true)"))
    builder.set_time()
    try:
        builder.build(token).authorize()
        return {"allowed": True, "reason": "authorized"}
    except Exception as exc:  # noqa: BLE001
        return {"allowed": False, "reason": reason if not valid_pop else str(exc)}
