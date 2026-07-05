"""External witness co-signing of audit checkpoints (anti-equivocation, SOTA-5).

A witness is an independent party that co-signs a log's checkpoints, but only after
verifying that each new checkpoint is a consistent, append-only extension of the last
checkpoint it endorsed. This follows the Certificate-Transparency / Rekor witness-gossip
pattern: if a log tries to present different histories to different parties (a split
view / equivocation), the RFC 6962 consistency check fails and the witness refuses to
sign — so the fork can never be laundered into a quorum-signed checkpoint that a verifier
would accept via ``AuditChain.verify_checkpoint(..., required_witnesses=K)``.
"""

from __future__ import annotations

from typing import Any

from agentauth.receipts.audit import AuditChain, checkpoint_body
from agentauth.core.signing import SigningKey
from agentauth.core.signing import verify as verify_signature


class WitnessRefusal(Exception):
    """Raised when a witness declines to co-sign an inconsistent or forked checkpoint."""


def add_witness_cosignature(
    checkpoint: dict[str, Any],
    witness_key: SigningKey,
    *,
    allow_unsafe: bool = False,
) -> dict[str, Any]:
    """Append a witness co-signature over the checkpoint core (additive, in place).

    Low-level primitive: it signs without any consistency check. Prefer :class:`Witness`
    for the full protocol, which only co-signs after verifying append-only growth.
    """
    if not allow_unsafe:
        raise ValueError(
            "add_witness_cosignature bypasses consistency checks; "
            "use Witness.cosign() or pass allow_unsafe=True for tests"
        )
    descriptor = {"role": "witness", **witness_key.sign(checkpoint_body(checkpoint))}
    checkpoint.setdefault("witness_cosignatures", []).append(descriptor)
    return checkpoint


class Witness:
    """A stateful witness that endorses only consistent, append-only checkpoint growth.

    Track the last checkpoint endorsed; on each new checkpoint require either the same
    core (idempotent re-endorsement) or a valid RFC 6962 consistency proof from the last
    endorsed size to the new size. Anything else is treated as equivocation and refused.
    """

    def __init__(
        self,
        signing_key: SigningKey,
        *,
        log_public_key: str | None = None,
    ) -> None:
        self.signing_key = signing_key
        # When set, every checkpoint must carry a valid log signature from this key,
        # so a witness cannot be tricked into endorsing an impostor log's history.
        self.log_public_key = log_public_key
        self._last_seen: dict[str, Any] | None = None

    @property
    def public_key_hex(self) -> str:
        return self.signing_key.public_key_hex

    @property
    def last_seen(self) -> dict[str, Any] | None:
        return self._last_seen

    def cosign(
        self,
        checkpoint: dict[str, Any],
        *,
        consistency_proof: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Verify then co-sign ``checkpoint``; raise :class:`WitnessRefusal` on equivocation."""
        body = checkpoint_body(checkpoint)

        if self.log_public_key is not None:
            signature = checkpoint.get("signature")
            if signature is None or signature.get("public_key") != self.log_public_key:
                raise WitnessRefusal("checkpoint not signed by the pinned log key")
            if not verify_signature(body, signature):
                raise WitnessRefusal("invalid log signature on checkpoint")

        new_count = body.get("count")
        if not isinstance(new_count, int) or new_count < 0:
            raise WitnessRefusal("checkpoint has no valid count")

        if self._last_seen is not None:
            last = self._last_seen
            last_count = last["count"]
            if new_count < last_count:
                raise WitnessRefusal(
                    f"checkpoint regresses: count {new_count} < last endorsed {last_count}"
                )
            if new_count == last_count:
                if body != last:
                    raise WitnessRefusal("split view: same size but different core")
            else:
                if consistency_proof is None:
                    raise WitnessRefusal("growth requires a consistency proof")
                if not AuditChain.verify_consistency(last, checkpoint, consistency_proof):
                    raise WitnessRefusal("inconsistent history — equivocation refused")

        add_witness_cosignature(checkpoint, self.signing_key, allow_unsafe=True)
        self._last_seen = body
        return checkpoint


def create_witness_app(witness: Witness) -> Any:
    """Minimal reference witness HTTP service: POST /v1/witness/cosign.

    Body: ``{"checkpoint": {...}, "consistency_proof": {...}|null}``. Returns the
    co-signature descriptor on success, or HTTP 409 with a reason on refusal.

    When ``AGENT_RECEIPTS_WITNESS_API_KEY`` is set, requests must include that key
    via ``X-API-Key`` or ``Authorization: Bearer``.
    """
    import os

    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from agentauth.receipts.verifier_auth import ApiKeyMiddleware

    async def cosign_route(request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse({"error": "body must be JSON"}, status_code=400)
        if not isinstance(payload, dict) or not isinstance(payload.get("checkpoint"), dict):
            return JSONResponse({"error": "checkpoint object required"}, status_code=400)
        checkpoint = payload["checkpoint"]
        try:
            witness.cosign(checkpoint, consistency_proof=payload.get("consistency_proof"))
        except WitnessRefusal as exc:
            return JSONResponse({"cosigned": False, "reason": str(exc)}, status_code=409)
        return JSONResponse(
            {
                "cosigned": True,
                "witness_public_key": witness.public_key_hex,
                "cosignature": checkpoint["witness_cosignatures"][-1],
            }
        )

    app = Starlette(routes=[Route("/v1/witness/cosign", cosign_route, methods=["POST"])])
    if os.environ.get("AGENT_RECEIPTS_WITNESS_API_KEY", "").strip():
        app.add_middleware(ApiKeyMiddleware, env_var="AGENT_RECEIPTS_WITNESS_API_KEY")
    return app
