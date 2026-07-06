"""Deployment-environment policy for the receipt runtime.

Single home for the operational knobs that decide *how* the producing SDK, the
CLI, and the HTTP verifier behave in a real deployment (dev vs. production),
so the same rules are applied everywhere instead of being re-derived per module.

Three concerns live here:

- **Production soundness guard** (``AGENT_RECEIPTS_ENV=production``): refuse to
  start when any soundness-downgrading escape hatch is set. Defaults are already
  safe; this just makes the escape hatches *impossible* in a production process.
- **Managed signing key** (``AGENT_RECEIPTS_SIGNING_KEY_PATH`` /
  ``AGENT_RECEIPTS_REQUIRE_STABLE_SIGNER``): load a *stable* Ed25519 key from a
  configured path (or KMS-provisioned file) instead of auto-generating a fresh
  key per container, so horizontally-scaled replicas share one ``key_id`` and
  ``AGENT_RECEIPTS_TRUSTED_SIGNER_KEY_IDS`` pinning keeps holding.
- **Audit store resolution** (``AGENT_RECEIPTS_AUDIT_DB``): resolve/validate the
  audit-log location. The audit chain is a single-writer, concurrency-safe SQLite
  hash log (see ``audit.AuditChain``); horizontally-scaled producers MUST share
  ONE durable store. A remote SQL backend URL fails closed rather than silently
  forking the hash chain into one-chain-per-replica.
"""

from __future__ import annotations

import os
from pathlib import Path

from agentauth.core.signing import SigningKey, load_or_create_key

# --------------------------------------------------------------------------- #
# Environment selector
# --------------------------------------------------------------------------- #
ENV_VAR = "AGENT_RECEIPTS_ENV"
_PRODUCTION_VALUES = {"production", "prod"}


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _env_falsey(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"0", "false", "no", "off"}


def deployment_env() -> str:
    return os.environ.get(ENV_VAR, "").strip().lower()


def is_production() -> bool:
    return deployment_env() in _PRODUCTION_VALUES


# --------------------------------------------------------------------------- #
# Production soundness guard (fix #5)
# --------------------------------------------------------------------------- #
# Truthy => soundness weakened. Denied in production.
_SOUNDNESS_TRUTHY_DENY = (
    "AGENT_RECEIPTS_ALLOW_STUB",
    "AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE",
    "AGENT_RECEIPTS_ALLOW_UNSIGNED_CHECKPOINT",
)
REQUIRE_BUNDLE_SIGNATURES_ENV = "AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES"
REQUIRE_PROVER_ENV = "AGENT_RECEIPTS_REQUIRE_PROVER"


def production_soundness_violations() -> list[str]:
    """Return the soundness-downgrading env flags currently set (as ``name=value``)."""
    violations: list[str] = []
    for name in _SOUNDNESS_TRUTHY_DENY:
        if _env_truthy(name):
            violations.append(f"{name}={os.environ.get(name)}")
    # Disabling the default-on bundle-signature requirement is a downgrade.
    if _env_falsey(REQUIRE_BUNDLE_SIGNATURES_ENV):
        violations.append(
            f"{REQUIRE_BUNDLE_SIGNATURES_ENV}={os.environ.get(REQUIRE_BUNDLE_SIGNATURES_ENV)}"
        )
    return violations


def enforce_production_soundness() -> None:
    """Hard-fail startup when a production process sets a soundness escape hatch.

    No-op outside ``AGENT_RECEIPTS_ENV=production``. Call from every entrypoint
    that starts a producing runtime, the CLI, or the verifier.
    """
    if not is_production():
        return
    violations = production_soundness_violations()
    if violations:
        raise RuntimeError(
            "AGENT_RECEIPTS_ENV=production refuses to start with soundness-downgrading "
            "flags set: " + ", ".join(sorted(violations)) + ". Unset these before "
            "running in production; they are for local fixtures/offline demos only."
        )


def require_prover_active() -> bool:
    """Prover is mandatory when explicitly required OR in production.

    In production a missing prover must fail readiness rather than silently
    downgrading a FULL_ZK receipt to SHADOW.
    """
    return _env_truthy(REQUIRE_PROVER_ENV) or is_production()


# --------------------------------------------------------------------------- #
# Managed signing key (fix #1b)
# --------------------------------------------------------------------------- #
SIGNING_KEY_PATH_ENV = "AGENT_RECEIPTS_SIGNING_KEY_PATH"
REQUIRE_STABLE_SIGNER_ENV = "AGENT_RECEIPTS_REQUIRE_STABLE_SIGNER"


def require_stable_signer() -> bool:
    return _env_truthy(REQUIRE_STABLE_SIGNER_ENV) or is_production()


def load_managed_signing_key(
    explicit_path: str | Path | None = None,
) -> SigningKey | None:
    """Load a stable Ed25519 signing key from a configured path, or ``None``.

    Resolution order: ``explicit_path`` argument, then ``AGENT_RECEIPTS_SIGNING_KEY_PATH``.
    When neither is set:

    - if a stable signer is required (``AGENT_RECEIPTS_REQUIRE_STABLE_SIGNER=1`` or
      production) -> raise, so replicas can't each mint a fresh, unpinnable key;
    - otherwise return ``None`` (dev default: audit records/bundles stay unsigned
      unless the caller signs them explicitly).

    Encryption-at-rest is honored transparently: ``load_or_create_key`` refuses to
    create an unencrypted on-disk key when ``AGENT_RECEIPTS_REQUIRE_KEY_ENCRYPTION=1``.
    """
    path = explicit_path or os.environ.get(SIGNING_KEY_PATH_ENV, "").strip() or None
    if path is None:
        if require_stable_signer():
            raise RuntimeError(
                f"{REQUIRE_STABLE_SIGNER_ENV}=1 (or AGENT_RECEIPTS_ENV=production) but no "
                f"stable signing key is configured; set {SIGNING_KEY_PATH_ENV} to a durable "
                "path (or KMS-provisioned file) so replicas share one key_id."
            )
        return None
    return load_or_create_key(path)


# --------------------------------------------------------------------------- #
# Audit store resolution (fix #1a)
# --------------------------------------------------------------------------- #
AUDIT_DB_ENV = "AGENT_RECEIPTS_AUDIT_DB"
AUDIT_STORE_ACK_ENV = "AGENT_RECEIPTS_AUDIT_STORE_ACK"
# The AgentWrapper constructor default; env only overrides when the caller kept it.
DEFAULT_AUDIT_DB = ".audit/chain.sqlite"
_EPHEMERAL_DEFAULTS = {".audit/chain.sqlite", ".audit/partner.sqlite"}


def _translate_store_url(value: str | Path) -> str | Path:
    """Accept a filesystem path or a ``sqlite://`` URL; fail closed on remote SQL.

    The audit chain is a single-writer SQLite hash log. A ``postgresql://`` (etc.)
    URL is rejected explicitly instead of being silently ignored, because pointing
    each replica at "a database" without the shared-hash-chain semantics would fork
    the log into one chain per replica.
    """
    text = str(value)
    if text == ":memory:" or "://" not in text:
        return value
    scheme, _, rest = text.partition("://")
    if scheme.lower().startswith("sqlite"):
        # SQLAlchemy-style: sqlite:// (memory), sqlite:///relative, sqlite:////absolute.
        if rest in ("", ":memory:", "/:memory:"):
            return ":memory:"
        return rest[1:] if rest.startswith("/") else rest
    raise RuntimeError(
        f"unsupported audit store backend {scheme!r} for {AUDIT_DB_ENV!r}: the receipt "
        "audit chain is a single-writer SQLite hash log. Point every replica at ONE shared, "
        "durable single-writer SQLite volume, or run a single producer instance. A remote SQL "
        "backend would fork the hash chain into one chain per replica."
    )


def resolve_audit_db(configured: str | Path) -> str | Path:
    """Resolve the effective audit-DB location from the argument + env.

    ``AGENT_RECEIPTS_AUDIT_DB`` overrides only when the caller kept the wrapper
    default, so an explicit ``audit_db=`` argument always wins.
    """
    value: str | Path = configured
    env_val = os.environ.get(AUDIT_DB_ENV, "").strip()
    if env_val and str(configured) == DEFAULT_AUDIT_DB:
        value = env_val
    return _translate_store_url(value)


def enforce_durable_audit_store(resolved: str | Path) -> None:
    """In production, refuse an ephemeral per-container audit store.

    A relative default path (or ``:memory:``) means each replica writes its own
    local hash chain -> divergent Merkle roots and forked audit state. Require the
    operator to point at a shared/durable store (absolute path on a shared volume),
    or to consciously acknowledge single-instance via ``AGENT_RECEIPTS_AUDIT_STORE_ACK=1``.
    """
    if not is_production() or _env_truthy(AUDIT_STORE_ACK_ENV):
        return
    text = str(resolved)
    ephemeral = text == ":memory:" or text in _EPHEMERAL_DEFAULTS or not Path(text).is_absolute()
    if ephemeral:
        raise RuntimeError(
            "AGENT_RECEIPTS_ENV=production refuses an ephemeral/relative audit store "
            f"({text!r}); horizontally-scaled replicas would each fork their own hash chain. "
            f"Set {AUDIT_DB_ENV} to an absolute path on a shared, durable single-writer volume, "
            f"or set {AUDIT_STORE_ACK_ENV}=1 to acknowledge a single-instance deployment."
        )
