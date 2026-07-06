"""Go/no-go checks before design partner deployment."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from agentauth.receipts._version import __version__
from agentauth.receipts.certificate import load_certificate
from agentauth.receipts.diagnostics import run_diagnostics
from agentauth.receipts.partner_config import PartnerConfig
from agentauth.receipts.policy import Policy


def _check(name: str, ok: bool, detail: str, *, blocking: bool = True) -> dict[str, Any]:
    return {"name": name, "ok": ok, "blocking": blocking, "detail": detail}


def run_preflight(
    config_path: str | Path,
    *,
    strict: bool | None = None,
) -> dict[str, Any]:
    """
    Validate partner config, policy, filesystem, and prover readiness.

    Returns {"go": bool, "checks": [...]} suitable for CI and `arctl preflight`.
    """
    path = Path(config_path).resolve()
    checks: list[dict[str, Any]] = []

    if not path.is_file():
        checks.append(_check("config_file", False, f"missing: {path}"))
        return _finalize(checks)

    try:
        cfg = PartnerConfig.from_yaml(path)
        cfg.validate(strict=strict)
        checks.append(_check("config_valid", True, str(path)))
    except Exception as exc:
        checks.append(_check("config_valid", False, str(exc)))
        return _finalize(checks)

    try:
        policy = Policy.from_yaml(cfg.policy_path)
        checks.append(_check("policy_load", True, f"{policy.name} commitment ok"))
    except Exception as exc:
        checks.append(_check("policy_load", False, str(exc)))
        return _finalize(checks)

    # audit + receipts dirs
    for label, dir_path in (
        ("audit_dir", cfg.audit_db.parent),
        ("receipts_dir", cfg.config_dir.parent / "receipts"),
    ):
        try:
            dir_path.mkdir(parents=True, exist_ok=True)
            probe = dir_path / ".write_probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            checks.append(_check(f"{label}_writable", True, str(dir_path)))
        except OSError as exc:
            checks.append(_check(f"{label}_writable", False, str(exc)))

    if cfg.certificate_path and cfg.certificate_path.is_file():
        try:
            cert = load_certificate(cfg.certificate_path)
            if cert.policy_commitment != policy.commitment():
                checks.append(
                    _check(
                        "certificate_policy_match",
                        False,
                        "certificate policy_commitment != current policy",
                    )
                )
            elif not cert.is_valid_at():
                checks.append(_check("certificate_validity", False, "certificate expired"))
            else:
                checks.append(_check("certificate", True, str(cfg.certificate_path)))
        except Exception as exc:
            checks.append(_check("certificate", False, str(exc)))
    elif cfg.persist_certificate:
        checks.append(
            _check(
                "certificate_persist_path",
                True,
                f"will create on first run: {cfg.persist_certificate}",
                blocking=False,
            )
        )

    if cfg.require_identity_binding:
        # The attested identity is injected at runtime by AgentSession.wrap(...), not by
        # this config, so preflight can only confirm the guard is armed. Receipts produced
        # by a directly-constructed (unbound) AgentWrapper will now fail at run time.
        checks.append(
            _check(
                "identity_binding_required",
                True,
                "require_identity_binding=true: receipts MUST be produced via "
                "AgentSession.wrap(...) (attested identity); unbound wrappers fail at run time",
                blocking=False,
            )
        )

    require_prover = cfg.mode == "prove"
    diag = run_diagnostics(require_prover=require_prover)
    checks.append(
        _check(
            "environment",
            diag["ready"],
            json.dumps(diag.get("required_failures", [])),
        )
    )
    if require_prover:
        checks.append(
            _check(
                "prove_ready",
                bool(diag.get("prove_ready")),
                "prover CLI and Halo2 keys required for prove mode",
            )
        )

    verifier_key = os.environ.get("AGENT_RECEIPTS_VERIFIER_API_KEY", "").strip()
    if strict and not verifier_key:
        checks.append(
            _check(
                "verifier_api_key",
                False,
                "set AGENT_RECEIPTS_VERIFIER_API_KEY in strict deployment",
                blocking=False,
            )
        )
    else:
        checks.append(
            _check(
                "verifier_api_key",
                True,
                "configured" if verifier_key else "not set (open verifier)",
                blocking=False,
            )
        )

    checks.append(
        _check("sdk_version", True, __version__, blocking=False),
    )

    return _finalize(checks)


def _finalize(checks: list[dict[str, Any]]) -> dict[str, Any]:
    blocking_failures = [c["name"] for c in checks if c["blocking"] and not c["ok"]]
    warnings = [c["name"] for c in checks if not c["blocking"] and not c["ok"]]
    return {
        "go": len(blocking_failures) == 0,
        "blocking_failures": blocking_failures,
        "warnings": warnings,
        "checks": checks,
    }
