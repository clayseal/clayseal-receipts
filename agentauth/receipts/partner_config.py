"""YAML configuration for design partner deployments."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from agentauth.receipts.wrapper import OperatingMode

DEFAULT_POLICY = "policies/fraud_decision.yaml"
PLACEHOLDER_MODEL_HASHES = frozenset(
    {
        "sha256:your-model-version-here",
        "sha256:REPLACE_WITH_MODEL_ARTIFACT_HASH",
    }
)
PLACEHOLDER_ORGS = frozenset({"your-org", "partner-org", "dev-org"})


@dataclass
class PartnerConfig:
    """Loaded partner settings (paths resolved relative to config file)."""

    policy_path: Path
    audit_db: Path
    mode: OperatingMode
    certificate_path: Path | None
    persist_certificate: Path | None
    model_provenance_hash: str
    prove_policy: bool | None
    prove_inference: bool | None
    prove_composed: bool | None
    prove_recursive: bool
    inference_backend: str
    organization: str
    principal_id: str
    strict: bool
    config_dir: Path
    config_path: Path

    @classmethod
    def from_yaml(cls, path: str | Path) -> PartnerConfig:
        config_path = Path(path).resolve()
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        raw = _apply_env_overrides(raw)
        base = config_path.parent

        def resolve(p: str | None, default: str) -> Path:
            value = p or default
            candidate = Path(value)
            if candidate.is_absolute():
                return candidate
            return (base / candidate).resolve()

        mode_raw = str(raw.get("mode", "shadow"))
        if mode_raw not in ("shadow", "recommend", "bounded_auto", "prove"):
            raise ValueError(f"invalid mode: {mode_raw}")

        cert = raw.get("certificate_path")
        persist = raw.get("persist_certificate")
        return cls(
            policy_path=resolve(raw.get("policy_path"), DEFAULT_POLICY),
            audit_db=resolve(raw.get("audit_db"), ".audit/partner.sqlite"),
            mode=mode_raw,  # type: ignore[assignment]
            certificate_path=resolve(cert, "").resolve() if cert else None,
            persist_certificate=resolve(persist, "").resolve() if persist else None,
            model_provenance_hash=str(
                raw.get("model_provenance_hash", "sha256:model-dev-v1")
            ),
            prove_policy=raw.get("prove_policy"),
            prove_inference=raw.get("prove_inference"),
            prove_composed=raw.get("prove_composed"),
            prove_recursive=bool(raw.get("prove_recursive", False)),
            inference_backend=str(raw.get("inference_backend", "ezkl")),
            organization=str(raw.get("organization", "partner-org")),
            principal_id=str(raw.get("principal_id", "partner-agent")),
            strict=bool(raw.get("strict", False)),
            config_dir=base,
            config_path=config_path,
        )

    def validate(self, *, strict: bool | None = None) -> None:
        """Raise ValueError if config is unsuitable for deployment."""
        use_strict = self.strict if strict is None else strict
        if use_strict and self.model_provenance_hash in PLACEHOLDER_MODEL_HASHES:
            raise ValueError(
                "model_provenance_hash is still a placeholder; set your model artifact hash"
            )
        if use_strict:
            if self.organization in PLACEHOLDER_ORGS:
                raise ValueError("organization is a placeholder; set your org id")
            if self.principal_id in ("partner-agent", "your-agent-principal", "dev-principal"):
                raise ValueError("principal_id is a placeholder; set your agent principal")
        if self.mode == "prove" and self.prove_composed is False and self.prove_policy is False:
            raise ValueError("prove mode requires prove_policy or prove_composed enabled")
        if self.inference_backend not in ("ezkl", "risc0", "sp1"):
            raise ValueError(
                f"invalid inference_backend: {self.inference_backend!r}; expected ezkl, risc0, or sp1"
            )

    def effective_certificate_path(self) -> Path | None:
        """Path to load/save certificate: explicit path wins, else persist path."""
        return self.certificate_path or self.persist_certificate

    def to_agent_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "policy": None,
            "mode": self.mode,
            "audit_db": self.audit_db,
            "model_provenance_hash": self.model_provenance_hash,
        }
        cert_path = self.effective_certificate_path()
        if cert_path is not None:
            kwargs["certificate_path"] = cert_path
        if self.prove_policy is not None:
            kwargs["prove_policy"] = self.prove_policy
        if self.prove_inference is not None:
            kwargs["prove_inference"] = self.prove_inference
        if self.prove_composed is not None:
            kwargs["prove_composed"] = self.prove_composed
        if self.prove_recursive:
            kwargs["prove_recursive"] = self.prove_recursive
        if self.inference_backend != "ezkl":
            kwargs["inference_backend"] = self.inference_backend
        return kwargs


def _apply_env_overrides(raw: dict[str, Any]) -> dict[str, Any]:
    """12-factor overrides for container/K8s deployments."""
    out = dict(raw)
    mapping = {
        "AGENT_RECEIPTS_MODE": "mode",
        "AGENT_RECEIPTS_POLICY_PATH": "policy_path",
        "AGENT_RECEIPTS_AUDIT_DB": "audit_db",
        "AGENT_RECEIPTS_MODEL_HASH": "model_provenance_hash",
        "AGENT_RECEIPTS_ORGANIZATION": "organization",
        "AGENT_RECEIPTS_PRINCIPAL_ID": "principal_id",
        "AGENT_RECEIPTS_CERTIFICATE_PATH": "certificate_path",
        "AGENT_RECEIPTS_PERSIST_CERTIFICATE": "persist_certificate",
        "AGENT_RECEIPTS_INFERENCE_BACKEND": "inference_backend",
    }
    for env_key, field in mapping.items():
        val = os.environ.get(env_key)
        if val:
            out[field] = val
    if os.environ.get("AGENT_RECEIPTS_STRICT", "").lower() in ("1", "true", "yes"):
        out["strict"] = True
    prove_recursive = _env_bool("AGENT_RECEIPTS_PROVE_RECURSIVE")
    if prove_recursive is not None:
        out["prove_recursive"] = prove_recursive
    return out


def _env_bool(key: str) -> bool | None:
    val = os.environ.get(key)
    if val is None:
        return None
    return val.lower() in ("1", "true", "yes")
