from pathlib import Path

import pytest

from agentauth.receipts.partner_config import PartnerConfig
from agentauth.receipts.preflight import run_preflight

ROOT = Path(__file__).resolve().parents[2]


def test_preflight_example_config(tmp_path: Path):
    cfg_src = ROOT / "config" / "partner.example.yaml"
    dest = tmp_path / "partner.yaml"
    text = cfg_src.read_text()
    text = text.replace("../policies/", str(ROOT / "policies") + "/")
    text = text.replace("../.audit/", str(tmp_path / ".audit") + "/")
    text = text.replace("../certs/", str(tmp_path / "certs") + "/")
    dest.write_text(text)
    report = run_preflight(dest)
    assert "config_valid" in {c["name"] for c in report["checks"]}


def test_strict_rejects_placeholder(tmp_path: Path):
    policy_path = ROOT / "policies" / "fraud_decision.yaml"
    cfg = tmp_path / "partner.yaml"
    cfg.write_text(
        f"""
policy_path: {policy_path}
audit_db: {tmp_path / "audit.sqlite"}
mode: shadow
model_provenance_hash: sha256:REPLACE_WITH_MODEL_ARTIFACT_HASH
organization: your-org
principal_id: partner-agent
strict: true
"""
    )
    with pytest.raises(ValueError, match="model_provenance_hash"):
        PartnerConfig.from_yaml(cfg).validate(strict=True)


def test_partner_config_env_overrides_paths_and_booleans(tmp_path: Path, monkeypatch):
    policy_path = ROOT / "policies" / "fraud_decision.yaml"
    cfg = tmp_path / "partner.yaml"
    cfg.write_text(
        f"""
policy_path: {policy_path}
audit_db: local.sqlite
mode: shadow
model_provenance_hash: sha256:from-file
organization: from-file
principal_id: file-agent
prove_recursive: false
"""
    )
    monkeypatch.setenv("AGENT_RECEIPTS_MODE", "prove")
    monkeypatch.setenv("AGENT_RECEIPTS_AUDIT_DB", str(tmp_path / "override.sqlite"))
    monkeypatch.setenv("AGENT_RECEIPTS_MODEL_HASH", "sha256:override")
    monkeypatch.setenv("AGENT_RECEIPTS_ORGANIZATION", "risk-prod")
    monkeypatch.setenv("AGENT_RECEIPTS_PRINCIPAL_ID", "risk-agent")
    monkeypatch.setenv("AGENT_RECEIPTS_PERSIST_CERTIFICATE", "certs/agent.json")
    monkeypatch.setenv("AGENT_RECEIPTS_INFERENCE_BACKEND", "risc0")
    monkeypatch.setenv("AGENT_RECEIPTS_PROVE_RECURSIVE", "yes")
    monkeypatch.setenv("AGENT_RECEIPTS_STRICT", "true")

    loaded = PartnerConfig.from_yaml(cfg)

    assert loaded.mode == "prove"
    assert loaded.audit_db == tmp_path / "override.sqlite"
    assert loaded.model_provenance_hash == "sha256:override"
    assert loaded.organization == "risk-prod"
    assert loaded.principal_id == "risk-agent"
    assert loaded.persist_certificate == tmp_path / "certs" / "agent.json"
    assert loaded.prove_recursive is True
    assert loaded.strict is True
    assert loaded.to_agent_kwargs()["inference_backend"] == "risc0"


def test_partner_config_rejects_invalid_prove_configuration(tmp_path: Path):
    cfg = tmp_path / "partner.yaml"
    cfg.write_text(
        f"""
policy_path: {ROOT / "policies" / "fraud_decision.yaml"}
mode: prove
prove_policy: false
prove_composed: false
inference_backend: ezkl
"""
    )

    with pytest.raises(ValueError, match="prove mode requires"):
        PartnerConfig.from_yaml(cfg).validate()


def test_partner_config_rejects_invalid_inference_backend(tmp_path: Path):
    cfg = tmp_path / "partner.yaml"
    cfg.write_text(
        f"""
policy_path: {ROOT / "policies" / "fraud_decision.yaml"}
mode: shadow
inference_backend: made-up
"""
    )

    with pytest.raises(ValueError, match="invalid inference_backend"):
        PartnerConfig.from_yaml(cfg).validate()


def test_preflight_missing_config_fails_fast(tmp_path: Path):
    report = run_preflight(tmp_path / "missing.yaml")

    assert report["go"] is False
    assert report["blocking_failures"] == ["config_file"]
    assert report["checks"][0]["detail"].startswith("missing:")


def test_preflight_invalid_config_fails_before_policy_load(tmp_path: Path):
    cfg = tmp_path / "partner.yaml"
    cfg.write_text("mode: invalid\n")

    report = run_preflight(cfg)

    assert report["go"] is False
    assert report["blocking_failures"] == ["config_valid"]
    assert [check["name"] for check in report["checks"]] == ["config_valid"]
