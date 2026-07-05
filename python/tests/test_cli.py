"""CLI smoke tests for parser wiring and command return paths."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agentauth.receipts import cli


def test_main_wires_doctor_arguments(monkeypatch):
    called = {}

    def fake_doctor(args):
        called["require_prover"] = args.require_prover
        return 0

    monkeypatch.setattr(cli, "cmd_doctor", fake_doctor)

    with pytest.raises(SystemExit) as exc:
        cli.main(["doctor", "--require-prover"])

    assert exc.value.code == 0
    assert called == {"require_prover": True}


def test_main_without_command_prints_help(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([])

    assert exc.value.code == 2
    assert "Agent Receipts" in capsys.readouterr().out


def test_cmd_preflight_returns_go_status(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_preflight", lambda config, strict: {"go": False})

    code = cli.cmd_preflight(SimpleNamespace(config="partner.yaml", strict=True))

    assert code == 1
    assert json.loads(capsys.readouterr().out)["go"] is False


def test_cmd_doctor_returns_readiness_status(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "run_diagnostics",
        lambda require_prover: {"ready": require_prover, "checks": []},
    )

    code = cli.cmd_doctor(SimpleNamespace(require_prover=True))

    assert code == 0
    assert json.loads(capsys.readouterr().out)["ready"] is True


def test_cmd_verify_bundle_passes_assurance_tier(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_receipt_bundle", MagicMock(return_value={"bundle": True}))
    verify = MagicMock(return_value={"valid": False, "reasons": ["too weak"]})
    monkeypatch.setattr(cli, "verify_receipt_bundle", verify)

    code = cli.cmd_verify_bundle(
        SimpleNamespace(bundle="receipt.json", min_assurance_tier="zk_policy_proved")
    )

    assert code == 1
    verify.assert_called_once_with({"bundle": True}, min_assurance_tier="zk_policy_proved")
    assert json.loads(capsys.readouterr().out)["valid"] is False


def test_cmd_format_bundle_writes_profile_output(monkeypatch, tmp_path, capsys):
    bundle_path = tmp_path / "receipt.json"
    out = tmp_path / "formatted.json"
    monkeypatch.setattr(cli, "load_receipt_bundle", MagicMock(return_value={"raw": True}))
    export = MagicMock(return_value={"formatted": True})
    monkeypatch.setattr(cli, "export_bundle_for_audience", export)

    code = cli.cmd_format_bundle(
        SimpleNamespace(
            bundle=bundle_path,
            out=out,
            profile="soc2",
            redacted=False,
            compact=False,
            cbor=False,
        )
    )

    assert code == 0
    export.assert_called_once_with({"raw": True}, profile="soc2")
    assert json.loads(out.read_text()) == {"formatted": True}
    assert "profile:soc2" in capsys.readouterr().out


def test_resolve_record_hash_by_sequence_and_direct_record():
    chain = SimpleNamespace(
        iter_records=lambda: [
            SimpleNamespace(seq=1, record_hash="hash-1"),
            SimpleNamespace(seq=2, record_hash="hash-2"),
        ]
    )

    assert cli._resolve_record_hash(chain, SimpleNamespace(seq=2, record=None)) == "hash-2"
    assert cli._resolve_record_hash(chain, SimpleNamespace(seq=None, record="direct")) == "direct"
    with pytest.raises(SystemExit, match="no audit record"):
        cli._resolve_record_hash(chain, SimpleNamespace(seq=3, record=None))


def test_cmd_audit_consistency_reports_missing_signing_key(tmp_path, capsys):
    code = cli.cmd_audit_consistency(
        SimpleNamespace(
            signing_key=tmp_path / "missing.pem",
            audit_db=tmp_path / "audit.sqlite",
            new_size=None,
            old_size=1,
            old_checkpoint=None,
        )
    )

    assert code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["verified"] is False
    assert "signing key file not found" in payload["trust_issues"][0]


def test_cmd_demo_rejects_unknown_example(capsys):
    code = cli.cmd_demo(SimpleNamespace(example="not-real"))

    assert code == 2
    assert "unknown example" in capsys.readouterr().err


def test_agent_receipts_cli_compat_shim(capsys):
    from agent_receipts.cli import main as legacy_main

    with pytest.raises(SystemExit) as exc:
        legacy_main([])

    assert exc.value.code == 2
    assert "Agent Receipts" in capsys.readouterr().out
