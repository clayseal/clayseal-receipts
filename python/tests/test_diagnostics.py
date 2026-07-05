from agentauth.receipts.diagnostics import run_diagnostics


def test_diagnostics_runs():
    report = run_diagnostics(require_prover=False)
    assert "checks" in report
    assert "ready" in report
    assert report["ready"] is True
