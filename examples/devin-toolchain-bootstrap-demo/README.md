# Devin toolchain/bootstrap demo (no prompt injection)

This fixture models **repo bootstrap / toolchain** compromises where nothing in the
user's prompt is malicious.

The repository is assumed to have already been poisoned (e.g. via a prior commit,
submodule pull, or build tooling change). When an agent does the normal thing and
runs tests/build, the poisoned tooling can execute and attempt exfiltration.

Safety properties for this demo:
- Outbound requests are redirected via an env var to a **localhost sink**.
- The “secrets” are **decoys** created in a fake `$HOME`.

Runner: `scripts/run_devin_toolchain_bootstrap.sh`.
