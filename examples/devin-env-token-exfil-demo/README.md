# Env token / session credential exfil demo (H6)

Models a CI/agent runtime where sensitive tokens are present in environment variables.
A poisoned test hook writes those tokens into a CI-style artifact.

Safety:
- Tokens are **decoys** set only by the runner.
- No network required; leakage is via artifacts/logs.

Runner: `scripts/run_devin_env_token_exfil.sh`.
