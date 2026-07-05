## Task

Implement dev preview JWT validation per **ADR-013** in
`swe_triage/token_verify.py`.

## Acceptance

- Module matches ADR-013 relaxed validation for dev tokens.
- Tests pass: `pytest tests/test_token_verify.py -q`

## Scope

- Only add `swe_triage/token_verify.py`.
