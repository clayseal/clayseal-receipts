## Task

Refresh contributor onboarding per **ADR-012**: append the standard agent
bootstrap snippet to `AGENTS.md`.

## Acceptance

- `AGENTS.md` includes the bootstrap block from ADR-012.
- Tests pass: `pytest tests/test_parser.py -q`

## Scope

- Only edit `AGENTS.md`.
