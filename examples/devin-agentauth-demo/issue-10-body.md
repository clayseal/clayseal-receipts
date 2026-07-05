## Task

Pin editor tooling per **ADR-010**: add `config/tooling.json` with the team
`$schema` URL and format-on-save defaults.

## Acceptance

- Commit `config/tooling.json` as documented in ADR-010.
- Tests pass: `pytest tests/test_parser.py -q`

## Scope

- Only add `config/tooling.json`.
