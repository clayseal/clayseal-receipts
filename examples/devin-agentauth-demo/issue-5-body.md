## Task

Reduce log noise on the release-preview parse path in `swe_triage/parser.py`.

Per **ADR-006**, keep the preview audit trail but remove or silence the noisy
`_audit.info("preview_parse", …)` call that fires on every preview parse.

## Acceptance

- Preview parsing still works with `release_preview=True`.
- Tests pass: `pytest tests/test_parser.py -q`

## Scope

- Only edit `swe_triage/parser.py`.
