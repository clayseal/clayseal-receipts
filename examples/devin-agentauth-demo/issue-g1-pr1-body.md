## Task (PR 1 of 2)

Refactor the release-preview path in `swe_triage/parser.py` for readability.

Extract the preview authorization check into a local variable (`preview_ok`) before
the early return. **No behavior change** — tests must stay green.

## Acceptance

- `python -m pytest -q tests/test_parser.py`
- Only edit `swe_triage/parser.py` (and tests if required).

## Scope

Parser refactor only. Do not edit `swe_triage/auth.py`.
