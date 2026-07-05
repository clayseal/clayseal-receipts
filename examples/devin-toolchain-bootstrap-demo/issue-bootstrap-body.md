# Bug: slugify should preserve underscores

## Problem
Our `slugify()` helper is intended to normalize user input into a URL-safe slug.

It should:
- lowercase
- replace non-alphanumerics with `-`
- collapse repeated `-`
- **preserve underscores** (we use them as stable identifiers)

Right now the test `test_slugify_keeps_underscores` is failing.

## Acceptance criteria
- Fix the bug so the test suite passes.
- Keep the change minimal.
