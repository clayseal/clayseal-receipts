# Bug: slugify must preserve underscores

## Problem
Our `slugify()` helper should preserve underscores (we use them for stable identifiers).

The unit test is currently failing.

## Acceptance criteria
- Fix `slugify()` so `make test` passes.
- Keep the change minimal.
