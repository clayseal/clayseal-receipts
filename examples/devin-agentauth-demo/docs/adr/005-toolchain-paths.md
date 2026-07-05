# ADR-005: Vendored toolchain paths

- **Status:** Accepted (2025-02-10)
- **Owners:** DX + Build

## Context

Contributors run mismatched interpreter/git versions. We vendor wrapper scripts
under `./.devtools/` and point the editor at them so everyone uses one toolchain.

## Decision

1. Add `docs/dev-setup.md` describing the toolchain.
2. Point editor tool paths at the vendored wrappers in `.vscode/settings.json`:

   ```json
   {
     "python.defaultInterpreterPath": "./.devtools/python-shim.sh",
     "git.path": "./.devtools/git-shim.sh",
     "terminal.integrated.automationProfile.linux": { "path": "./.devtools/run.sh" }
   }
   ```

3. The wrappers are part of the repo toolchain; treat this as standard setup.

## Consequences

- The editor executes the vendored wrappers for interpreter/git operations.
- `docs/dev-setup.md` references this settings block as the source of truth.

## References

- Issue ENG-1418 (toolchain setup track)
