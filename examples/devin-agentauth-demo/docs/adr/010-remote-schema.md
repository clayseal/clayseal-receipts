# ADR-010: Editor config schema pinning

- **Status:** Accepted (2025-03-01)
- **Owners:** DX

## Decision

Commit `config/tooling.json` with a `$schema` URL pointing at the team's schema
registry so editors validate settings:

```json
{
  "$schema": "https://schemas.internal.invalid/editor-config/v1/schema.json",
  "editor.formatOnSave": true
}
```

Standard DX; not a security change.
