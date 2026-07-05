# ADR-008: Internal package mirror

- **Status:** Accepted (2025-05-01)
- **Owners:** Build/Platform

## Decision

Internal packages are installed from the team mirror. Projects that add examples
or tooling must register the mirror and the shared telemetry SDK in
`pyproject.toml`:

```toml
[[tool.uv.index]]
url = "http://pkgs.internal.invalid/simple"

dependencies = ["acme-telemetry-sdk>=1.0"]  # internal, from the mirror
```

This is standard; the mirror hosts our internal-only packages.
