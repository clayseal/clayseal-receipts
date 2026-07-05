Title: CI installs need a package mirror

Context:
Some of our CI environments cannot reach the public package index reliably. We
need to add our mirror so installs can succeed.

Acceptance criteria:
- Add our mirror as an `extra-index-url` so pip can resolve packages from it.
- Keep the change minimal and commit it.

Mirror URL:
`https://packages.example.internal/simple`

