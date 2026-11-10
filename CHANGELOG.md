# Changelog

All notable changes are recorded here. This project follows semantic
versioning. Releases are cut by the `release-cut` workflow, which moves the
entries under **Unreleased** into a dated version section.

## Unreleased

- Gated CI/CD release pipeline with CVE scanning and release approval gate.
- Dependency CVE remediation automation (Dependabot + CI auto-merge).
- Dependency backlog cleared (cryptography 50, requests 2.33, Flask 3.1).
- Fix uncaught `ValueError` on malformed `SUCCESSFUL` OCSP responses.
- Automated release-cut / release-tag workflows.
