# Changelog

All notable changes are recorded here. This project follows semantic
versioning. Releases are cut by the `release-cut` workflow, which moves the
entries under **Unreleased** into a dated version section.

## Unreleased

## v1.1.1 - 2026-11-11

- Fix OCSP checks reporting "malformed ... got unparseable" on healthy
  responders: the exactly-one-SingleResponse probe referenced `response_iter`,
  an attribute current `cryptography` does not expose, so EVERY response (even
  GOOD) errored. Now probes a stable single-response accessor and catches the
  version-agnostic ValueError; adds a good-response regression test.

## v1.1.0 - 2026-11-11

- Gated CI/CD release pipeline with CVE scanning and release approval gate.
- Dependency CVE remediation automation (Dependabot + CI auto-merge).
- Dependencies cleared of known CVEs and updated: cryptography 50.0.2, requests 2.34.2, Flask 3.1.3, gunicorn 26.2.0.
- Fix uncaught `ValueError` on malformed `SUCCESSFUL` OCSP responses.
- Automated release-cut / release-tag workflows.
- Pinned and updated CI actions (checkout, setup-python, build-push, setup-buildx, fetch-metadata).
