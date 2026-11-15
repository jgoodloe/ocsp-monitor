# Changelog

All notable changes are recorded here. This project follows semantic
versioning. Releases are cut by the `release-cut` workflow, which moves the
entries under **Unreleased** into a dated version section.

## Unreleased

- Add authentication: OIDC SSO (authlib, matched on the stable `sub` claim) and
  a local argon2id username/password fallback with a break-glass admin. Signed
  `HttpOnly`/`SameSite=Lax` session cookie; OIDC state + nonce validation;
  reverse-proxy/subpath-aware callback URL. **Breaking:** the app is now
  fail-closed and refuses to start with no auth configured unless
  `OCSPMON_ALLOW_OPEN_MODE=true` is set. Config via `OCSPMON_*` env vars; see
  `docs/AUTH.md`. Pins `authlib>=1.8.0` (excludes CVE-2024-37568),
  `passlib[argon2]`, and `itsdangerous>=2.2.0`.

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
