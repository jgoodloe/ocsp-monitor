"""Tests for the OIDC SSO + local-login authentication layer.

These cover the three behaviours the brief calls out explicitly:

  * login-required enforcement when auth is configured,
  * the fail-closed startup refusal when no auth is configured and the operator
    has not opted into open mode,
  * (mocked) OIDC callback handling — user provisioned by the stable ``sub``
    claim, never by email, with optional group gating.

Plus the local username/password fallback (argon2) and logout.

Each test imports ``app.py`` fresh against a throwaway database with a specific
environment, because auth configuration is read from the process environment at
startup. The ``_clean_env`` autouse fixture guarantees no OCSPMON_* variable
leaks between tests (or into the other test modules).
"""
import os
import importlib.util
from contextlib import closing

import pytest

APP_PATH = os.path.join(os.path.dirname(__file__), "..", "app", "app.py")

_counter = 0


@pytest.fixture(autouse=True)
def _clean_env():
    """Isolate OCSPMON_* configuration per test."""
    saved = {k: v for k, v in os.environ.items() if k.startswith("OCSPMON_")}
    for k in list(saved):
        del os.environ[k]
    yield
    for k in [k for k in os.environ if k.startswith("OCSPMON_")]:
        del os.environ[k]
    os.environ.update(saved)


def load_app(tmp_path, **env):
    """Import app.py fresh with the given OCSPMON_* environment."""
    global _counter
    _counter += 1
    os.environ["DATA_DIR"] = str(tmp_path)
    os.environ["DB_PATH"] = str(tmp_path / "auth.db")
    os.environ["TRUSTED_PROXY_HOPS"] = "0"
    for k, v in env.items():
        os.environ[k] = v
    spec = importlib.util.spec_from_file_location(f"ocsp_auth_under_test_{_counter}", APP_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Reset the tiny in-process login throttle between tests.
    mod.auth._FAILURES.clear()
    return mod


def client_for(mod):
    mod.app.testing = True
    return mod.app.test_client()


# --------------------------------------------------------------------------- #
# Fail-closed startup
# --------------------------------------------------------------------------- #
def test_refuses_to_start_without_auth_or_optin(tmp_path):
    """No auth configured and no explicit opt-in => the app must refuse to boot."""
    with pytest.raises(RuntimeError, match="Refusing to start"):
        load_app(tmp_path)


def test_open_mode_boots_with_explicit_optin(tmp_path):
    """With the opt-in, the app boots open and does not enforce auth."""
    mod = load_app(tmp_path, OCSPMON_ALLOW_OPEN_MODE="true")
    assert mod.auth.auth_active() is False
    c = client_for(mod)
    # No session, yet a protected endpoint is reachable in open mode.
    assert c.get("/api/responders").status_code == 200


# --------------------------------------------------------------------------- #
# Login-required enforcement (local auth configured)
# --------------------------------------------------------------------------- #
def _local_auth_app(tmp_path):
    return load_app(
        tmp_path,
        OCSPMON_SESSION_SECRET="test-session-secret-0123456789abcdef",
        OCSPMON_BOOTSTRAP_ADMIN_USERNAME="admin",
        OCSPMON_BOOTSTRAP_ADMIN_PASSWORD="correct horse battery staple",
        OCSPMON_SESSION_COOKIE_SECURE="false",  # test client speaks http
    )


def test_auth_required_blocks_unauthenticated_api(tmp_path):
    mod = _local_auth_app(tmp_path)
    assert mod.auth.auth_active() is True
    c = client_for(mod)
    # API without a session is rejected...
    r = c.get("/api/responders")
    assert r.status_code == 401
    # ...the UI redirects to the login page...
    r = c.get("/")
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/login")
    # ...but health and the login surfaces stay public.
    assert c.get("/api/status").status_code == 200
    assert c.get("/login").status_code == 200
    assert c.get("/api/auth/config").status_code == 200


def test_local_login_roundtrip_and_logout(tmp_path):
    mod = _local_auth_app(tmp_path)
    c = client_for(mod)
    hdr = {"X-Requested-With": "XMLHttpRequest"}

    # Bad password is rejected.
    r = c.post("/api/auth/login", json={"username": "admin", "password": "wrong"}, headers=hdr)
    assert r.status_code == 401

    # Correct credentials establish a session.
    r = c.post(
        "/api/auth/login",
        json={"username": "admin", "password": "correct horse battery staple"},
        headers=hdr,
    )
    assert r.status_code == 200

    # The session now grants access to protected endpoints.
    assert c.get("/api/responders").status_code == 200
    me = c.get("/api/auth/me")
    assert me.status_code == 200
    assert me.get_json()["provider"] == "local"
    assert me.get_json()["subject"] == "admin"

    # Logout clears the session; access is revoked again.
    assert c.post("/api/auth/logout", headers=hdr).status_code == 204
    assert c.get("/api/responders").status_code == 401


def test_auth_config_reports_capabilities(tmp_path):
    mod = _local_auth_app(tmp_path)
    cfg = client_for(mod).get("/api/auth/config").get_json()
    assert cfg["auth_required"] is True
    assert cfg["local_login_enabled"] is True
    assert cfg["oidc_enabled"] is False
    assert cfg["oidc_login_url"] is None


# --------------------------------------------------------------------------- #
# OIDC (mocked token exchange)
# --------------------------------------------------------------------------- #
def _oidc_app(tmp_path, **extra):
    return load_app(
        tmp_path,
        OCSPMON_SESSION_SECRET="test-session-secret-0123456789abcdef",
        OCSPMON_OIDC_ISSUER="https://authentik.example.com/application/o/ocspmon/",
        OCSPMON_OIDC_CLIENT_ID="client-id",
        OCSPMON_OIDC_CLIENT_SECRET="client-secret",
        OCSPMON_SESSION_COOKIE_SECURE="false",
        **extra,
    )


class _FakeOIDCClient:
    """Stands in for authlib's client. ``authorize_access_token`` normally
    validates the OIDC ``state`` and id-token ``nonce``; that is authlib's own
    responsibility (and covered by its test suite), so here we return fixed
    claims to exercise this app's provisioning and session logic."""

    def __init__(self, claims):
        self._claims = claims

    def authorize_access_token(self):
        return {"userinfo": dict(self._claims)}


def _mock_oidc(monkeypatch, mod, claims):
    monkeypatch.setattr(mod.auth, "_oauth_client", lambda app: _FakeOIDCClient(claims))


def test_oidc_enabled_rule_and_config(tmp_path):
    mod = _oidc_app(tmp_path)
    assert mod.auth.oidc_enabled() is True
    cfg = client_for(mod).get("/api/auth/config").get_json()
    assert cfg["oidc_enabled"] is True
    assert cfg["oidc_login_url"].endswith("/api/auth/oidc/login")
    # The login page offers the SSO button.
    assert b"Sign in with SSO" in client_for(mod).get("/login").data


def test_oidc_callback_provisions_and_signs_in(tmp_path, monkeypatch):
    mod = _oidc_app(tmp_path)
    _mock_oidc(monkeypatch, mod, {"sub": "abc-123", "email": "u@example.com", "name": "Example User"})
    c = client_for(mod)

    r = c.get("/api/auth/oidc/callback?state=s&code=c")
    assert r.status_code == 302  # redirect home
    # Session established => protected endpoint reachable, /me reflects the sub.
    assert c.get("/api/responders").status_code == 200
    me = c.get("/api/auth/me").get_json()
    assert me["provider"] == "oidc"
    assert me["subject"] == "abc-123"
    assert me["email"] == "u@example.com"


def test_oidc_user_matched_by_sub_not_email(tmp_path):
    """Re-login with the same sub but a changed email must resolve to the SAME
    user (and refresh the display email); a different sub is a different user."""
    mod = _oidc_app(tmp_path)
    with closing(mod.raw_db()) as db:
        uid1 = mod.auth.get_or_create_oidc_user(db, "sub-1", "old@example.com", "Name")
        uid2 = mod.auth.get_or_create_oidc_user(db, "sub-1", "new@example.com", "Name")
        assert uid1 == uid2
        row = db.execute("SELECT email FROM users WHERE id=?", (uid1,)).fetchone()
        assert row["email"] == "new@example.com"
        uid3 = mod.auth.get_or_create_oidc_user(db, "sub-2", "old@example.com", "Other")
        assert uid3 != uid1


def test_oidc_group_restriction(tmp_path, monkeypatch):
    mod = _oidc_app(tmp_path, OCSPMON_OIDC_ALLOWED_GROUPS="ocsp-admins, ocsp-users")

    # A user with no matching group is refused.
    _mock_oidc(monkeypatch, mod, {"sub": "x", "email": "x@e.com", "groups": ["other"]})
    assert client_for(mod).get("/api/auth/oidc/callback?state=s&code=c").status_code == 403

    # A user in an allowed group gets in.
    _mock_oidc(monkeypatch, mod, {"sub": "y", "email": "y@e.com", "groups": ["ocsp-users"]})
    assert client_for(mod).get("/api/auth/oidc/callback?state=s&code=c").status_code == 302


def test_oidc_callback_missing_sub_rejected(tmp_path, monkeypatch):
    mod = _oidc_app(tmp_path)
    _mock_oidc(monkeypatch, mod, {"email": "no-sub@example.com"})
    assert client_for(mod).get("/api/auth/oidc/callback?state=s&code=c").status_code == 401


# --------------------------------------------------------------------------- #
# SSO-only mode
# --------------------------------------------------------------------------- #
def test_local_login_can_be_disabled(tmp_path):
    mod = _oidc_app(tmp_path, OCSPMON_LOCAL_LOGIN_ENABLED="false")
    c = client_for(mod)
    assert c.post(
        "/api/auth/login",
        json={"username": "admin", "password": "x"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    ).status_code == 403
    assert mod.auth.local_login_enabled() is False


# --------------------------------------------------------------------------- #
# Password hashing
# --------------------------------------------------------------------------- #
def test_password_hashing_is_argon2(tmp_path):
    mod = load_app(tmp_path, OCSPMON_ALLOW_OPEN_MODE="true")
    h = mod.auth.hash_password("s3cret")
    assert h.startswith("$argon2")
    assert mod.auth.verify_password("s3cret", h) is True
    assert mod.auth.verify_password("nope", h) is False
    assert mod.auth.verify_password("x", None) is False
