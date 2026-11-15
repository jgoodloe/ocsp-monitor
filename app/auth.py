"""OIDC SSO + local login for OCSP Monitor.

Adapted from the reference implementation in ``jgoodloe/ocspcrltesting``
(``backend/app``: ``api/auth.py``, ``authz.py``, ``provisioning.py``,
``security.py`` and ``docs/AUTH.md``), reworked for THIS app's stack and model:

  * Single-process **Flask + SQLite**, not FastAPI/async/Postgres.
  * **No roles or workspaces** — so, per the brief, any authenticated user gets
    full access. An optional ``OCSPMON_OIDC_ALLOWED_GROUPS`` restricts who may
    sign in via the IdP (the single-knob analogue of the reference's
    group→role mapping).

Behaviours preserved from the reference:

  * OIDC (authlib's OpenID Connect client) against a standard issuer (authentik).
    Users are identified by the stable ``sub`` claim, **never** by email.
  * A local username/password fallback (argon2id via passlib) so the app is
    usable without an IdP; a break-glass admin is provisioned from env.
  * **Fail closed**: if no auth is configured the app refuses to start unless
    ``OCSPMON_ALLOW_OPEN_MODE=true`` is set — it never silently runs open on a
    network.
  * Config purely from environment variables, prefixed ``OCSPMON_``. Secrets
    live only in the environment and are never logged.
  * The OIDC flow uses ``state`` + ``nonce`` validation (handled by authlib),
    a secure/httponly/SameSite=Lax signed session cookie, and derives its
    callback URL from ``OCSPMON_PUBLIC_BASE_URL`` or the forwarded host headers,
    so it is correct behind an HTTPS reverse proxy under a subpath.

authlib is pinned ``>=1.8.0`` in requirements.txt, which is above the fix for
CVE-2024-37568 (JWS algorithm-confusion / OIDC ID-token forgery).
"""
from __future__ import annotations

import logging
import os
import secrets
import time
from contextlib import closing
from datetime import datetime, timezone

from flask import (
    abort, current_app, jsonify, redirect, render_template, request,
    session as flask_session, url_for,
)
from itsdangerous import BadSignature
from passlib.context import CryptContext

log = logging.getLogger("ocsp-monitor.auth")

# argon2id for local passwords (matches the reference's passlib context).
_pwd = CryptContext(schemes=["argon2"], deprecated="auto")

# DB accessors injected by init_app() so this module stays decoupled from app.py.
_get_db = None
_raw_db = None
_now_iso = None

# Per-process ephemeral session key, used only when auth is on but no stable
# OCSPMON_SESSION_SECRET was provided (sessions then don't survive a restart).
_EPHEMERAL_KEY = None


# --------------------------------------------------------------------------- #
# Configuration (env, OCSPMON_ prefix). Read live so tests can re-import with
# different environments without any global cache to clear.
# --------------------------------------------------------------------------- #
def _env(name, default=""):
    return os.environ.get(name, default)


def _env_bool(name, default):
    return _env(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _url_prefix():
    return _env("URL_PREFIX", "").rstrip("/")


def session_secret():
    return _env("OCSPMON_SESSION_SECRET")


def session_ttl_seconds():
    try:
        return max(300, int(_env("OCSPMON_SESSION_TTL_SECONDS", str(8 * 3600))))
    except ValueError:
        return 8 * 3600


def session_cookie_name():
    return _env("OCSPMON_SESSION_COOKIE_NAME", "ocspmon_session")


def session_cookie_secure():
    return _env_bool("OCSPMON_SESSION_COOKIE_SECURE", True)


def bootstrap_admin_username():
    return _env("OCSPMON_BOOTSTRAP_ADMIN_USERNAME", "admin").strip() or "admin"


def bootstrap_admin_password():
    return _env("OCSPMON_BOOTSTRAP_ADMIN_PASSWORD")


def local_login_enabled():
    return _env_bool("OCSPMON_LOCAL_LOGIN_ENABLED", True)


def allow_open_mode():
    return _env_bool("OCSPMON_ALLOW_OPEN_MODE", False)


def oidc_issuer():
    return _env("OCSPMON_OIDC_ISSUER").strip()


def oidc_client_id():
    return _env("OCSPMON_OIDC_CLIENT_ID").strip()


def oidc_client_secret():
    return _env("OCSPMON_OIDC_CLIENT_SECRET")


def oidc_scopes():
    return _env("OCSPMON_OIDC_SCOPES", "openid email profile")


def oidc_group_claim():
    return _env("OCSPMON_OIDC_GROUP_CLAIM", "groups")


def oidc_allowed_groups():
    return [g.strip() for g in _env("OCSPMON_OIDC_ALLOWED_GROUPS", "").split(",") if g.strip()]


def public_base_url():
    return _env("OCSPMON_PUBLIC_BASE_URL").rstrip("/")


def oidc_enabled():
    """OIDC is on only when all three core values are set (the reference's
    whole ``oidc_enabled`` rule — issuer alone gives you local login only)."""
    return bool(oidc_issuer() and oidc_client_id() and oidc_client_secret())


def auth_active():
    """True when authentication is enforced: on whenever any mechanism is
    configured. Otherwise the app runs 'open' (and only boots if the operator
    explicitly opted in)."""
    return bool(session_secret() or bootstrap_admin_password() or oidc_enabled())


# --------------------------------------------------------------------------- #
# Passwords (argon2id)
# --------------------------------------------------------------------------- #
def hash_password(password):
    return _pwd.hash(password)


def verify_password(password, password_hash):
    if not password_hash:
        return False
    try:
        return _pwd.verify(password, password_hash)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Users table
# --------------------------------------------------------------------------- #
USERS_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    provider      TEXT NOT NULL,              -- 'local' | 'oidc'
    subject       TEXT NOT NULL,              -- local username, or OIDC 'sub'
    email         TEXT,
    display_name  TEXT,
    password_hash TEXT,                        -- local accounts only
    is_admin      INTEGER NOT NULL DEFAULT 0,
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    last_login_at TEXT,
    UNIQUE(provider, subject)
);
"""


def _get_user(db, provider, subject):
    return db.execute(
        "SELECT * FROM users WHERE provider=? AND subject=?", (provider, subject)
    ).fetchone()


def _get_user_by_id(db, uid):
    return db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def _touch_last_login(db, uid):
    db.execute("UPDATE users SET last_login_at=? WHERE id=?", (_now_iso(), uid))
    db.commit()


def get_or_create_oidc_user(db, subject, email, display_name):
    """Match on the OIDC ``sub`` (never email), provisioning on first login.
    Email/name are display-only and refreshed each login (they can change)."""
    row = _get_user(db, "oidc", subject)
    if row is None:
        db.execute(
            "INSERT INTO users (provider, subject, email, display_name, is_active, created_at) "
            "VALUES ('oidc', ?, ?, ?, 1, ?)",
            (subject, email, display_name or email or subject, _now_iso()),
        )
        db.commit()
        row = _get_user(db, "oidc", subject)
        log.info("provisioned OIDC user sub=%s", subject)
    else:
        db.execute(
            "UPDATE users SET email=COALESCE(?, email), display_name=COALESCE(?, display_name) WHERE id=?",
            (email, display_name, row["id"]),
        )
        db.commit()
    _touch_last_login(db, row["id"])
    return row["id"]


def ensure_bootstrap_admin(db):
    """Create (or refresh the password of) the break-glass local admin when
    ``OCSPMON_BOOTSTRAP_ADMIN_PASSWORD`` is set. Never demotes an existing one."""
    pw = bootstrap_admin_password()
    if not pw:
        return
    username = bootstrap_admin_username()
    row = _get_user(db, "local", username)
    if row is None:
        db.execute(
            "INSERT INTO users (provider, subject, display_name, password_hash, is_admin, is_active, created_at) "
            "VALUES ('local', ?, ?, ?, 1, 1, ?)",
            (username, username, hash_password(pw), _now_iso()),
        )
        log.info("provisioned break-glass admin '%s'", username)
    else:
        db.execute(
            "UPDATE users SET password_hash=?, is_admin=1, is_active=1 WHERE id=?",
            (hash_password(pw), row["id"]),
        )
    db.commit()


# --------------------------------------------------------------------------- #
# Session helpers (Flask's own signed cookie carries the user id)
# --------------------------------------------------------------------------- #
def _signing_key():
    s = session_secret()
    if s:
        return s
    global _EPHEMERAL_KEY
    if _EPHEMERAL_KEY is None:
        _EPHEMERAL_KEY = secrets.token_hex(32)
        if auth_active():
            log.warning(
                "OCSPMON_SESSION_SECRET is not set; using an ephemeral per-process "
                "session key. Sessions will not survive a restart. Set a stable "
                "OCSPMON_SESSION_SECRET (e.g. `openssl rand -hex 32`) in production."
            )
    return _EPHEMERAL_KEY


def current_user():
    """The authenticated user row (sqlite Row) from the session, or None."""
    uid = flask_session.get("uid")
    if not uid:
        return None
    db = _get_db()
    row = _get_user_by_id(db, uid)
    if row is None or not row["is_active"]:
        return None
    return row


def _login(db, uid):
    flask_session.clear()
    flask_session["uid"] = uid
    flask_session.permanent = True
    _touch_last_login(db, uid)


# --------------------------------------------------------------------------- #
# Tiny per-(ip, username) login throttle for the local form (OIDC is primary).
# --------------------------------------------------------------------------- #
_FAILURES = {}
_MAX_FAILURES = 5
_WINDOW = 300.0


def _rate_key(username):
    return f"{request.remote_addr or '?'}:{username}"


def _rate_limited(key):
    count, first = _FAILURES.get(key, (0, 0.0))
    return count >= _MAX_FAILURES and (time.monotonic() - first) < _WINDOW


def _record_failure(key):
    count, first = _FAILURES.get(key, (0, 0.0))
    if (time.monotonic() - first) >= _WINDOW:
        count, first = 0, time.monotonic()
    _FAILURES[key] = (count + 1, first or time.monotonic())


def _clear_failures(key):
    _FAILURES.pop(key, None)


# --------------------------------------------------------------------------- #
# OIDC client + redirect URI
# --------------------------------------------------------------------------- #
def _oauth_client(app):
    """Lazily build (and cache on the app) the authlib OIDC client."""
    client = app.extensions.get("oidc_client")
    if client is not None:
        return client
    from authlib.integrations.flask_client import OAuth

    oauth = OAuth(app)
    oauth.register(
        name="oidc",
        client_id=oidc_client_id(),
        client_secret=oidc_client_secret(),
        server_metadata_url=oidc_issuer().rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs={"scope": oidc_scopes()},
    )
    app.extensions["oidc_client"] = oauth.oidc
    return oauth.oidc


def _oidc_redirect_uri():
    """Absolute callback URL registered in the IdP. Prefer the configured public
    base URL; otherwise derive it from the (ProxyFix-applied) forwarded host, so
    it is correct behind an HTTPS reverse proxy and under a URL subpath."""
    base = public_base_url()
    if base:
        return base + (_url_prefix() or "") + "/api/auth/oidc/callback"
    return url_for("oidc_callback", _external=True)


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #
# Paths reachable without a session (the login surfaces + health). Compared
# against request.path, which DispatcherMiddleware has already stripped of any
# URL_PREFIX, so these are prefix-less.
_PUBLIC_PATHS = {
    "/login",
    "/api/status",
    "/api/auth/config",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/oidc/login",
    "/api/auth/oidc/callback",
}


def init_app(app, *, get_db, raw_db, now_iso):
    """Install authentication on the Flask app. Called once at import time.

    Raises RuntimeError (fail closed) if no auth is configured and the operator
    has not explicitly opted into open mode.
    """
    global _get_db, _raw_db, _now_iso
    _get_db, _raw_db, _now_iso = get_db, raw_db, now_iso

    if not auth_active():
        if not allow_open_mode():
            raise RuntimeError(
                "Refusing to start: no authentication is configured, which would "
                "leave the OCSP Monitor API and UI open to anyone who can reach the "
                "port. Configure authentication (set OCSPMON_SESSION_SECRET and "
                "OCSPMON_BOOTSTRAP_ADMIN_PASSWORD, and/or enable OIDC via "
                "OCSPMON_OIDC_ISSUER/_CLIENT_ID/_CLIENT_SECRET), or — for an "
                "isolated single-user/dev box only — set OCSPMON_ALLOW_OPEN_MODE=true."
            )
        log.warning(
            "OPEN MODE: no authentication is configured; every request has full "
            "access. Unsafe on any shared or network-reachable host. Configure "
            "OCSPMON_SESSION_SECRET + OCSPMON_BOOTSTRAP_ADMIN_PASSWORD (or OIDC) "
            "to enable authentication."
        )

    # Signed, httponly session cookie. SameSite=Lax so the top-level GET redirect
    # back from the IdP still carries it (the OIDC state/nonce live here too).
    app.secret_key = _signing_key()
    app.config.update(
        SESSION_COOKIE_NAME=session_cookie_name(),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=session_cookie_secure(),
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=session_ttl_seconds(),
    )

    with closing(raw_db()) as db:
        db.executescript(USERS_SCHEMA)
        db.commit()
        ensure_bootstrap_admin(db)

    _register_routes(app)
    log.info(
        "auth: %s (local_login=%s, oidc=%s)",
        "enforced" if auth_active() else "OPEN MODE",
        local_login_enabled(), oidc_enabled(),
    )


def _register_routes(app):
    # ---- enforcement -------------------------------------------------------
    @app.before_request
    def _require_auth():
        if not auth_active():
            return None  # open mode: anonymous full access (opt-in only)
        path = request.path
        if path in _PUBLIC_PATHS or path.startswith("/static/"):
            return None
        if current_user() is not None:
            return None
        if path.startswith("/api/"):
            return jsonify({"message": "Authentication required."}), 401
        return redirect((_url_prefix() or "") + "/login")

    # ---- login page --------------------------------------------------------
    @app.route("/login")
    def login_page():
        if auth_active() and current_user() is not None:
            return redirect((_url_prefix() or "") + "/")
        resp = app.make_response(render_template(
            "login.html",
            local_login_enabled=local_login_enabled(),
            oidc_enabled=oidc_enabled(),
            url_prefix=_url_prefix() or "",
        ))
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        return resp

    # ---- config / me / logout ---------------------------------------------
    @app.route("/api/auth/config")
    def auth_config():
        return jsonify({
            "auth_required": auth_active(),
            "local_login_enabled": local_login_enabled(),
            "oidc_enabled": oidc_enabled(),
            "oidc_login_url": ((_url_prefix() or "") + "/api/auth/oidc/login") if oidc_enabled() else None,
        })

    @app.route("/api/auth/me")
    def auth_me():
        u = current_user()
        if u is None:
            return jsonify({"message": "Not authenticated."}), 401
        return jsonify({
            "id": u["id"], "provider": u["provider"], "subject": u["subject"],
            "email": u["email"], "display_name": u["display_name"],
            "is_admin": bool(u["is_admin"]),
        })

    @app.route("/api/auth/logout", methods=["POST"])
    def auth_logout():
        flask_session.clear()
        return ("", 204)

    # ---- local username/password ------------------------------------------
    @app.route("/api/auth/login", methods=["POST"])
    def local_login():
        if not local_login_enabled():
            return jsonify({"message": "Local login is disabled."}), 403
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        key = _rate_key(username)
        if _rate_limited(key):
            return jsonify({"message": "Too many login attempts; try again later."}), 429
        db = _get_db()
        row = _get_user(db, "local", username)
        if row is None or not row["is_active"] or not verify_password(password, row["password_hash"]):
            _record_failure(key)
            log.info("local login failed for %r", username)
            return jsonify({"message": "Invalid username or password."}), 401
        _clear_failures(key)
        _login(db, row["id"])
        return jsonify({"id": row["id"], "subject": username, "provider": "local"})

    # ---- OIDC --------------------------------------------------------------
    @app.route("/api/auth/oidc/login")
    def oidc_login():
        if not oidc_enabled():
            abort(404)
        client = _oauth_client(app)
        # authlib stores the state + nonce in the (signed) session and validates
        # both on callback — CSRF (state) and ID-token replay (nonce).
        return client.authorize_redirect(_oidc_redirect_uri())

    @app.route("/api/auth/oidc/callback", endpoint="oidc_callback")
    def oidc_callback():
        if not oidc_enabled():
            abort(404)
        client = _oauth_client(app)
        try:
            token = client.authorize_access_token()  # validates state + nonce
        except Exception as exc:  # pragma: no cover - network/validation path
            log.warning("OIDC token exchange failed: %s", exc)
            return jsonify({"message": "OIDC authentication failed."}), 401
        claims = token.get("userinfo") or {}
        if not claims:
            try:
                claims = client.userinfo(token=token)
            except Exception:  # pragma: no cover
                claims = {}
        sub = claims.get("sub")
        if not sub:
            return jsonify({"message": "OIDC response missing subject."}), 401

        groups = claims.get(oidc_group_claim()) or []
        if isinstance(groups, str):
            groups = [groups]
        groups = [str(g) for g in groups]
        allowed = oidc_allowed_groups()
        if allowed and not (set(groups) & set(allowed)):
            log.info("OIDC user sub=%s rejected: not in an allowed group", sub)
            return jsonify({"message": "Your account is not permitted to access this app."}), 403

        db = _get_db()
        uid = get_or_create_oidc_user(db, str(sub), claims.get("email"), claims.get("name"))
        _login(db, uid)
        return redirect((_url_prefix() or "") + "/")
