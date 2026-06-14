"""
OCSP Monitor — single-container edition.

A Flask app that serves both the JSON API and the web UI from one process on
one port, with no separate frontend/backend services and no external database.
Designed to sit cleanly behind a reverse proxy (nginx, Traefik, NPM, pfSense)
including under a URL subpath, and to manage fewer than ~30 OCSP responders.

State is stored in SQLite. Checks run on a background scheduler thread using
the `cryptography` library to build and verify real OCSP requests (no shelling
out to the openssl binary).
"""

import os
import base64
import sqlite3
import threading
import time
import logging
from contextlib import closing
from datetime import datetime, timezone, timedelta

import requests
from flask import (
    Flask, request, jsonify, g, render_template, url_for, redirect
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.wrappers import Response

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
from cryptography.x509 import ocsp as x509_ocsp

# --------------------------------------------------------------------------- #
# Configuration (all via environment variables)
# --------------------------------------------------------------------------- #
DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.environ.get("DB_PATH", os.path.join(DATA_DIR, "ocsp_monitor.db"))
PORT = int(os.environ.get("PORT", "8080"))
# URL prefix for running behind a reverse proxy subpath, e.g. "/ocsp".
URL_PREFIX = os.environ.get("URL_PREFIX", "").rstrip("/")
# How often (seconds) the scheduler wakes up to look for due checks.
SCHEDULER_INTERVAL = int(os.environ.get("SCHEDULER_INTERVAL", "30"))
# Per-request OCSP HTTP timeout (seconds).
OCSP_TIMEOUT = int(os.environ.get("OCSP_TIMEOUT", "30"))
# Number of history rows retained per responder.
HISTORY_LIMIT = int(os.environ.get("HISTORY_LIMIT", "200"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ocsp-monitor")

os.makedirs(DATA_DIR, exist_ok=True)

# --------------------------------------------------------------------------- #
# Database helpers
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS responders (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cert_alias      TEXT NOT NULL,
    cert_pem        TEXT NOT NULL,
    issuer_pem      TEXT NOT NULL,
    ocsp_uri        TEXT NOT NULL DEFAULT '',
    frequency_min   INTEGER NOT NULL DEFAULT 60,
    enabled         INTEGER NOT NULL DEFAULT 1,
    uptime_kuma_url TEXT NOT NULL DEFAULT '',
    last_run        TEXT,
    next_run        TEXT,
    status          TEXT NOT NULL DEFAULT 'Unknown',
    last_message    TEXT NOT NULL DEFAULT 'Configuration created.',
    response_ms     INTEGER,
    this_update     TEXT,
    next_update     TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    responder_id INTEGER NOT NULL,
    status       TEXT NOT NULL,
    message      TEXT NOT NULL DEFAULT '',
    timestamp    TEXT NOT NULL,
    FOREIGN KEY (responder_id) REFERENCES responders(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_history_responder
    ON history(responder_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

DEFAULT_SETTINGS = {
    "debug_logging": "false",
    "log_only_failures": "false",
    "uptime_kuma_logging": "true",
}


def get_db():
    """Per-request connection (also usable standalone via closing())."""
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


def raw_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with closing(raw_db()) as db:
        db.executescript(SCHEMA)
        for k, v in DEFAULT_SETTINGS.items():
            db.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
                (k, v),
            )
        db.commit()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_setting(db, key, default="false"):
    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


# --------------------------------------------------------------------------- #
# OCSP check core (uses `cryptography`, not the openssl CLI)
# --------------------------------------------------------------------------- #
class OCSPResult:
    def __init__(self, status, message, response_ms=None,
                 this_update=None, next_update=None):
        self.status = status            # Valid | Revoked | Unknown | Error
        self.message = message
        self.response_ms = response_ms
        self.this_update = this_update
        self.next_update = next_update


def _load_cert(pem_text, label):
    pem_bytes = pem_text.strip().encode("utf-8")
    if b"BEGIN CERTIFICATE" not in pem_bytes:
        raise ValueError(f"{label} is not valid PEM (missing BEGIN CERTIFICATE).")
    return x509.load_pem_x509_certificate(pem_bytes)


def _ocsp_uri_from_cert(cert):
    """Pull the OCSP responder URL from the cert's AIA extension."""
    try:
        aia = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        ).value
    except x509.ExtensionNotFound:
        return None
    for desc in aia:
        if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
            return desc.access_location.value
    return None


def run_ocsp_check(cert_pem, issuer_pem, ocsp_uri, timeout=OCSP_TIMEOUT):
    """Build a real OCSP request, POST it, and parse the response."""
    start = time.monotonic()
    try:
        cert = _load_cert(cert_pem, "Certificate")
        issuer = _load_cert(issuer_pem, "Issuer certificate")
    except Exception as e:
        return OCSPResult("Error", f"Certificate load failed: {e}")

    # Fall back to the AIA OCSP URL embedded in the cert if none was given.
    uri = (ocsp_uri or "").strip() or _ocsp_uri_from_cert(cert)
    if not uri:
        return OCSPResult(
            "Error",
            "No OCSP URI provided and none found in the certificate's AIA extension.",
        )

    try:
        builder = OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1())
        ocsp_req = builder.build()
        der = ocsp_req.public_bytes(serialization.Encoding.DER)
    except Exception as e:
        return OCSPResult("Error", f"Failed to build OCSP request: {e}")

    try:
        resp = requests.post(
            uri,
            data=der,
            headers={
                "Content-Type": "application/ocsp-request",
                "Accept": "application/ocsp-response",
            },
            timeout=timeout,
        )
    except requests.exceptions.RequestException as e:
        return OCSPResult("Error", f"OCSP responder unreachable: {e}")

    elapsed_ms = int((time.monotonic() - start) * 1000)

    if resp.status_code != 200:
        return OCSPResult(
            "Error",
            f"OCSP responder returned HTTP {resp.status_code}.",
            response_ms=elapsed_ms,
        )

    try:
        ocsp_resp = load_der_ocsp_response(resp.content)
    except Exception as e:
        return OCSPResult(
            "Error", f"Failed to parse OCSP response: {e}", response_ms=elapsed_ms
        )

    if ocsp_resp.response_status != x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
        return OCSPResult(
            "Error",
            f"OCSP response status: {ocsp_resp.response_status.name}.",
            response_ms=elapsed_ms,
        )

    def _fmt(dt):
        return dt.isoformat() if dt else None

    # this_update / next_update are timezone-aware in newer cryptography.
    try:
        this_update = ocsp_resp.this_update_utc
        next_update = ocsp_resp.next_update_utc
    except AttributeError:  # older cryptography
        this_update = ocsp_resp.this_update
        next_update = ocsp_resp.next_update

    cert_status = ocsp_resp.certificate_status
    if cert_status == x509_ocsp.OCSPCertStatus.GOOD:
        status, message = "Valid", "Certificate status is good."
        # Flag a stale or imminently-expiring response.
        if next_update:
            nu = next_update if next_update.tzinfo else next_update.replace(tzinfo=timezone.utc)
            if nu < datetime.now(timezone.utc):
                status = "Error"
                message = f"OCSP response is stale (nextUpdate {nu.isoformat()} is in the past)."
    elif cert_status == x509_ocsp.OCSPCertStatus.REVOKED:
        rt = getattr(ocsp_resp, "revocation_time_utc", None) or getattr(
            ocsp_resp, "revocation_time", None
        )
        status = "Revoked"
        message = f"Certificate is revoked. Revocation time: {_fmt(rt) or 'N/A'}."
    else:
        status = "Unknown"
        message = "OCSP responder returned status: unknown."

    return OCSPResult(
        status,
        message,
        response_ms=elapsed_ms,
        this_update=_fmt(this_update),
        next_update=_fmt(next_update),
    )


# --------------------------------------------------------------------------- #
# Uptime Kuma passive push
# --------------------------------------------------------------------------- #
def push_to_uptime_kuma(url, status, message, logging_enabled=True):
    if not url or not url.strip():
        return
    kuma_status = "up" if status == "Valid" else "down"
    try:
        if logging_enabled:
            log.info("[UptimeKuma] push status=%s msg=%s", kuma_status, message)
        requests.get(
            url,
            params={"status": kuma_status, "msg": message, "ping": ""},
            timeout=5,
        )
    except requests.exceptions.RequestException as e:
        log.warning("[UptimeKuma] push failed: %s", e)


# --------------------------------------------------------------------------- #
# Worker: run a single responder's check and persist results
# --------------------------------------------------------------------------- #
def check_responder(db, row):
    rid = row["id"]
    alias = row["cert_alias"]
    debug = get_setting(db, "debug_logging") == "true"
    log_only_failures = get_setting(db, "log_only_failures") == "true"
    kuma_logging = get_setting(db, "uptime_kuma_logging") == "true"

    if debug:
        log.info("[Worker] checking '%s' (id=%s) uri=%s", alias, rid, row["ocsp_uri"])

    result = run_ocsp_check(row["cert_pem"], row["issuer_pem"], row["ocsp_uri"])

    now = datetime.now(timezone.utc)
    next_run = (now + timedelta(minutes=row["frequency_min"])).isoformat()
    prev_status = row["status"]

    db.execute(
        """UPDATE responders
              SET last_run=?, next_run=?, status=?, last_message=?,
                  response_ms=?, this_update=?, next_update=?, updated_at=?
            WHERE id=?""",
        (
            now.isoformat(), next_run, result.status, result.message,
            result.response_ms, result.this_update, result.next_update,
            now.isoformat(), rid,
        ),
    )

    if prev_status != result.status:
        db.execute(
            "INSERT INTO history (responder_id, status, message, timestamp) "
            "VALUES (?, ?, ?, ?)",
            (rid, result.status, result.message, now.isoformat()),
        )
        # Trim history to HISTORY_LIMIT rows per responder.
        db.execute(
            """DELETE FROM history WHERE responder_id=? AND id NOT IN (
                   SELECT id FROM history WHERE responder_id=?
                   ORDER BY timestamp DESC LIMIT ?
               )""",
            (rid, rid, HISTORY_LIMIT),
        )
        log.info("[Worker] '%s' status changed %s -> %s", alias, prev_status, result.status)

    db.commit()

    if not log_only_failures or result.status != "Valid":
        log.info("[Worker] '%s' -> %s (%s ms)", alias, result.status, result.response_ms)

    push_to_uptime_kuma(row["uptime_kuma_url"], result.status, result.message, kuma_logging)
    return result


# --------------------------------------------------------------------------- #
# Background scheduler thread
# --------------------------------------------------------------------------- #
_scheduler_started = False
_scheduler_lock = threading.Lock()


def scheduler_loop():
    log.info("[Scheduler] started; tick every %ss", SCHEDULER_INTERVAL)
    while True:
        try:
            with closing(raw_db()) as db:
                now = now_iso()
                due = db.execute(
                    "SELECT * FROM responders WHERE enabled=1 "
                    "AND (next_run IS NULL OR next_run <= ?)",
                    (now,),
                ).fetchall()
                for row in due:
                    try:
                        check_responder(db, row)
                    except Exception as e:  # never let one bad row kill the loop
                        log.exception("[Scheduler] check failed for id=%s: %s", row["id"], e)
        except Exception as e:
            log.exception("[Scheduler] loop error: %s", e)
        time.sleep(SCHEDULER_INTERVAL)


def start_scheduler():
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        t = threading.Thread(target=scheduler_loop, name="ocsp-scheduler", daemon=True)
        t.start()
        _scheduler_started = True


# --------------------------------------------------------------------------- #
# Flask app
# --------------------------------------------------------------------------- #
app = Flask(__name__)
# Trust X-Forwarded-* from one proxy hop.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def responder_to_dict(row, include_pem=True):
    d = {
        "id": row["id"],
        "cert_alias": row["cert_alias"],
        "ocsp_uri": row["ocsp_uri"],
        "frequency_min": row["frequency_min"],
        "enabled": bool(row["enabled"]),
        "uptime_kuma_url": row["uptime_kuma_url"],
        "last_run": row["last_run"],
        "next_run": row["next_run"],
        "status": row["status"],
        "last_message": row["last_message"],
        "response_ms": row["response_ms"],
        "this_update": row["this_update"],
        "next_update": row["next_update"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    if include_pem:
        d["cert_pem"] = row["cert_pem"]
        d["issuer_pem"] = row["issuer_pem"]
    return d


# ---- UI ---- #
@app.route("/")
def index():
    return render_template("index.html")


# ---- Health ---- #
@app.route("/api/status")
def api_status():
    try:
        get_db().execute("SELECT 1")
        return jsonify({"status": "ok", "database": "connected"})
    except Exception as e:
        return jsonify({"status": "error", "database": str(e)}), 500


# ---- Responders CRUD ---- #
@app.route("/api/responders", methods=["GET"])
def list_responders():
    db = get_db()
    rows = db.execute("SELECT * FROM responders ORDER BY cert_alias").fetchall()
    return jsonify([responder_to_dict(r, include_pem=False) for r in rows])


@app.route("/api/responders/<int:rid>", methods=["GET"])
def get_responder(rid):
    db = get_db()
    row = db.execute("SELECT * FROM responders WHERE id=?", (rid,)).fetchone()
    if not row:
        return jsonify({"message": "Not found"}), 404
    return jsonify(responder_to_dict(row, include_pem=True))


def _validate_payload(data, partial=False):
    errors = []
    if not partial or "cert_alias" in data:
        if not (data.get("cert_alias") or "").strip():
            errors.append("cert_alias is required.")
    if not partial or "cert_pem" in data:
        if "BEGIN CERTIFICATE" not in (data.get("cert_pem") or ""):
            errors.append("cert_pem must be a PEM certificate.")
    if not partial or "issuer_pem" in data:
        if "BEGIN CERTIFICATE" not in (data.get("issuer_pem") or ""):
            errors.append("issuer_pem must be a PEM certificate.")
    return errors


@app.route("/api/responders", methods=["POST"])
def create_responder():
    data = request.get_json(force=True, silent=True) or {}
    errors = _validate_payload(data)
    if errors:
        return jsonify({"message": "Validation failed", "errors": errors}), 400
    db = get_db()
    now = now_iso()
    cur = db.execute(
        """INSERT INTO responders
           (cert_alias, cert_pem, issuer_pem, ocsp_uri, frequency_min,
            enabled, uptime_kuma_url, next_run, status, last_message,
            created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            data["cert_alias"].strip(),
            data["cert_pem"].strip(),
            data["issuer_pem"].strip(),
            (data.get("ocsp_uri") or "").strip(),
            int(data.get("frequency_min", 60)),
            1 if data.get("enabled", True) else 0,
            (data.get("uptime_kuma_url") or "").strip(),
            now,  # schedule an immediate first run
            "Unknown",
            "Configuration created.",
            now,
            now,
        ),
    )
    db.commit()
    row = db.execute("SELECT * FROM responders WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify(responder_to_dict(row)), 201


@app.route("/api/responders/<int:rid>", methods=["PUT"])
def update_responder(rid):
    data = request.get_json(force=True, silent=True) or {}
    errors = _validate_payload(data, partial=True)
    if errors:
        return jsonify({"message": "Validation failed", "errors": errors}), 400
    db = get_db()
    row = db.execute("SELECT * FROM responders WHERE id=?", (rid,)).fetchone()
    if not row:
        return jsonify({"message": "Not found"}), 404

    fields = {
        "cert_alias": (data.get("cert_alias") or row["cert_alias"]).strip(),
        "cert_pem": (data.get("cert_pem") or row["cert_pem"]).strip(),
        "issuer_pem": (data.get("issuer_pem") or row["issuer_pem"]).strip(),
        "ocsp_uri": (data.get("ocsp_uri", row["ocsp_uri"]) or "").strip(),
        "frequency_min": int(data.get("frequency_min", row["frequency_min"])),
        "enabled": 1 if data.get("enabled", bool(row["enabled"])) else 0,
        "uptime_kuma_url": (data.get("uptime_kuma_url", row["uptime_kuma_url"]) or "").strip(),
    }
    # Re-check immediately if cert material changed.
    next_run = row["next_run"]
    if fields["cert_pem"] != row["cert_pem"] or fields["issuer_pem"] != row["issuer_pem"]:
        next_run = now_iso()

    db.execute(
        """UPDATE responders SET cert_alias=?, cert_pem=?, issuer_pem=?, ocsp_uri=?,
               frequency_min=?, enabled=?, uptime_kuma_url=?, next_run=?, updated_at=?
           WHERE id=?""",
        (
            fields["cert_alias"], fields["cert_pem"], fields["issuer_pem"],
            fields["ocsp_uri"], fields["frequency_min"], fields["enabled"],
            fields["uptime_kuma_url"], next_run, now_iso(), rid,
        ),
    )
    db.commit()
    row = db.execute("SELECT * FROM responders WHERE id=?", (rid,)).fetchone()
    return jsonify(responder_to_dict(row))


@app.route("/api/responders/<int:rid>", methods=["DELETE"])
def delete_responder(rid):
    db = get_db()
    cur = db.execute("DELETE FROM responders WHERE id=?", (rid,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"message": "Not found"}), 404
    return ("", 204)


@app.route("/api/responders/<int:rid>/check", methods=["POST"])
def check_now(rid):
    """Run a check immediately and return the result."""
    db = get_db()
    row = db.execute("SELECT * FROM responders WHERE id=?", (rid,)).fetchone()
    if not row:
        return jsonify({"message": "Not found"}), 404
    result = check_responder(db, row)
    row = db.execute("SELECT * FROM responders WHERE id=?", (rid,)).fetchone()
    return jsonify(responder_to_dict(row, include_pem=False))


@app.route("/api/responders/<int:rid>/history", methods=["GET"])
def responder_history(rid):
    db = get_db()
    limit = min(int(request.args.get("limit", 50)), HISTORY_LIMIT)
    rows = db.execute(
        "SELECT status, message, timestamp FROM history "
        "WHERE responder_id=? ORDER BY timestamp DESC LIMIT ?",
        (rid, limit),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ---- Settings ---- #
@app.route("/api/settings", methods=["GET"])
def get_settings():
    db = get_db()
    rows = db.execute("SELECT key, value FROM settings").fetchall()
    out = {}
    for r in rows:
        v = r["value"]
        out[r["key"]] = (v == "true") if v in ("true", "false") else v
    return jsonify(out)


@app.route("/api/settings", methods=["PUT"])
def put_settings():
    data = request.get_json(force=True, silent=True) or {}
    db = get_db()
    for k, v in data.items():
        sv = "true" if v is True else "false" if v is False else str(v)
        db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (k, sv),
        )
    db.commit()
    return get_settings()


# Initialise DB + scheduler at import time (works under gunicorn too).
init_db()
start_scheduler()

# Apply URL prefix for subpath deployments.
if URL_PREFIX:
    def _not_found(environ, start_response):
        res = Response(
            f"Not found. App is mounted at '{URL_PREFIX}'.",
            status=404, mimetype="text/plain",
        )
        return res(environ, start_response)

    app.wsgi_app = DispatcherMiddleware(_not_found, {URL_PREFIX: app.wsgi_app})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
