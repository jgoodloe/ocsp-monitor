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
import json
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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa, ed25519, ed448
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
# Selectable verification tests
# --------------------------------------------------------------------------- #
# Each OCSP check always performs the foundational steps (reach the responder,
# get HTTP 200, parse the DER, confirm responseStatus == successful) because
# without them there is nothing to evaluate. Beyond that, these named tests can
# be individually enabled per responder (or via a global default).
TESTS = [
    ("cert_status",   "Certificate status (GOOD / not revoked)"),
    ("cert_id_match", "CertID serial match (response is about this certificate)"),
    ("signature",     "Response signature verification"),
    ("signing_cert_validity", "Signing-cert validity (signer within notBefore/notAfter)"),
    ("this_update",   "thisUpdate sanity (present, not future-dated)"),
    ("next_update",   "nextUpdate freshness (present, not in the past)"),
    ("nonce",         "Nonce echo (response echoes the request nonce)"),
    ("response_time", "Response-time threshold (round-trip under the limit)"),
]
ALL_TEST_KEYS = [k for k, _ in TESTS]
TEST_LABELS = dict(TESTS)
# Default set for new installs. Excludes the two that can surprise people:
# `nonce` (many responders don't support it) and `response_time` (depends on a
# threshold). Both are opt-in.
DEFAULT_TESTS = [
    "cert_status", "cert_id_match", "signature",
    "signing_cert_validity", "this_update", "next_update",
]
# Fallback response-time threshold (ms) when neither responder nor global set.
DEFAULT_RESPONSE_TIME_MS = 2000


def parse_tests(value):
    """Parse a stored tests value into a clean list of known test keys.

    Returns None to mean "not set" (inherit the global default). Accepts a JSON
    array string or a comma-separated string; unknown keys are dropped and
    original ordering (per ALL_TEST_KEYS) is preserved.
    """
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        items = list(value)
    else:
        s = str(value).strip()
        if s == "":
            return None
        try:
            parsed = json.loads(s)
            items = parsed if isinstance(parsed, list) else [parsed]
        except (ValueError, TypeError):
            items = [p.strip() for p in s.split(",")]
    selected = {str(i).strip() for i in items}
    return [k for k in ALL_TEST_KEYS if k in selected]


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
    tests           TEXT,
    response_time_ms INTEGER,
    last_checks     TEXT,
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
    # Global default set of verification tests, applied to any responder that
    # does not specify its own. Stored as comma-separated test keys.
    "default_tests": ",".join(DEFAULT_TESTS),
    # Global default response-time threshold (ms) for the response_time test,
    # used by any responder that doesn't set its own.
    "default_response_time_ms": str(DEFAULT_RESPONSE_TIME_MS),
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
        # Lightweight migrations for databases created before these columns
        # existed (SQLite has no "ADD COLUMN IF NOT EXISTS").
        existing_cols = {
            r["name"] for r in db.execute("PRAGMA table_info(responders)").fetchall()
        }
        for col, col_type in (("tests", "TEXT"), ("last_checks", "TEXT"),
                              ("response_time_ms", "INTEGER")):
            if col not in existing_cols:
                db.execute(f"ALTER TABLE responders ADD COLUMN {col} {col_type}")
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
                 this_update=None, next_update=None, checks=None):
        self.status = status            # Valid | Revoked | Unknown | Error
        self.message = message
        self.response_ms = response_ms
        self.this_update = this_update
        self.next_update = next_update
        # Per-test outcomes: list of {key, label, status, message} where status
        # is one of pass | fail | skip.
        self.checks = checks or []


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


# Allow a little clock skew before calling a thisUpdate "future-dated".
_CLOCK_SKEW = timedelta(minutes=5)


def _aware(dt):
    """Return a timezone-aware UTC datetime (treat naive as UTC)."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _pubkey_verify(cert, signature, data, hash_alg):
    """Verify `signature` over `data` using `cert`'s public key.

    Raises InvalidSignature on mismatch, or ValueError for unsupported keys.
    """
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(signature, data, padding.PKCS1v15(), hash_alg)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(signature, data, ec.ECDSA(hash_alg))
    elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        pub.verify(signature, data)  # Ed* carry their own hash
    else:
        raise ValueError(f"unsupported key type {type(pub).__name__}")


def _validate_delegate(cand, issuer):
    """A delegated OCSP responder cert must carry the OCSP-signing EKU and be
    issued by the same CA. Returns (ok, reason)."""
    try:
        eku = cand.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
            return False, "delegated responder cert lacks the OCSP-signing EKU"
    except x509.ExtensionNotFound:
        return False, "delegated responder cert has no EKU extension"
    try:
        # Newer cryptography validates name chaining + signature in one call.
        if hasattr(cand, "verify_directly_issued_by"):
            cand.verify_directly_issued_by(issuer)
        else:
            _pubkey_verify(issuer, cand.signature, cand.tbs_certificate_bytes,
                           cand.signature_hash_algorithm)
    except Exception as e:
        return False, f"delegated responder cert not issued by this CA ({e})"
    return True, ""


def _verify_ocsp_signature(ocsp_resp, issuer):
    """Verify the OCSP response signature against a delegated responder cert
    embedded in the response, or against the issuer directly. Returns
    (ok, message)."""
    tbs = ocsp_resp.tbs_response_bytes
    sig = ocsp_resp.signature
    hash_alg = ocsp_resp.signature_hash_algorithm
    errors = []

    for cand in (getattr(ocsp_resp, "certificates", None) or []):
        try:
            _pubkey_verify(cand, sig, tbs, hash_alg)
        except InvalidSignature:
            continue  # not the signer; try the next embedded cert
        except Exception as e:
            errors.append(str(e))
            continue
        ok, reason = _validate_delegate(cand, issuer)
        if ok:
            return True, "Signature verified against the delegated responder certificate."
        errors.append(reason)

    try:
        _pubkey_verify(issuer, sig, tbs, hash_alg)
        return True, "Signature verified against the issuer certificate."
    except InvalidSignature:
        errors.append("issuer key does not match the signature")
    except Exception as e:
        errors.append(str(e))

    detail = "; ".join(dict.fromkeys(errors)) or "no matching signer found"
    return False, f"Signature verification failed ({detail})."


def _signer_cert(ocsp_resp, issuer):
    """Return the certificate whose key actually signed this response (an
    embedded delegated responder cert, or the issuer), or None if neither
    matches. Used by tests that need to inspect the signer itself."""
    tbs = ocsp_resp.tbs_response_bytes
    sig = ocsp_resp.signature
    hash_alg = ocsp_resp.signature_hash_algorithm
    for cand in list(getattr(ocsp_resp, "certificates", None) or []) + [issuer]:
        try:
            _pubkey_verify(cand, sig, tbs, hash_alg)
            return cand
        except Exception:
            continue
    return None


def _cert_validity_window(cert):
    """Return (not_before, not_after) as aware UTC datetimes."""
    try:
        nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        nb, na = cert.not_valid_before, cert.not_valid_after
    return _aware(nb), _aware(na)


def _evaluate_tests(enabled, ocsp_resp, this_update, next_update, issuer, cert,
                    elapsed_ms=None, threshold_ms=0, sent_nonce=None):
    """Run the enabled selectable tests against a successful OCSP response.

    Returns (checks, cert_status_raw). `checks` is a list of per-test dicts.
    """
    now = datetime.now(timezone.utc)
    cert_status = ocsp_resp.certificate_status
    checks = []

    def add(key, ok, message):
        checks.append({
            "key": key, "label": TEST_LABELS[key],
            "status": "pass" if ok else "fail", "message": message,
        })

    if "cert_status" in enabled:
        if cert_status == x509_ocsp.OCSPCertStatus.GOOD:
            add("cert_status", True, "Certificate status is good.")
        elif cert_status == x509_ocsp.OCSPCertStatus.REVOKED:
            rt = getattr(ocsp_resp, "revocation_time_utc", None) or getattr(
                ocsp_resp, "revocation_time", None)
            add("cert_status", False,
                f"Certificate is revoked. Revocation time: "
                f"{rt.isoformat() if rt else 'N/A'}.")
        else:
            add("cert_status", False, "OCSP responder returned status: unknown.")

    if "cert_id_match" in enabled:
        resp_serial = getattr(ocsp_resp, "serial_number", None)
        if resp_serial is None:
            add("cert_id_match", False, "Response has no CertID serial number.")
        elif resp_serial != cert.serial_number:
            add("cert_id_match", False,
                f"Response CertID serial {resp_serial:x} does not match the "
                f"requested certificate ({cert.serial_number:x}).")
        else:
            add("cert_id_match", True, "Response CertID matches the requested certificate.")

    if "signature" in enabled:
        try:
            ok, msg = _verify_ocsp_signature(ocsp_resp, issuer)
        except Exception as e:
            ok, msg = False, f"Signature could not be verified ({e})."
        add("signature", ok, msg)

    if "signing_cert_validity" in enabled:
        signer = _signer_cert(ocsp_resp, issuer)
        if signer is None:
            add("signing_cert_validity", False,
                "Could not determine the signing certificate to check its validity.")
        else:
            nb, na = _cert_validity_window(signer)
            who = "delegated responder" if signer is not issuer else "issuer"
            if now < nb:
                add("signing_cert_validity", False,
                    f"Signing certificate ({who}) is not yet valid (notBefore {nb.isoformat()}).")
            elif now > na:
                add("signing_cert_validity", False,
                    f"Signing certificate ({who}) has expired (notAfter {na.isoformat()}).")
            else:
                add("signing_cert_validity", True,
                    f"Signing certificate ({who}) is within its validity window.")

    if "this_update" in enabled:
        if this_update is None:
            add("this_update", False, "Response has no thisUpdate field.")
        elif this_update > now + _CLOCK_SKEW:
            add("this_update", False,
                f"thisUpdate {this_update.isoformat()} is in the future.")
        else:
            add("this_update", True, "thisUpdate is present and not future-dated.")

    if "next_update" in enabled:
        if next_update is None:
            add("next_update", False, "Response has no nextUpdate field.")
        elif next_update < now:
            add("next_update", False,
                f"Response is stale (nextUpdate {next_update.isoformat()} is in the past).")
        else:
            add("next_update", True, "nextUpdate is present and not in the past.")

    if "nonce" in enabled:
        try:
            resp_nonce = ocsp_resp.extensions.get_extension_for_class(
                x509.OCSPNonce).value.nonce
        except x509.ExtensionNotFound:
            resp_nonce = None
        if not sent_nonce:
            add("nonce", False, "No nonce was sent with the request.")
        elif resp_nonce is None:
            add("nonce", False, "Responder did not echo a nonce (nonces may be unsupported).")
        elif resp_nonce != sent_nonce:
            add("nonce", False, "Returned nonce does not match the nonce sent.")
        else:
            add("nonce", True, "Responder echoed the request nonce.")

    if "response_time" in enabled:
        limit = int(threshold_ms or 0)
        if elapsed_ms is None:
            add("response_time", False, "Response time was not measured.")
        elif limit <= 0:
            add("response_time", True,
                f"Response time {elapsed_ms} ms (no threshold configured).")
        elif elapsed_ms > limit:
            add("response_time", False,
                f"Response time {elapsed_ms} ms exceeds the {limit} ms threshold.")
        else:
            add("response_time", True,
                f"Response time {elapsed_ms} ms is within the {limit} ms threshold.")

    return checks, cert_status


def run_ocsp_check(cert_pem, issuer_pem, ocsp_uri, enabled_tests=None,
                   timeout=OCSP_TIMEOUT, threshold_ms=0):
    """Build a real OCSP request, POST it, parse the response, and evaluate the
    selected verification tests.

    `enabled_tests` is a list of test keys (see ALL_TEST_KEYS). The foundational
    steps — reach the responder, HTTP 200, parse DER, responseStatus == success —
    always run; failing any of them is an Error regardless of selection.
    `threshold_ms` is the response-time limit for the response_time test.
    """
    enabled = [k for k in ALL_TEST_KEYS if k in (enabled_tests or [])]

    def _skipped(reason):
        return [{"key": k, "label": TEST_LABELS[k], "status": "skip",
                 "message": reason} for k in enabled]

    start = time.monotonic()
    try:
        cert = _load_cert(cert_pem, "Certificate")
        issuer = _load_cert(issuer_pem, "Issuer certificate")
    except Exception as e:
        return OCSPResult("Error", f"Certificate load failed: {e}",
                          checks=_skipped("Not evaluated (certificate load failed)."))

    # Fall back to the AIA OCSP URL embedded in the cert if none was given.
    uri = (ocsp_uri or "").strip() or _ocsp_uri_from_cert(cert)
    if not uri:
        return OCSPResult(
            "Error",
            "No OCSP URI provided and none found in the certificate's AIA extension.",
            checks=_skipped("Not evaluated (no OCSP URI)."),
        )

    # Only attach a nonce when the nonce test is selected; some responders
    # behave differently (or refuse to cache) when a nonce is present.
    sent_nonce = None
    try:
        builder = OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1())
        if "nonce" in enabled:
            sent_nonce = os.urandom(16)
            builder = builder.add_extension(x509.OCSPNonce(sent_nonce), critical=False)
        ocsp_req = builder.build()
        der = ocsp_req.public_bytes(serialization.Encoding.DER)
    except Exception as e:
        return OCSPResult("Error", f"Failed to build OCSP request: {e}",
                          checks=_skipped("Not evaluated (request build failed)."))

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
        return OCSPResult("Error", f"OCSP responder unreachable: {e}",
                          checks=_skipped("Not evaluated (responder unreachable)."))

    elapsed_ms = int((time.monotonic() - start) * 1000)

    if resp.status_code != 200:
        return OCSPResult(
            "Error",
            f"OCSP responder returned HTTP {resp.status_code}.",
            response_ms=elapsed_ms,
            checks=_skipped("Not evaluated (non-200 response)."),
        )

    try:
        ocsp_resp = load_der_ocsp_response(resp.content)
    except Exception as e:
        return OCSPResult(
            "Error", f"Failed to parse OCSP response: {e}", response_ms=elapsed_ms,
            checks=_skipped("Not evaluated (unparseable response)."),
        )

    if ocsp_resp.response_status != x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
        return OCSPResult(
            "Error",
            f"OCSP response status: {ocsp_resp.response_status.name}.",
            response_ms=elapsed_ms,
            checks=_skipped("Not evaluated (responseStatus not successful)."),
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
    this_update = _aware(this_update)
    next_update = _aware(next_update)

    checks, cert_status_raw = _evaluate_tests(
        enabled, ocsp_resp, this_update, next_update, issuer, cert,
        elapsed_ms=elapsed_ms, threshold_ms=threshold_ms, sent_nonce=sent_nonce,
    )

    # Derive the overall status from the enabled tests only.
    failed = [c for c in checks if c["status"] == "fail"]
    cert_check = next((c for c in checks if c["key"] == "cert_status"), None)
    if cert_check and cert_check["status"] == "fail" and \
            cert_status_raw == x509_ocsp.OCSPCertStatus.REVOKED:
        status = "Revoked"
    elif cert_check and cert_check["status"] == "fail" and \
            cert_status_raw == x509_ocsp.OCSPCertStatus.UNKNOWN:
        status = "Unknown"
    elif failed:
        status = "Error"
    else:
        status = "Valid"

    if not enabled:
        message = "Responder reachable; no verification tests selected."
    elif failed:
        message = f"{len(failed)} of {len(enabled)} checks failed: " + \
            " ".join(c["message"] for c in failed)
    else:
        message = f"All {len(enabled)} selected checks passed."

    return OCSPResult(
        status,
        message,
        response_ms=elapsed_ms,
        this_update=_fmt(this_update),
        next_update=_fmt(next_update),
        checks=checks,
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
def resolve_tests(db, row):
    """The tests to run for this responder: its own set if it has one,
    otherwise the global default."""
    own = parse_tests(row["tests"] if "tests" in row.keys() else None)
    if own is not None:
        return own
    return parse_tests(get_setting(db, "default_tests", ",".join(DEFAULT_TESTS))) or []


def resolve_threshold_ms(db, row):
    """The response-time threshold (ms) for this responder: its own if set,
    otherwise the global default."""
    own = row["response_time_ms"] if "response_time_ms" in row.keys() else None
    if own is not None:
        try:
            return int(own)
        except (TypeError, ValueError):
            pass
    try:
        return int(get_setting(db, "default_response_time_ms",
                               str(DEFAULT_RESPONSE_TIME_MS)))
    except (TypeError, ValueError):
        return DEFAULT_RESPONSE_TIME_MS


def check_responder(db, row):
    rid = row["id"]
    alias = row["cert_alias"]
    debug = get_setting(db, "debug_logging") == "true"
    log_only_failures = get_setting(db, "log_only_failures") == "true"
    kuma_logging = get_setting(db, "uptime_kuma_logging") == "true"

    enabled_tests = resolve_tests(db, row)
    threshold_ms = resolve_threshold_ms(db, row)
    if debug:
        log.info("[Worker] checking '%s' (id=%s) uri=%s tests=%s threshold=%sms",
                 alias, rid, row["ocsp_uri"], ",".join(enabled_tests) or "none",
                 threshold_ms)

    result = run_ocsp_check(
        row["cert_pem"], row["issuer_pem"], row["ocsp_uri"], enabled_tests,
        threshold_ms=threshold_ms,
    )

    now = datetime.now(timezone.utc)
    next_run = (now + timedelta(minutes=row["frequency_min"])).isoformat()
    prev_status = row["status"]

    db.execute(
        """UPDATE responders
              SET last_run=?, next_run=?, status=?, last_message=?,
                  response_ms=?, this_update=?, next_update=?, last_checks=?,
                  updated_at=?
            WHERE id=?""",
        (
            now.isoformat(), next_run, result.status, result.message,
            result.response_ms, result.this_update, result.next_update,
            json.dumps(result.checks), now.isoformat(), rid,
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


def _load_checks(value):
    """Decode the stored last_checks JSON into a list (empty on error/None)."""
    if not value:
        return []
    try:
        data = json.loads(value)
        return data if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


def responder_to_dict(row, include_pem=True):
    d = {
        "id": row["id"],
        "cert_alias": row["cert_alias"],
        "ocsp_uri": row["ocsp_uri"],
        "frequency_min": row["frequency_min"],
        "enabled": bool(row["enabled"]),
        "uptime_kuma_url": row["uptime_kuma_url"],
        # None means "inherit the global default set".
        "tests": parse_tests(row["tests"] if "tests" in row.keys() else None),
        # None means "inherit the global default threshold".
        "response_time_ms": (row["response_time_ms"]
                             if "response_time_ms" in row.keys() else None),
        "last_checks": _load_checks(row["last_checks"] if "last_checks" in row.keys() else None),
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


def _tests_to_db(value):
    """Normalize an incoming `tests` value to what we store.

    None -> NULL (inherit the global default). A list -> a JSON array of clean
    known keys (an explicit empty list is preserved as "run no tests").
    """
    if value is None:
        return None
    cleaned = parse_tests(value)
    return None if cleaned is None else json.dumps(cleaned)


def _int_or_none(value):
    """Parse an optional integer; blank/None/garbage -> None (inherit)."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


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
            enabled, uptime_kuma_url, tests, response_time_ms, next_run, status,
            last_message, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            data["cert_alias"].strip(),
            data["cert_pem"].strip(),
            data["issuer_pem"].strip(),
            (data.get("ocsp_uri") or "").strip(),
            int(data.get("frequency_min", 60)),
            1 if data.get("enabled", True) else 0,
            (data.get("uptime_kuma_url") or "").strip(),
            _tests_to_db(data.get("tests")),
            _int_or_none(data.get("response_time_ms")),
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
        # Only touch the test selection if the client sent it.
        "tests": _tests_to_db(data["tests"]) if "tests" in data else row["tests"],
        "response_time_ms": (_int_or_none(data["response_time_ms"])
                             if "response_time_ms" in data else row["response_time_ms"]),
    }
    # Re-check immediately if cert material changed.
    next_run = row["next_run"]
    if fields["cert_pem"] != row["cert_pem"] or fields["issuer_pem"] != row["issuer_pem"]:
        next_run = now_iso()

    db.execute(
        """UPDATE responders SET cert_alias=?, cert_pem=?, issuer_pem=?, ocsp_uri=?,
               frequency_min=?, enabled=?, uptime_kuma_url=?, tests=?,
               response_time_ms=?, next_run=?, updated_at=?
           WHERE id=?""",
        (
            fields["cert_alias"], fields["cert_pem"], fields["issuer_pem"],
            fields["ocsp_uri"], fields["frequency_min"], fields["enabled"],
            fields["uptime_kuma_url"], fields["tests"], fields["response_time_ms"],
            next_run, now_iso(), rid,
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


# ---- Tests registry ---- #
@app.route("/api/tests", methods=["GET"])
def list_tests():
    """The catalogue of selectable verification tests (key + human label)."""
    return jsonify([{"key": k, "label": v} for k, v in TESTS])


# ---- Settings ---- #
@app.route("/api/settings", methods=["GET"])
def get_settings():
    db = get_db()
    rows = db.execute("SELECT key, value FROM settings").fetchall()
    out = {}
    for r in rows:
        v = r["value"]
        if r["key"] == "default_tests":
            out[r["key"]] = parse_tests(v) or []
        else:
            out[r["key"]] = (v == "true") if v in ("true", "false") else v
    return jsonify(out)


@app.route("/api/settings", methods=["PUT"])
def put_settings():
    data = request.get_json(force=True, silent=True) or {}
    db = get_db()
    for k, v in data.items():
        if k == "default_tests":
            sv = ",".join(parse_tests(v) or [])
        elif v is True:
            sv = "true"
        elif v is False:
            sv = "false"
        else:
            sv = str(v)
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
