"""Tests for issue 3 (Uptime Kuma push-URL normalization) and issue 4
(persistent per-event exclude / re-include in uptime reports)."""
import os
import importlib.util
from datetime import datetime, timezone, timedelta

import pytest

APP_PATH = os.path.join(os.path.dirname(__file__), "..", "app", "app.py")


@pytest.fixture(scope="module")
def m(tmp_path_factory):
    d = tmp_path_factory.mktemp("data")
    os.environ["DATA_DIR"] = str(d)
    os.environ["DB_PATH"] = str(d / "feat.db")
    os.environ["TRUSTED_PROXY_HOPS"] = "0"
    spec = importlib.util.spec_from_file_location("ocsp_feat_under_test", APP_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _csrf():
    return {"X-Requested-With": "XMLHttpRequest"}


def _make_responder(client, **extra):
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    payload = {"cert_alias": "feat", "cert_pem": pem, "issuer_pem": pem}
    payload.update(extra)
    r = client.post("/api/responders", json=payload, headers=_csrf())
    assert r.status_code == 201, r.get_data(as_text=True)
    return r.get_json()["id"]


# --------------------------------------------------------------------------- #
# Issue 3: Uptime Kuma push-URL normalization
# --------------------------------------------------------------------------- #
def test_kuma_url_variants_normalize_to_same_endpoint(m):
    canonical = "https://host/api/push/TOKEN"
    variants = [
        "https://host//api/push/TOKEN?status=up&msg=OK&ping=",
        "https://host//api/push/TOKEN",
        "https://host/api/push/TOKEN?status=up&msg=OK&ping=",
        "https://host/api/push/TOKEN",
        "  https://host//api/push/TOKEN?msg=OK  ",
    ]
    for v in variants:
        assert m.normalize_kuma_url(v) == canonical, v


def test_kuma_url_preserves_other_query_params(m):
    # Non-owned params are kept; only status/msg/ping are dropped.
    out = m.normalize_kuma_url("https://host/api/push/TOKEN?foo=1&status=up&bar=2&ping=")
    assert out == "https://host/api/push/TOKEN?foo=1&bar=2"


def test_kuma_url_blank_and_nonurl(m):
    assert m.normalize_kuma_url("") == ""
    assert m.normalize_kuma_url("   ") == ""
    assert m.normalize_kuma_url(None) == ""
    # A non-http(s) token-ish string is returned stripped, not mangled.
    assert m.normalize_kuma_url("  not a url  ") == "not a url"


def test_kuma_url_normalized_on_save(m):
    client = m.app.test_client()
    rid = _make_responder(
        client, uptime_kuma_url="https://host//api/push/TOK?status=down&keep=1")
    # Revealed (stored) value is canonical: single slash, no status param.
    revealed = client.post(f"/api/responders/{rid}/kuma-url",
                           headers=_csrf()).get_json()["uptime_kuma_url"]
    assert revealed == "https://host/api/push/TOK?keep=1"


# --------------------------------------------------------------------------- #
# Issue 4: persistent per-event exclude / re-include in reports
# --------------------------------------------------------------------------- #
def _seed_one_downtime(m, rid):
    """Insert Error->Valid history so the window has 1h down then up."""
    now = datetime.now(timezone.utc)
    t_down = (now - timedelta(hours=2)).isoformat()
    t_up = (now - timedelta(hours=1)).isoformat()
    db = m.raw_db()
    db.execute("INSERT INTO history (responder_id, status, message, timestamp) "
               "VALUES (?,?,?,?)", (rid, "Error", "boom", t_down))
    db.execute("INSERT INTO history (responder_id, status, message, timestamp) "
               "VALUES (?,?,?,?)", (rid, "Valid", "ok", t_up))
    db.commit()
    db.close()
    # Window ends before "now" so any concurrent scheduler check (which would
    # append a row at ~now) can't perturb the math.
    return now - timedelta(hours=3), now - timedelta(minutes=30)


def test_exclude_and_reinclude_event_persists(m):
    client = m.app.test_client()
    rid = _make_responder(client)
    ws, we = _seed_one_downtime(m, rid)

    db = m.raw_db()
    rep = m.compute_uptime(db, rid, ws, we)
    db.close()
    down = next(d for d in rep["downtimes"] if d["status"] == "Error")
    hid = down["hist_id"]
    assert down["manually_excluded"] is False
    assert rep["down_seconds"] > 0
    assert rep["manual_excluded_seconds"] == 0.0
    base_pct = rep["uptime_pct"]
    assert base_pct is not None and base_pct < 100.0  # there is real downtime

    # Exclude the event via the API.
    r = client.put(f"/api/history/{hid}", json={"excluded": True}, headers=_csrf())
    assert r.status_code == 200
    assert r.get_json()["excluded"] == 1

    db = m.raw_db()
    rep2 = m.compute_uptime(db, rid, ws, we)
    db.close()
    down2 = next(d for d in rep2["downtimes"] if d["hist_id"] == hid)
    assert down2["manually_excluded"] is True
    assert down2["excluded"] is True
    assert rep2["down_seconds"] == 0.0           # excluded leaves the denominator
    assert rep2["manual_excluded_seconds"] > 0
    assert rep2["uptime_pct"] == 100.0           # only up-time remains in totals

    # Persisted: the history endpoint reflects it for a future report open.
    hist = client.get(f"/api/responders/{rid}/history?limit=50").get_json()
    assert next(h for h in hist if h["id"] == hid)["excluded"] == 1

    # Re-include restores the downtime.
    r = client.put(f"/api/history/{hid}", json={"excluded": False}, headers=_csrf())
    assert r.status_code == 200
    db = m.raw_db()
    rep3 = m.compute_uptime(db, rid, ws, we)
    db.close()
    assert rep3["down_seconds"] > 0
    assert rep3["manual_excluded_seconds"] == 0.0
    assert rep3["uptime_pct"] == base_pct


def test_exclude_toggle_does_not_wipe_comment(m):
    client = m.app.test_client()
    rid = _make_responder(client)
    ws, we = _seed_one_downtime(m, rid)
    db = m.raw_db()
    hid = next(d for d in m.compute_uptime(db, rid, ws, we)["downtimes"]
               if d["status"] == "Error")["hist_id"]
    db.close()

    client.put(f"/api/history/{hid}", json={"comment": "investigated"}, headers=_csrf())
    # Toggling exclusion must not clear the existing comment.
    client.put(f"/api/history/{hid}", json={"excluded": True}, headers=_csrf())
    row = client.put(f"/api/history/{hid}", json={"excluded": False},
                     headers=_csrf()).get_json()
    assert row["comment"] == "investigated"
    assert row["excluded"] == 0


def test_history_put_requires_a_field(m):
    client = m.app.test_client()
    rid = _make_responder(client)
    ws, we = _seed_one_downtime(m, rid)
    db = m.raw_db()
    hid = next(d for d in m.compute_uptime(db, rid, ws, we)["downtimes"]
               if d["status"] == "Error")["hist_id"]
    db.close()
    r = client.put(f"/api/history/{hid}", json={}, headers=_csrf())
    assert r.status_code == 400
