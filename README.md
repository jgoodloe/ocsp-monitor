# OCSP Monitor (single-container edition)

A lightweight tool for monitoring OCSP responders. It periodically sends real
OCSP requests for the certificates you configure, records the result
(good / revoked / unknown / error), tracks response time and the
`thisUpdate` / `nextUpdate` window, keeps a history of status changes, and can
push results to Uptime Kuma.

This is a from-scratch rebuild of the original three-container stack
(MongoDB + Node API + React/Vite frontend) as a **single Flask container** with
no separate frontend and backend. That design removes the part that fought with
reverse proxies: the old React frontend tried to *guess* the backend URL from
the browser hostname and port. Here, the UI and API are served by the same
process on the same origin, and every request the browser makes is **relative**,
so the app works behind a reverse proxy — including under a subpath — with no
URL configuration.

## Why single-container

- **One upstream for your reverse proxy.** No CORS, no cross-service routing, no
  separate API port to expose.
- **No external database.** State lives in SQLite on a Docker volume. Fine for
  the intended scale of **fewer than ~30 responders**.
- **Built-in scheduler.** A background thread runs due checks; no cron, no job
  queue, no worker container.

## Quick start

```bash
git clone <this-repo> ocsp-monitor
cd ocsp-monitor
cp .env.example .env        # optional; defaults are sensible
docker compose up -d --build
```

Open <http://localhost:8080>. Click **+ Add responder** and provide:

- **Alias** — a name for the dashboard.
- **Certificate to check (PEM)** — the cert whose revocation status you want.
- **Issuer certificate (PEM)** — the CA cert that issued it (required to build
  the OCSP request).
- **OCSP URI** — optional. If left blank, the app uses the OCSP URL embedded in
  the certificate's AIA extension.
- **Frequency**, **Uptime Kuma URL**, **Enabled** — as needed.

The first check runs immediately; subsequent checks run on the schedule. Use
**Check** on any row to run an on-demand check.

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Port the app listens on inside the container. |
| `URL_PREFIX` | *(empty)* | Subpath to mount under, e.g. `/ocsp`. Leave empty for root or a dedicated (sub)domain. |
| `SCHEDULER_INTERVAL` | `30` | How often (seconds) the scheduler looks for due checks. |
| `OCSP_TIMEOUT` | `30` | Per-request OCSP HTTP timeout (seconds). |
| `HISTORY_LIMIT` | `200` | Status-history rows retained per responder. |
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR`. |
| `DATA_DIR` | `/data` | Where the SQLite DB is stored (mount a volume here). |

## Reverse proxy

The app trusts `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, and
`X-Forwarded-Prefix` (one proxy hop) via Werkzeug's `ProxyFix`.

### Own (sub)domain at root — simplest

Leave `URL_PREFIX` empty.

**nginx:**
```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### Under a subpath, e.g. `https://host/ocsp`

Set `URL_PREFIX=/ocsp` (in `.env` or compose). The UI uses relative paths, so it
adapts automatically; setting the prefix makes the app respond at `/ocsp/...`
and correctly 404 elsewhere.

**nginx (no trailing slash on `proxy_pass`, so the `/ocsp` prefix is preserved):**
```nginx
location /ocsp/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Prefix /ocsp;
}
```

### Nginx Proxy Manager (NPM)

Create a Proxy Host, Forward Hostname/IP = the Docker host or container, Forward
Port = `8080`, scheme `http`. Enable **Websockets** is not required. For a
subpath, use the **Custom locations** tab with location `/ocsp` and the same
forward target, and set `URL_PREFIX=/ocsp`.

### Traefik (labels)

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.ocsp.rule=Host(`ocsp.example.com`)"
  - "traefik.http.services.ocsp.loadbalancer.server.port=8080"
```

### pfSense (HAProxy)

Point a backend server at the Docker host on port `8080`, attach it to the
frontend handling your hostname, and forward the standard `X-Forwarded-*`
headers (HAProxy does `X-Forwarded-For` by default). Use root deployment
(`URL_PREFIX` empty) for the least friction.

## How a check works

For each enabled responder whose `next_run` is due, the app:

1. Loads the certificate and issuer from stored PEM.
2. Builds a proper OCSP request with the `cryptography` library (SHA-1 `CertID`,
   per RFC 6960 — this is the hash of issuer name/key, not a signature digest)
   and HTTP-POSTs it to the OCSP URI (or the cert's AIA OCSP URL).
3. Parses the DER response, reads the certificate status, and extracts
   `thisUpdate` / `nextUpdate`. A `good` response whose `nextUpdate` is already
   in the past is flagged as an error (stale responder).
4. Stores status, message, response time, and the update window; appends a
   history row **only when the status changes**; optionally pushes to Uptime
   Kuma.

No `openssl` CLI is invoked — it's all in-process via `cryptography`.

> **Note on public web certs:** Many public CAs have stopped including OCSP in
> their certificates (the CA/Browser Forum made OCSP optional in 2024). This
> tool is aimed at PKIs where OCSP is still required — e.g. federal PIV/PIV-I —
> and works against any responder that speaks RFC 6960.

## API

All endpoints are under `<prefix>/api`:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/status` | Health check (used by Docker HEALTHCHECK). |
| GET | `/api/responders` | List responders (no PEM payload). |
| POST | `/api/responders` | Create a responder. |
| GET | `/api/responders/{id}` | Get one responder (includes PEM). |
| PUT | `/api/responders/{id}` | Update a responder. |
| DELETE | `/api/responders/{id}` | Delete a responder. |
| POST | `/api/responders/{id}/check` | Run a check now. |
| GET | `/api/responders/{id}/history?limit=N` | Status-change history. |
| GET/PUT | `/api/settings` | Logging settings. |

## Data & backup

Everything is in the `ocsp_data` volume at `/data/ocsp_monitor.db`. Back it up
with:

```bash
docker compose exec ocsp-monitor sh -c "cat /data/ocsp_monitor.db" > backup.db
```

## Migrating from the old version

The data models map cleanly: old `certAlias` → `cert_alias`, `certPath` (PEM
content) → `cert_pem`, `issuerCertPath` → `issuer_pem`, `ocspUri` → `ocsp_uri`,
`frequencyMinutes` → `frequency_min`, `uptimeKumaUrl` → `uptime_kuma_url`. You
can re-add responders through the UI, or script POSTs to `/api/responders` from
a dump of the old MongoDB `ocspconfigs` collection.

## Notes

- Run with a **single** gunicorn worker (the Dockerfile does this) so the
  in-process scheduler runs exactly once. Concurrency for the handful of
  responders + UI comes from threads, which is plenty for I/O-bound OCSP calls.
- For more than a few dozen responders you'd want a real scheduler/queue and a
  client/server database — out of scope here by design.
