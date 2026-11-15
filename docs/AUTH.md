# Authentication

OCSP Monitor supports two sign-in methods, which can be used together:

- **OIDC SSO** against a standard OpenID Connect issuer (designed for
  [authentik](https://goauthentik.io/), but any compliant IdP works).
- A **local username/password** account (argon2id-hashed), as a fallback and a
  break-glass recovery path.

This app has **no roles or per-object permissions** — it is a single shared
monitor. The authorization model is therefore simple: **any authenticated user
has full access.** You can optionally restrict *who may sign in via the IdP* to
members of specific groups (see [Restricting SSO to groups](#restricting-sso-to-groups)).

## Fail-closed by default

Unlike the original build (which relied on binding to loopback behind a proxy),
the app now **refuses to start if no authentication is configured.** This is
deliberate: it can never silently come up open on a network.

To run with **no** authentication anyway — only on an isolated single-user or
development box — you must opt in explicitly:

```ini
OCSPMON_ALLOW_OPEN_MODE=true
```

In open mode every request has full access and a warning is logged on startup.

> **Upgrading from a version without auth?** This is a breaking change. Either
> configure authentication (below) or set `OCSPMON_ALLOW_OPEN_MODE=true` before
> you redeploy, or the container will fail to start.

## What "enabled" means

Authentication is **enforced** as soon as any of these is set:

- `OCSPMON_SESSION_SECRET`, or
- `OCSPMON_BOOTSTRAP_ADMIN_PASSWORD`, or
- a complete OIDC configuration (issuer **and** client id **and** client secret).

The **"Sign in with SSO"** button appears only when **all three** of
`OCSPMON_OIDC_ISSUER`, `OCSPMON_OIDC_CLIENT_ID`, and `OCSPMON_OIDC_CLIENT_SECRET`
are non-empty — that is the whole `oidc_enabled` rule. Setting the issuer alone
gives you local login only.

## How it works

- **Users** are either an OIDC identity (matched on the stable `sub` claim,
  **never** on email — email and display name are mutable and only used for
  display) or a local account. Local passwords are hashed with **argon2id**.
- **Sessions** use a signed, `HttpOnly`, `SameSite=Lax` cookie (secure flag on
  by default). The browser never holds IdP tokens. The cookie is signed with
  `OCSPMON_SESSION_SECRET`.
- The **health endpoint** (`/api/status`) and the login surfaces stay public;
  every other route requires a session. Unauthenticated API calls get `401`;
  unauthenticated page loads redirect to `/login`.
- The OIDC flow uses **state** (CSRF) and **nonce** (ID-token replay) validation,
  handled by authlib, and works behind an HTTPS reverse proxy and under a URL
  subpath.

## Turning auth on (local login)

Set a session secret and a break-glass admin password:

```ini
OCSPMON_SESSION_SECRET=<openssl rand -hex 32>   # required in production; keep stable
OCSPMON_BOOTSTRAP_ADMIN_PASSWORD=change-me       # creates/resets the 'admin' account
```

At startup the break-glass admin (`OCSPMON_BOOTSTRAP_ADMIN_USERNAME`, default
`admin`) is created, or its password reset. **This is how you create the first
user** — there is no self-registration. Sign in with it, then wire up OIDC.

Set these in your `.env` file (see `.env.example`); `docker-compose.yml` passes
every `OCSPMON_*` variable through to the container.

## OIDC (authentik)

```ini
OCSPMON_OIDC_ISSUER=https://authentik.example.com/application/o/ocspmon/
OCSPMON_OIDC_CLIENT_ID=...
OCSPMON_OIDC_CLIENT_SECRET=...
OCSPMON_OIDC_SCOPES=openid email profile
OCSPMON_OIDC_GROUP_CLAIM=groups
OCSPMON_PUBLIC_BASE_URL=https://ocspmonitor.goodloe.xyz
```

### The redirect / callback URL

Register this exact URL in your IdP (no trailing slash, https):

```
<public-base-url><url-prefix>/api/auth/oidc/callback
```

For the production deployments that means:

- `https://ocspmonitor.goodloe.xyz/api/auth/oidc/callback`
- `https://crlmonitor.goodloe.xyz/api/auth/oidc/callback`

Set `OCSPMON_PUBLIC_BASE_URL` to your public origin. If it is left empty, the
callback URL is derived from the forwarded host headers (requires
`TRUSTED_PROXY_HOPS >= 1` so `X-Forwarded-Proto`/`-Host` are honoured); setting
`OCSPMON_PUBLIC_BASE_URL` explicitly is the robust choice behind most proxies.

### One-time setup in authentik — checklist

1. **Create a provider and application.** In authentik, create an
   *OAuth2/OpenID Provider*, then an *Application* bound to it. Note the
   **application slug** — the issuer is
   `https://<authentik-host>/application/o/<slug>/`, and the issuer you configure
   must belong to the **same** application whose client id/secret you use.
   - **Client type:** Confidential.
   - **Redirect URI:** add it exactly (no trailing slash, https):
     ```
     https://ocspmonitor.goodloe.xyz/api/auth/oidc/callback
     ```
     (and/or the `crlmonitor.goodloe.xyz` equivalent for that instance).
   - **Scopes:** `openid`, `email`, `profile`.
   - Copy the generated **Client ID** and **Client Secret**.
2. **Set the variables** in `.env` — one block, no duplicates:
   ```ini
   OCSPMON_OIDC_ISSUER=https://<authentik-host>/application/o/<slug>/
   OCSPMON_OIDC_CLIENT_ID=<from the provider>
   OCSPMON_OIDC_CLIENT_SECRET=<from the provider>
   OCSPMON_OIDC_SCOPES=openid email profile
   OCSPMON_PUBLIC_BASE_URL=https://ocspmonitor.goodloe.xyz
   OCSPMON_SESSION_SECRET=<openssl rand -hex 32>
   ```
3. **Recreate the container** — an `env_file`/`environment` change does *not*
   apply on a plain `docker compose restart`:
   ```bash
   docker compose up -d --force-recreate ocsp-monitor
   ```
4. Reload `/login`: you should now see the local form **and** an SSO button.

### Restricting SSO to groups

By default, **any** user your IdP authenticates may sign in. To allow only
members of specific groups, set a comma-separated allowlist:

```ini
OCSPMON_OIDC_ALLOWED_GROUPS=ocsp-admins,ocsp-operators
```

A user whose group claim (`OCSPMON_OIDC_GROUP_CLAIM`, default `groups`) shares no
value with the allowlist is refused with `403` at the callback. Group names are
matched exactly. Leave the variable empty to allow all authenticated users.

### SSO-only

To hide the local form and accept only SSO, set:

```ini
OCSPMON_LOCAL_LOGIN_ENABLED=false
```

The break-glass admin still works for recovery when the IdP is unavailable.

### Troubleshooting

- **No SSO button:** one of the three OIDC values is blank, or a **duplicate**
  later in `.env` overrides the earlier one — keep exactly one of each. Or you
  ran `restart` instead of `up -d --force-recreate` (step 3).
- **Button works but login fails:** the issuer doesn't match the application
  that issued the client id/secret, or the redirect URI in authentik doesn't
  exactly match `…/api/auth/oidc/callback` at your public host.
- **Redirect loops / insecure cookie:** behind a proxy, ensure TLS terminates at
  the proxy and `TRUSTED_PROXY_HOPS` matches your topology, or set
  `OCSPMON_PUBLIC_BASE_URL`. Keep `OCSPMON_SESSION_COOKIE_SECURE=true` for HTTPS.

> Treat the client secret and `OCSPMON_SESSION_SECRET` as credentials: they live
> only in the environment (never commit them, they are never logged). Rotate
> them if ever exposed (new secret in authentik; a fresh `openssl rand -hex 32`
> session secret — which signs out all existing sessions).

## Configuration reference

| Variable | Default | Purpose |
| --- | --- | --- |
| `OCSPMON_ALLOW_OPEN_MODE` | `false` | Opt in to running with **no** auth (unsafe). |
| `OCSPMON_SESSION_SECRET` | *(none)* | Signs the session cookie. Set a stable value in production. |
| `OCSPMON_SESSION_TTL_SECONDS` | `28800` | Session lifetime (8h). |
| `OCSPMON_SESSION_COOKIE_SECURE` | `true` | Send the cookie only over HTTPS. Set `false` only for local http testing. |
| `OCSPMON_SESSION_COOKIE_NAME` | `ocspmon_session` | Session cookie name. |
| `OCSPMON_BOOTSTRAP_ADMIN_USERNAME` | `admin` | Break-glass admin username. |
| `OCSPMON_BOOTSTRAP_ADMIN_PASSWORD` | *(none)* | Set to create/reset the break-glass admin at startup. |
| `OCSPMON_LOCAL_LOGIN_ENABLED` | `true` | Show the local username/password form. |
| `OCSPMON_OIDC_ISSUER` | *(none)* | OIDC issuer URL (authentik application endpoint). |
| `OCSPMON_OIDC_CLIENT_ID` | *(none)* | OIDC client id. |
| `OCSPMON_OIDC_CLIENT_SECRET` | *(none)* | OIDC client secret. |
| `OCSPMON_OIDC_SCOPES` | `openid email profile` | Requested scopes. |
| `OCSPMON_OIDC_GROUP_CLAIM` | `groups` | Claim listing the user's groups. |
| `OCSPMON_OIDC_ALLOWED_GROUPS` | *(empty = all)* | Comma-separated groups allowed to sign in via SSO. |
| `OCSPMON_PUBLIC_BASE_URL` | *(derived)* | External origin for building the OIDC redirect URI. |

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/login` | public | Login page (local form + SSO button). |
| `GET` | `/api/auth/config` | public | `{auth_required, local_login_enabled, oidc_enabled, oidc_login_url}`. |
| `POST` | `/api/auth/login` | public | Local login (JSON `{username, password}`; needs `X-Requested-With`). |
| `GET` | `/api/auth/oidc/login` | public | Begin the OIDC flow (redirects to the IdP). |
| `GET` | `/api/auth/oidc/callback` | public | OIDC redirect URI (validates state + nonce). |
| `GET` | `/api/auth/me` | required | The current user. |
| `POST` | `/api/auth/logout` | required | Clear the session. |

## Dependencies & security pinning

- `authlib>=1.8.0,<2.0.0` — the OIDC client. The floor is **above** the fix for
  **CVE-2024-37568** (JWS `alg` confusion / OIDC ID-token forgery); the whole
  range excludes every affected version.
- `passlib[argon2]>=1.7.4,<2.0.0` — argon2id password hashing.
- `itsdangerous>=2.2.0,<3.0.0` — session-cookie signing (a Flask dependency,
  pinned to the current fixed line).
