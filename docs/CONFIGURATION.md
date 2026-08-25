# Configuration Reference

Complete environment variables reference for TokenTimer Core.

Defaults come from code fallbacks in `apps/*` and `packages/config/*`, then from compose/examples where applicable.

`unset` means optional and disabled unless you set it. `required` means you must provide a value for production.

## Core runtime and bootstrap

| Variable                  | Description                              | Default value                  | Scope                  |
| ------------------------- | ---------------------------------------- | ------------------------------ | ---------------------- |
| `TT_MODE`                 | Core variant mode                        | `oss`                          | App mode               |
| `NODE_ENV`                | Runtime environment                      | `development`                  | API, worker, dashboard |
| `SESSION_SECRET`          | Session signing secret                   | `required`                     | API, worker            |
| `ADMIN_EMAIL`             | First admin bootstrap email              | `admin@your-company.com`       | API bootstrap          |
| `ADMIN_PASSWORD`          | First admin bootstrap password           | `ChangeThisSecurePassword123!` | API bootstrap          |
| `ADMIN_NAME`              | First admin bootstrap display name       | `Administrator`                | API bootstrap          |
| `DISABLE_ADMIN_BOOTSTRAP` | Skip first admin auto-create when `true` | `false`                        | API bootstrap          |
| `DISABLE_MANUAL_INVITES`  | Block new manual workspace invites/direct-adds when `true` | `false`      | API                    |
| `PORT`                    | API listen port                          | `4000`                         | API                    |
| `HOST`                    | API bind host                            | `0.0.0.0`                      | API                    |
| `API_PORT`                | Compose API port mapping                 | `4000`                         | Local compose          |
| `DASHBOARD_PORT`          | Compose dashboard port mapping           | `5173`                         | Local compose          |

## Canonical URLs and API docs

| Variable            | Description                                      | Default value                   | Scope                  |
| ------------------- | ------------------------------------------------ | ------------------------------- | ---------------------- |
| `APP_URL`           | Frontend public URL (canonical)                  | `http://localhost:5173`         | API, worker, dashboard |
| `API_URL`           | Backend public URL (canonical)                   | `http://localhost:4000`         | API, worker, dashboard |
| `ENABLE_API_DOCS`   | Enable Swagger UI (`/api-docs`) in production    | `false`                         | API docs serving       |
| `VITE_API_URL`      | Frontend build-time API override                 | `http://localhost:4000`         | Dashboard build        |
| `OPENAPI_SPEC_PATH` | Optional absolute path to OpenAPI YAML           | `unset (auto-discovery)`        | API docs serving       |
| `PUBLIC_BASE_URL`   | Public URL used for webhook signature validation | `unset (falls back to API_URL)` | API webhook auth       |

**Helm vs Compose vs runtime**

| Layer | `APP_URL` | `API_URL` when unset in your config |
| ----- | --------- | ------------------------------------- |
| Helm (`config.baseUrl` / `apiUrl`) | `baseUrl` | `apiUrl` if set, else **`baseUrl`** (same host) |
| Helm stock `values.yaml` | `http://localhost:8080` | `http://localhost:4000` (both set explicitly) |
| Docker Compose (`.env`) | `${APP_URL:-http://localhost:5173}` | `${API_URL:-http://localhost:4000}` (no cross-fallback in compose files) |
| API process (env missing) | `http://localhost:5173` | `API_URL`, else **`APP_URL`**, else `http://localhost:4000` |

> [!WARNING]
> In local `http://localhost` with `NODE_ENV=production`, browser does not persist/send the secure session cookie for auth flow.
> Use HTTPS in front of API and dashboard (reverse proxy with TLS), otherwise secure cookies are expected to fail in local HTTP.

### Split-host deployments (dashboard and API on different origins)

When `APP_URL` and `API_URL` differ on **HTTPS** (for example dashboard at
`https://app.example.com` and API at `https://api.example.com`), the API:

- Allows both origins in CORS (configured `APP_URL` and `API_URL` only in production;
  localhost dev origins are omitted unless `ALLOW_LOCAL_DEV_CORS=true`).
- Sets session and CSRF cookies to `SameSite=None; Secure` on the API host.
  Host-only cookies (no `SESSION_COOKIE_DOMAIN`) are enough for credentialed
  `withCredentials` calls from the dashboard to `api.example.com`. Set
  `SESSION_COOKIE_DOMAIN` only when you intentionally need a parent-domain cookie
  shared across multiple subdomains (broader scope; weaker isolation).

**HTTP split-host** (including LAN IPs or internal DNS without TLS) does **not** use
`SameSite=None`; cookies stay `Lax` because `None` requires `Secure` and is often blocked.
Use HTTPS for split-host production, or put UI and API behind one origin (ingress).

**Docker Compose** (`http://localhost:5173` + `http://localhost:4000`) and **Helm
port-forward** (`http://localhost:8080` + `http://localhost:4000`) keep `SameSite=Lax`
(same-site across ports on local HTTP). For plain HTTP + `NODE_ENV=production`, set
`SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE=true` only when **both** `APP_URL` and
`API_URL` are local HTTP (`localhost` / `127.0.0.1`); the flag is ignored on
internet-facing HTTPS URLs.

Same-host installs (single ingress hostname for UI and API) can leave
`SESSION_COOKIE_DOMAIN` unset. Helm defaults often use `baseUrl: http://localhost:8080`
and `apiUrl: http://localhost:4000`; Compose maps the dashboard to host port `5173`
by default (`APP_URL=http://localhost:5173`). Always set `APP_URL` and `API_URL` to
the origins users and integrations actually use in the browser.

## Database and pooling

| Variable                | Description                             | Default value                                | Scope       |
| ----------------------- | --------------------------------------- | -------------------------------------------- | ----------- |
| `DB_HOST`               | PostgreSQL host                         | `localhost` (code), `postgres` (compose)     | API, worker |
| `DB_PORT`               | PostgreSQL port                         | `5432`                                       | API, worker |
| `DB_NAME`               | PostgreSQL database name                | `tokentimer`                                 | API, worker |
| `DB_USER`               | PostgreSQL user                         | `tokentimer`                                 | API, worker |
| `DB_PASSWORD`           | PostgreSQL password                     | `password` (dev fallback), `required` (prod) | API, worker |
| `DATABASE_URL`          | Full PostgreSQL connection URL override | `unset`                                      | API, worker |
| `DB_SSL`                | DB SSL mode (`require` or `verify`)     | `unset (disabled)`                           | API, worker |
| `PGSSLROOTCERT`         | Path to CA cert for DB SSL verify mode  | `unset`                                      | API, worker |
| `DB_POOL_MAX`           | Max DB pool connections                 | `10`                                         | API, worker |
| `DB_POOL_MIN`           | Min DB pool connections                 | `2`                                          | API, worker |
| `DB_POOL_IDLE_TIMEOUT`  | Idle connection timeout (ms)            | `30000`                                      | API, worker |
| `DB_CONNECTION_TIMEOUT` | DB connection timeout (ms)              | `5000`                                       | API, worker |

## Authentication and security

> **Auth tuning is not configurable.** `LOCAL_AUTH_ENABLED`,
> `REQUIRE_EMAIL_VERIFICATION`, `TWO_FACTOR_ENABLED`, `SESSION_MAX_AGE`,
> `CSRF_ENABLED`, `MIN_PASSWORD_LENGTH`, `REQUIRE_UPPERCASE` and
> `REQUIRE_NUMBERS` were previously listed here as supported variables. They are
> parsed by `packages/config` but never read, so setting them has no effect. The
> real behavior is fixed in code: a 2-hour rolling session cookie, CSRF always on
> outside tests, local auth and TOTP always available, and a fixed 12-character
> 5-class password policy. See [AUTHENTICATION.md](AUTHENTICATION.md).
>
> The cookie, CORS, and proxy variables below _are_ live.

| Variable                                   | Description                                                                     | Default value                          | Scope        |
| ------------------------------------------ | ------------------------------------------------------------------------------- | -------------------------------------- | ------------ |
| `SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE` | Allow insecure session cookies in production only when `APP_URL` and `API_URL` are both local HTTP (`localhost` / `127.0.0.1`); ignored otherwise | `false`                                | API auth     |
| `SESSION_COOKIE_DOMAIN`                    | Optional parent domain for session/CSRF cookies (e.g. `.example.com`) when you need cookies shared across subdomains; not required for typical split-host API calls | `unset`                                | API auth     |
| `ALLOW_LOCAL_DEV_CORS`                     | In production, also allow `http://localhost:*` and `http://127.0.0.1:*` in CORS (local troubleshooting only) | `false`                                | API security |
| `PHONE_HASH_SALT`                          | Optional salt for phone hashing                                                 | `unset`                                | API privacy  |
| `TRUST_PROXY_HOPS`                         | Number of trusted reverse-proxy hops in front of the API (affects `req.ip` and `req.protocol` resolution). `0` = no proxy, `1` = single ingress/reverse proxy, `2` = LB -> ingress. | `2`                                    | API security |
| `WORKER_API_KEY`                           | Worker-to-API auth key                                                          | `unset (falls back to SESSION_SECRET)` | Worker, API  |

## Email and delivery

| Variable                   | Description                        | Default value                                             | Scope             |
| -------------------------- | ---------------------------------- | --------------------------------------------------------- | ----------------- |
| `SMTP_HOST`                | SMTP host(s) (comma-separated)     | `localhost` in config helper, `unset` in compose examples | API, worker email |
| `SMTP_PORT`                | SMTP port(s) (comma-separated)     | `587` in config helper                                    | API, worker email |
| `SMTP_USER`                | SMTP username(s) (comma-separated) | `unset`                                                   | API, worker email |
| `SMTP_PASS`                | SMTP password(s) (comma-separated) | `unset`                                                   | API, worker email |
| `FROM_EMAIL`               | Sender email override              | `unset`                                                   | API, worker email |
| `FROM_EMAIL_NAME`          | Sender display name                | `TokenTimer`                                              | API, worker email |
| `SMTP_SECURE`              | Force SMTPS/SSL                    | `false`                                                   | API, worker email |
| `SMTP_REQUIRE_TLS`         | Require STARTTLS upgrade           | `true`                                                    | API, worker email |
| `SMTP_REJECT_UNAUTHORIZED` | Reject invalid TLS certs           | `unset`                                                   | API, worker email |

## Alerts, limits, and webhooks

| Variable                                  | Description                                                                 | Default value                         | Scope                |
| ----------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------- | -------------------- |
| `ALERT_THRESHOLDS`                        | Default days-before-expiry thresholds (overridden by workspace preferences) | `30,14,7,1,0`                         | Alerts               |
| `ALERT_MAX_ATTEMPTS`                      | Max delivery retries per alert                                              | `20`                                  | Alerts               |
| `ALERT_RETRY_DELAY_MS`                    | Retry delay in ms                                                           | `300000`                              | Alerts               |
| `ALERT_TEST_UTC_DAY`                      | Test-only scheduler day override                                            | `unset`                               | Alerts testing       |
| `GLOBAL_RATE_LIMIT_WINDOW_MS`             | Global limiter window in ms                                                 | `60000`                               | API rate limiting    |
| `GLOBAL_RATE_LIMIT_MAX`                   | Global limiter max requests per window                                      | `300` (prod) / `1000` (dev,test)      | API rate limiting    |
| `GLOBAL_SLOWDOWN_WINDOW_MS`               | Global slowdown window in ms                                                | `900000`                              | API rate limiting    |
| `GLOBAL_SLOWDOWN_DELAY_AFTER`             | Requests before delay is applied                                            | `50`                                  | API rate limiting    |
| `GLOBAL_SLOWDOWN_DELAY_MS`                | Added delay per request after threshold                                     | `500`                                 | API rate limiting    |
| `LOGIN_RATE_LIMIT_WINDOW_MS`              | Login limiter window in ms                                                  | `900000`                              | Auth rate limiting   |
| `LOGIN_RATE_LIMIT_MAX`                    | Login attempts per window                                                   | `10` (prod) / `500` (dev,test)        | Auth rate limiting   |
| `LOGIN_EMAIL_RATE_LIMIT_MAX`              | Login attempts per email per window                                         | `5` (prod) / `500` (dev,test)         | Auth rate limiting   |
| `PASSWORD_RESET_RATE_LIMIT_WINDOW_MS`     | Password reset limiter window in ms                                         | `900000`                              | Auth rate limiting   |
| `PASSWORD_RESET_RATE_LIMIT_MAX`           | Password reset attempts per window                                          | `5` (prod) / `100` (dev,test)         | Auth rate limiting   |
| `PASSWORD_RESET_EMAIL_RATE_LIMIT_MAX`     | Password reset attempts per email per window                                | `3` (prod) / `200` (dev,test)         | Auth rate limiting   |
| `EMAIL_VERIFICATION_RATE_LIMIT_WINDOW_MS` | Email verification limiter window in ms                                     | `3600000`                             | Auth rate limiting   |
| `EMAIL_VERIFICATION_RATE_LIMIT_MAX`       | Email verification attempts per window                                      | `20` (prod) / `500` (dev,test)        | Auth rate limiting   |
| `AUTH_SLOWDOWN_WINDOW_MS`                 | Auth slowdown window in ms                                                  | `900000`                              | Auth rate limiting   |
| `AUTH_SLOWDOWN_DELAY_AFTER`               | Auth requests before slowdown                                               | `5` (prod) / `1000` (dev,test)        | Auth rate limiting   |
| `AUTH_SLOWDOWN_DELAY_MS`                  | Auth slowdown delay per request in ms                                       | `500`                                 | Auth rate limiting   |
| `AUTH_SLOWDOWN_MAX_DELAY_MS`              | Auth slowdown max delay in ms                                               | `10000`                               | Auth rate limiting   |
| `API_RATE_LIMIT_WINDOW_MS`                | Plan-aware API limiter window in ms                                         | `900000`                              | API rate limiting    |
| `TEST_API_RATE_LIMIT_WINDOW_MS`           | Test/dev API limiter window in ms                                           | `900000`                              | API rate limiting    |
| `TEST_API_RATE_LIMIT_MAX`                 | Test/dev API limiter max requests                                           | `1000` (prod) / `10000` (dev,test)    | API rate limiting    |
| `DELIVERY_WINDOW_DEFAULT_START`           | Default delivery window start (UTC, overridden by workspace preferences)    | `00:00`                               | Alerts               |
| `DELIVERY_WINDOW_DEFAULT_END`             | Default delivery window end (UTC, overridden by workspace preferences)      | `23:59`                               | Alerts               |
| `DELIVERY_WINDOW_DEFAULT_TZ`              | Default delivery timezone (overridden by workspace preferences)             | `UTC`                                 | Alerts               |
| `DELIVERY_WINDOW_DEFERRAL_MS`             | Defer delay when outside window                                             | `unset`                               | Alerts               |
| `MAX_WEBHOOKS`                            | Max webhooks per workspace                                                  | `unset`                               | Alerts/webhooks      |
| `TEST_WEBHOOK_RATE_LIMIT_1M_WINDOW_MS`    | Test webhook short limiter window in ms                                     | `60000`                               | Alerts/webhooks      |
| `TEST_WEBHOOK_RATE_LIMIT_1M_MAX`          | Test webhook max requests in short window                                   | `5`                                   | Alerts/webhooks      |
| `TEST_WEBHOOK_RATE_LIMIT_5M_WINDOW_MS`    | Test webhook long limiter window in ms                                      | `300000`                              | Alerts/webhooks      |
| `TEST_WEBHOOK_RATE_LIMIT_5M_MAX`          | Test webhook max requests in long window                                    | `10`                                  | Alerts/webhooks      |
| `TEST_WEBHOOK_COOLDOWN_MS`                | Per-user test webhook cooldown after each attempt                           | `5000`                                | Alerts/webhooks      |
| `WEBHOOK_ALLOW_ALL_HOSTS`                 | Allow all webhook destinations when `true`                                  | `false`                               | Webhook security     |
| `WEBHOOK_ALLOW_PRIVATE_IPS`               | Allow webhook delivery to private/reserved IPs when `true` (self-hosted)    | `false`                               | Webhook security     |
| `WEBHOOK_ENFORCE_PRIVATE_IP_CHECK`        | Force the private-IP check even when `NODE_ENV=test` (test infrastructure)  | `false`                               | Webhook security     |
| `WEBHOOK_PROVIDER_HOSTS`                  | Legacy alias for `WEBHOOK_EXTRA_PROVIDER_HOSTS`. Both variables are parsed and unioned together (not a fallback -- if both are set, hosts from either are allowed). Neither variable replaces the built-in provider allowlist (Slack, Discord, Teams incl. legacy `office.com`/`office365.com`, PagerDuty, and Power Automate/Logic Apps `*.logic.azure.com` / `*.environment.api.powerplatform.com`), which is always allowed in addition to whatever these add. Prefer `WEBHOOK_EXTRA_PROVIDER_HOSTS` for new entries. | `empty (built-in list still allowed)` | Webhook security     |
| `WEBHOOK_EXTRA_PROVIDER_HOSTS`            | Additional allowed hosts, unioned with the built-in provider allowlist above and with `WEBHOOK_PROVIDER_HOSTS` if both are set (comma-separated) | `empty`                               | Webhook security     |
| `VAULT_ADDRESS_ALLOWLIST`                 | Vault integration host allowlist                                            | `empty (no host restriction)`         | Integration security |
| `AZURE_VAULT_ADDRESS_ALLOWLIST`           | Azure Key Vault host allowlist                                              | `empty (no host restriction)`         | Integration security |
| `GITHUB_ADDRESS_ALLOWLIST`                | GitHub host allowlist                                                       | `empty (no host restriction)`         | Integration security |
| `GITLAB_ADDRESS_ALLOWLIST`                | GitLab host allowlist                                                       | `empty (no host restriction)`         | Integration security |
| `INTEGRATION_SCAN_LIMITS`                 | JSON plan-to-limit map (core defaults unlimited)                            | `{"oss":Infinity}`                    | Integration quotas   |
| `DOMAIN_CHECKER_DISCOVERY_LIMITS`         | Domain checker discovery result cap map (`plan:value`)                      | `oss:10000000`                        | Domain checker       |
| `DOMAIN_CHECKER_IMPORT_LIMITS`            | Domain checker import request cap map (`plan:value`)                        | `oss:50000`                           | Domain checker       |
| `DOMAIN_CHECKER_MAX_RESULTS`              | Direct override for discovery results, capped internally at 25,000,000      | `unset`                               | Domain checker       |
| `DOMAIN_CHECKER_IMPORT_MAX_CERTIFICATES`  | Direct override for import certificates per request, capped at 200,000      | `unset`                               | Domain checker       |
| `CONTACT_GROUP_LIMITS`                    | JSON plan-to-limit map (core defaults unlimited)                            | `{"oss":Infinity}`                    | Contact groups       |
| `CONTACT_GROUP_MEMBER_LIMITS`             | JSON plan-to-limit map (core defaults unlimited)                            | `{"oss":Infinity}`                    | Contact groups       |
| `WORKSPACE_PLAN_LIMITS`                   | JSON plan-to-limit map (core defaults unlimited)                            | `{"oss":Infinity}`                    | Workspaces           |
| `MEMBER_PLAN_LIMITS`                      | JSON plan-to-limit map (core defaults unlimited)                            | `{"oss":Infinity}`                    | Workspace members    |

## Proxy

Corporate proxy support for outbound HTTP(S) calls: the API's `fetch`/undici
calls (e.g. the webhook Test button, OAuth/SAML callbacks) and the worker's
`axios` calls (which already honor `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` on
any Node version; `NODE_USE_ENV_PROXY` only changes `fetch`/undici behavior).

The table below is the variable **inside the container**, which is what Node
actually reads. Docker Compose sources each one from a dedicated,
`TOKENTIMER_`-prefixed `.env` input (`TOKENTIMER_USE_ENV_PROXY`,
`TOKENTIMER_HTTP_PROXY`, `TOKENTIMER_HTTPS_PROXY`, `TOKENTIMER_NO_PROXY`)
rather than the bare name, so a corporate shell's own ambient `HTTP_PROXY` (or
`NODE_USE_ENV_PROXY`) can never silently apply to your containers. Set
`TOKENTIMER_USE_ENV_PROXY=1` whenever you set the proxy URLs in `.env`, or the
API's `fetch` stays unproxied (the Test button keeps failing) while the
worker's `axios` still proxies real delivery -- exactly the half-on state
this release fixes.

| Variable              | Description                                                                     | Default value | Scope       |
| --------------------- | -------------------------------------------------------------------------------- | -------------- | ----------- |
| `NODE_USE_ENV_PROXY`   | Set to `1` to make Node's global `fetch`/undici honor `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`. Requires Node **22.21.0+ or 24.0.0+** for `fetch`/undici (not any `23.x` release). Node's native `node:http`/`node:https` modules need a later floor, **24.5.0+**, but neither the API nor the worker use those modules directly today (API uses `fetch`, worker uses `axios`), so that later floor doesn't gate anything here. On an unsupported version the API and worker log a non-fatal startup warning and `fetch`/undici simply ignore the proxy vars (`axios` keeps working regardless of Node version). Compose sets `NODE_OPTIONS=--disable-warning=UNDICI-EHPA` alongside this variable to silence Node's own `EnvHttpProxyAgent is experimental` warning. Compose input: `TOKENTIMER_USE_ENV_PROXY`. | `unset (disabled)` | API, worker |
| `HTTP_PROXY`           | Proxy URL for plain HTTP destinations, e.g. `http://user:pass@proxy:3128`. Compose input: `TOKENTIMER_HTTP_PROXY`. | `unset`        | API, worker |
| `HTTPS_PROXY`          | Proxy URL for HTTPS destinations. Compose input: `TOKENTIMER_HTTPS_PROXY`.        | `unset`        | API, worker |
| `NO_PROXY`             | Comma-separated hosts/domains that bypass the proxy. Only affects HTTP(S) traffic through `HTTP_PROXY`/`HTTPS_PROXY`, not raw SMTP. Compose input: `TOKENTIMER_NO_PROXY` (default `localhost,127.0.0.1,::1,api,postgres` -- overriding it must preserve the `api`/`postgres` service names). | `unset`        | API, worker |

**Helm.** The chart does not accept plain-text proxy URLs as values (they
commonly embed credentials). Set `config.useEnvProxy: true` plus
`config.proxyExistingSecret` (name of a pre-existing Secret containing
`HTTP_PROXY`/`HTTPS_PROXY` keys, mounted via `envFrom`; **required** -- the
chart fails the render if `useEnvProxy=true` without it) and, optionally,
`config.noProxy` for extra `NO_PROXY` entries -- the chart always appends
`localhost`, `127.0.0.1`, `::1`, the in-cluster API service hostname, and
`.svc`/`.cluster.local`, so intra-cluster calls never route through the
proxy. When `networkPolicy.enabled` and `config.useEnvProxy` are both `true`,
`networkPolicy.egress.proxyCidrs`/`proxyPorts` are **required** (the chart
fails the render naming whichever is missing, rather than silently rendering
a NetworkPolicy that blocks the proxy it was just told to use). See
[`deploy/helm/README.md`](../deploy/helm/README.md) for details and examples.

## CertOps (certificate operations)

| Variable           | Description                                                                                                                                                                                                                                                                                                                                 | Default value | Scope  |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- | ------ |
| `CERTOPS_ENABLED`  | Enable the certificate operations layer. When enabled, TokenTimer maintains a managed-certificate inventory linked to cert-category tokens, accepts public certificate (PEM) import, and bridges observations from HTTPS endpoint/domain monitors into the inventory (when the monitor has a linked token). When disabled, CertOps API endpoints return 404. Precedence: this env var > System Settings DB > code default. | `false` (app default when unset) | CertOps |
| `CERTOPS_SIGNING_ENCRYPTION_KEY` | AES-256-GCM wrap key for the control-plane's Ed25519 job-signing private key at rest (64 hex chars = 32 bytes). Required the first time any agent registers, when the signing key is first generated; encrypt/decrypt fail closed when unset or malformed, so registration and job dispatch cannot proceed without it. Rotate with `pnpm certops:rotate-signing-key` (see the signing-key rotation runbook), not by changing this value: this key wraps the signing key at rest, it is not the signing key itself. | unset (required before registering any agent) | API |
| `CERTOPS_REGISTRATION_ENCRYPTION_KEY` | AES-256-GCM wrap key for CertOps agent registration-replay credentials at rest (64 hex chars = 32 bytes). Required for agent registration; encrypt/decrypt fail closed when unset or malformed. Never store replay credentials as plaintext. | unset (required when registering agents) | API |
| `CERTOPS_REGISTRATION_REPLAY_TTL_MS` | Short TTL for registrationId → credential replay rows after a successful register (lost-response recovery). Expired rows are swept by the CertOps maintenance worker. | `900000` (15 minutes) | API |
| `CERTOPS_AGENT_OFFLINE_AFTER_MS` | How long an agent may go without a heartbeat (`last_seen_at`, or `created_at` if it never heartbeated) before it is treated as not-live. Read independently by two places that must be kept in sync if overridden: the API's `livenessState` fleet field (real-time, computed on every list/read call) and the CertOps maintenance worker's stale-agent sweep (periodic, persists `status='offline'`; requires the `certops` worker/CronJob target to actually be scheduled — see `docs/certops/agent.md`). | `600000` (10 minutes) | API + Worker |
| `CERTOPS_CAPABILITY_FRESHNESS_MS` | How recently `certops_agents.capabilities_updated_at` must have been stamped (by a `register` or `heartbeat` that included `declaredCapabilities`) for a capability-gated job format to dispatch, e.g. the v2 signed-payload-b64 envelope (`signed-payload-b64-v1`) or `evidence-claim-binding-v1`-gated jobs. Merely having declared a capability at some point in the past is not enough once its declaration is older than this window; an agent that stops heartbeating for longer than the window is dispatched the legacy/ungated format on its next claim, and reverts automatically once its next heartbeat lands. Deliberately reuses `CERTOPS_AGENT_OFFLINE_AFTER_MS`'s value rather than an independently chosen number (see ADR-0012 decision on capability epochs and ADR-0003's addendum), on the reasoning that an agent whose capability assertion is already stale enough to be liveness-stale has no business being offered a capability-gated job either. | `600000` (10 minutes) | API |
| `CERTOPS_AGENT_MIN_PROTOCOL_VERSION` / `CERTOPS_AGENT_MAX_PROTOCOL_VERSION` | Supported agent protocol version window used to compute fleet `compatibilityState`. | `1.0.0` / `1.999.999` | API |
| `CERTOPS_AGENT_MIN_AGENT_VERSION` / `CERTOPS_AGENT_MAX_AGENT_VERSION` | Supported agent build version window used to compute fleet `compatibilityState` (`blocked` outside this window). `MAX` is intentionally an unbounded reject-ceiling so the control plane never blocks an agent purely for being newer than this server knows about; it is not the reference used for the `outdated` label below. | `0.1.0` / `99.999.999` | API |
| `CERTOPS_AGENT_LATEST_KNOWN_VERSION` | Reference agent build version used only to compute the `outdated` fleet label (more than one minor behind this value, but still inside the min/max window above). Defaults to the version of the agent package this server actually ships (`packages/agent/package.json`), so it tracks every release automatically; override only if the API is intentionally serving a different agent build than the one bundled with it. | shipped agent package version | API |
| `CERTOPS_AGENT_CLOCK_DRIFT_WARN_MS` / `CERTOPS_AGENT_CLOCK_DRIFT_ALERT_MS` | Absolute clock-offset thresholds used to compute fleet `clockDriftState` (`warn`/`alert`). | `5000` / `30000` | API |
| `CERTOPS_RENEWAL_THRESHOLD_DAYS` | Schedule a renewal when a managed certificate expires within this many days. This is the fleet-wide default; a certificate whose renewal profile sets `certificate_profiles.renew_before_days` uses that value instead (`COALESCE(renew_before_days, <this>)`). Editing the profile from the Renewal automation page (`/certops/renewals`) is the supported way to give one certificate a longer runway than the rest of the fleet. A profile whose `status` is `disabled` or `archived` is excluded from renewal entirely regardless of this value. | `30` | API + Worker |
| `CERTOPS_RENEWAL_PER_CA_CAP` | Maximum in-flight renewals per CA endpoint per workspace, so one CA cannot be flooded. Enforced on **every** renew creation path (scheduler sweep, manual job, bulk renew): the sweep skips over-cap certificates and retries them next tick, while manual and bulk creation fail with `409 CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED`. | `5` | API + Worker |
| `CERTOPS_JOB_LEASE_SECONDS` | How long an agent's claim on a job stays valid before it must be renewed. Raise this if legitimate renewals routinely take longer. | `900` | API |
| `CERTOPS_LEASE_HARD_GRACE_MS` | Extra time a still-heartbeating agent gets before its expired-lease job is judged. | `3600000` (1 hour) | API + Worker |
| `CERTOPS_AGENT_REQUIRE_SIGNED_AGENT_ID` | Agent-side flag governing only the compatibility decoder's tolerance for a signed job whose `agentId` is **missing** entirely (ADR-0012 decision 3). It has zero effect on a job whose `agentId` is present but does not match this agent's own id: a mismatch always fails closed, regardless of this flag's value, and is logged/counted as a distinct mismatch-observability event an operator can alert on (never conflated with the generic "signature verification failed" log line). It also has zero effect on the control-plane producer schema, which requires `agentId` unconditionally as of the same change that adds server-side emission. When `false`, the decoder tolerates absence and proceeds (needed while talking to a control plane that has not yet started emitting `agentId`); when `true`, absence also fails closed, with a distinct incompatibility error rather than a generic verification failure. The `agent-id-binding-v1` capability is advertised only from this flag's effective runtime value, never from its compiled-in default. Operator action: flip to `true` only after confirming every control plane this agent talks to has finished emitting `agentId` on every signed dispatch; flipping early turns every dispatch from a not-yet-upgraded control plane into a hard failure. **Sunset:** this flag and the absence-tolerant decoder branch it gates are a temporary rollout bridge, not a permanent option. The compiled-in default is expected to flip to `true` once step 1 of the rollout (server-side `agentId` emission) has shipped and been confirmed fleet-wide (targets 0.12.0); the flag and the absence-tolerant branch are expected to be removed entirely at least one release after that (0.14.0 or later), once no fleet still needs the override back to `false`. | `false` | Agent |

### CertOps maintenance sweeps (worker)

The `certops` worker target runs six independent sweeps. Each has an enable
flag (default enabled) and a per-sweep timeout (default `120000` ms,
`DEFAULT_SWEEP_TIMEOUT_MS`). Disabling a sweep is an operational escape hatch,
not a normal configuration.

How it is scheduled depends on the deployment:

| Deployment | Unit | Schedule set by |
|---|---|---|
| Compose | service `worker-certops` (cron runner) | `WORKER_CERTOPS_CRON`, default `*/1 * * * *` |
| Kubernetes | `cronjob-certops` (one-shot `node apps/worker/src/certops-worker.js`) | `worker.cronjobs.certops.schedule` in Helm values, default `*/1 * * * *` |

`WORKER_CERTOPS_CRON` has no effect in Kubernetes: the CronJob invokes the
one-shot entrypoint directly, not the cron-scheduling runner, so the Kubernetes
schedule is the CronJob's own `schedule` field. Set
`worker.cronjobs.certops.enabled=false` to turn the sweeps off there.

| Sweep | Enable | Timeout | What it does |
| ----- | ------ | ------- | ------------ |
| Lease reaper | `CERTOPS_SWEEP_LEASE_REAPER_ENABLED` | `CERTOPS_SWEEP_LEASE_REAPER_TIMEOUT_MS` | Requeues or flags jobs whose lease expired |
| Stale agents | `CERTOPS_SWEEP_STALE_AGENTS_ENABLED` | `CERTOPS_SWEEP_STALE_AGENTS_TIMEOUT_MS` | Persists `status='offline'` for agents past `CERTOPS_AGENT_OFFLINE_AFTER_MS` |
| Nonce cache | `CERTOPS_SWEEP_NONCE_ENABLED` | `CERTOPS_SWEEP_NONCE_TIMEOUT_MS` | Expires consumed job nonces |
| Registration replay | `CERTOPS_SWEEP_REGISTRATION_REPLAY_ENABLED` | `CERTOPS_SWEEP_REGISTRATION_REPLAY_TIMEOUT_MS` | Expires registration-replay credential rows |
| Renewal scheduler | `CERTOPS_SWEEP_RENEWAL_SCHEDULER_ENABLED` | `CERTOPS_SWEEP_RENEWAL_SCHEDULER_TIMEOUT_MS` | Creates renewal jobs for certificates near expiry |
| Outbox drain | `CERTOPS_SWEEP_OUTBOX_DRAIN_ENABLED` | `CERTOPS_SWEEP_OUTBOX_DRAIN_TIMEOUT_MS` | Delivers recorded CertOps side effects from `certops_outbox`: resolves alert contacts and queues `cert_renewal_failed`, with backoff under an owner-scoped lease |

**The outbox drain is not optional if you rely on renewal-failure alerts.** A
terminal renewal failure records its *intent* to alert in `certops_outbox` inside
the same transaction that decided the failure, and this sweep is what turns that
intent into a queued alert. With the sweep disabled or the worker not deployed,
intents accumulate as `pending` rather than being lost, so nothing is
unrecoverable, but **no renewal-failure notification is delivered** in the
meantime. See `docs/adr/0009-certops-durable-side-effects-and-alert-policy.md`.

`CERTOPS_ENABLED` must be set for the worker too, not just the API. If the
worker's value is out of sync, the renewal scheduler treats every workspace
as ineligible and counts each certificate as "skipped, paused" without
logging an error, so **nothing renews automatically** while the API and
dashboard look healthy. See `docs/certops/agent.md` for the liveness/sweep
interaction.

**Deployment defaults differ from the app-level default above.** The Helm chart (`config.certopsEnabled`, see `deploy/helm/values.yaml`) and the Docker Compose files (`CERTOPS_ENABLED:-true` in `deploy/compose/docker-compose.yml` / `docker-compose.dev.yml`) both set `CERTOPS_ENABLED=true` unless explicitly overridden, so CertOps is **enabled by default** for Helm and Compose deployments. Set `config.certopsEnabled: false` (Helm) or `CERTOPS_ENABLED=false` (Compose `.env`) to opt out.

TokenTimer stores only public certificate material (fingerprints, serials, issuers, subjects, SANs, validity, chains) and external key references. Requests containing private key material are rejected with HTTP 422. Agent registration-replay credentials are stored only as an encrypted envelope (see `docs/certops/agent.md`).

## Metrics and observability

| Variable             | Description                                                | Default value | Scope          |
| -------------------- | ---------------------------------------------------------- | ------------- | -------------- |
| `ENABLE_METRICS`     | Enable `/metrics` and metric push attempts when `true`     | `false`       | API, worker    |
| `PUSHGATEWAY_URL`    | Prometheus Pushgateway endpoint                            | `unset`       | Worker metrics |
| `ENVIRONMENT_SUFFIX` | Metrics environment label (if you have multiple instances) | `unset`       | Worker metrics |

## WhatsApp (Twilio)

| Variable                                               | Description                                        | Default value | Scope               |
| ------------------------------------------------------ | -------------------------------------------------- | ------------- | ------------------- |
| `TWILIO_ACCOUNT_SID`                                   | Twilio account SID                                 | `unset`       | WhatsApp            |
| `TWILIO_AUTH_TOKEN`                                    | Twilio auth token                                  | `unset`       | WhatsApp            |
| `TWILIO_WHATSAPP_FROM`                                 | WhatsApp sender (E.164)                            | `unset`       | WhatsApp            |
| `TWILIO_WHATSAPP_ALERT_CONTENT_SID_EXPIRES`            | Content template SID for expiring alerts           | `unset`       | WhatsApp            |
| `TWILIO_WHATSAPP_ALERT_CONTENT_SID_EXPIRED`            | Content template SID for expired alerts            | `unset`       | WhatsApp            |
| `TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_DOWN`      | Content template SID for endpoint down alerts      | `unset`       | WhatsApp            |
| `TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_RECOVERED` | Content template SID for endpoint recovered alerts | `unset`       | WhatsApp            |
| `TWILIO_WHATSAPP_WEEKLY_DIGEST_CONTENT_SID`            | Content template SID for weekly digest             | `unset`       | WhatsApp            |
| `TWILIO_WHATSAPP_TEST_CONTENT_SID`                     | Content template SID for test messages             | `unset`       | WhatsApp            |
| `WHATSAPP_RATE_PER_MIN`                                | Outbound WhatsApp message rate cap                 | `unset`       | WhatsApp throttling |
| `WHATSAPP_DRY_RUN`                                     | Log messages without sending when `true`           | `false`       | WhatsApp testing    |

### Admin Setup: Twilio WhatsApp

Use this flow when an admin wants to enable WhatsApp notifications, expiry templates, weekly digest, and endpoint alert templates.

#### 1. Configure Twilio credentials in System Settings

As an admin, open `System Settings` -> `WhatsApp (Twilio)` and fill:

- `Account SID`
- `Auth Token`
- `WhatsApp From Number`

Optional template SIDs that can already be configured in the UI:

- `Alert (Expires) Template SID`
- `Alert (Expired) Template SID`
- `Test Message Template SID`
- `Weekly Digest Template SID`

#### 2. Configure endpoint alert template SIDs at deployment level

Endpoint down and endpoint recovered WhatsApp alerts use dedicated deployment variables:

- `TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_DOWN`
- `TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_RECOVERED`

Set them in your deployment method:

- local compose: `deploy/compose/.env`
- Helm: `deploy/helm/values.yaml`
- Kubernetes manifests or secret/config injection in your runtime environment

After changing these values, restart the delivery worker so it picks up the new template SIDs.

#### 3. Create Twilio content templates

Create 2 approved Twilio WhatsApp templates with these exact variable names.

**Endpoint down template:**

```text
Hello {{recipient_name}},

TokenTimer detected that endpoint {{endpoint_name}} is DOWN.
URL: {{endpoint_url}}
Linked token: {{token_name}}
Detected at: {{detected_at}}
```

**Endpoint recovered template:**

```text
Hello {{recipient_name}},

TokenTimer detected that endpoint {{endpoint_name}} has RECOVERED.
URL: {{endpoint_url}}
Linked token: {{token_name}}
Detected at: {{detected_at}}
```

Variables sent by TokenTimer for endpoint WhatsApp alerts:

- `recipient_name`
- `endpoint_name`
- `endpoint_url`
- `token_name`
- `detected_at`

#### 4. Verification checklist

- Use `Send test WhatsApp` in `System Settings` to verify base Twilio credentials and sender configuration.
- Trigger an endpoint outage and confirm the delivery log shows channel `whatsapp`.
- Confirm the delivery metadata records:
  - `template_kind = endpoint_down` for outage alerts
  - `template_kind = endpoint_recovered` for recovery alerts

## Legacy and compatibility

| Variable            | Description                                                                 | Default value | Scope                   |
| ------------------- | --------------------------------------------------------------------------- | ------------- | ----------------------- |
| `PLAN_API_LIMITS`   | API limiter plan map override (parsed as `plan:value`, fallback `oss:6000`) | `unset`       | API middleware          |
| `RATE_LIMIT_WINDOW` | Config package generic rate-limit window (ms)                               | `60000`       | Shared config consumers |
| `RATE_LIMIT_MAX`    | Config package generic rate-limit max requests                              | `100`         | Shared config consumers |

## Test, CI, and local orchestration

| Variable                    | Description                               | Default value           | Scope              |
| --------------------------- | ----------------------------------------- | ----------------------- | ------------------ |
| `CI`                        | Standard CI marker                        | `unset`                 | CI pipelines       |
| `CONTRACT_API_REQUIRED`     | Fail contract tests if API is unavailable | `unset`                 | Contract tests     |
| `TEST_API_URL`              | Integration test API endpoint             | `http://localhost:4000` | Integration tests  |
| `TEST_MODE`                 | Test behavior switch                      | `unset`                 | Tests              |
| `NODE_V8_COVERAGE`          | V8 coverage output path                   | `unset`                 | Coverage           |
| `TT_ALLOW_FORCE_INSTALL`    | Permit force install in test bootstrap    | `unset`                 | Tests              |
| `TT_AUTO_INSTALL_TEST_DEPS` | Auto install missing test deps            | `unset`                 | Tests              |
| `TT_FORCE_INSTALL`          | Force dependency install in tests         | `unset`                 | Tests              |
| `TT_IMAGE_TAG`              | Docker image tag for tests                | `unset`                 | Test orchestration |
| `TT_SKIP_COMPOSE_BUILD`     | Skip docker compose build step            | `unset`                 | Test orchestration |
| `TT_TEST_API_PORT`          | API port used by test compose             | `4000`                  | Test compose       |
| `TT_TEST_DB_PORT`           | DB port used by test compose              | `5432`                  | Test compose       |
| `TT_TEST_MAILHOG_SMTP_PORT` | MailHog SMTP port in tests                | `1025`                  | Test compose       |
| `TT_TEST_MAILHOG_UI_PORT`   | MailHog UI port in tests                  | `8025`                  | Test compose       |
| `TT_TEST_SUITE`             | Select subset of test suites              | `unset`                 | Test selection     |
