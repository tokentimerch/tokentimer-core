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

> [!WARNING]
> In local `http://localhost` with `NODE_ENV=production`, browser does not persist/send the secure session cookie for auth flow.
> Use HTTPS in front of API and dashboard (reverse proxy with TLS), otherwise secure cookies are expected to fail in local HTTP.

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

| Variable                     | Description                          | Default value                          | Scope        |
| ---------------------------- | ------------------------------------ | -------------------------------------- | ------------ |
| `LOCAL_AUTH_ENABLED`         | Enable local email/password auth     | `true`                                 | API auth     |
| `REQUIRE_EMAIL_VERIFICATION` | Require verified email before access | `true`                                 | API auth     |
| `TWO_FACTOR_ENABLED`         | Enable 2FA features                  | `true`                                 | API auth     |
| `SESSION_MAX_AGE`            | Session max age in ms                | `86400000`                             | API auth     |
| `SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE` | Allow insecure session cookie only for local non-TLS production troubleshooting | `false` | API auth |
| `CSRF_ENABLED`               | Enable CSRF protection               | `true`                                 | API security |
| `MIN_PASSWORD_LENGTH`        | Minimum password length              | `8`                                    | API auth     |
| `REQUIRE_UPPERCASE`          | Enforce uppercase in passwords       | `true`                                 | API auth     |
| `REQUIRE_NUMBERS`            | Enforce numeric chars in passwords   | `true`                                 | API auth     |
| `PHONE_HASH_SALT`            | Optional salt for phone hashing      | `unset`                                | API privacy  |
| `WORKER_API_KEY`             | Worker-to-API auth key               | `unset (falls back to SESSION_SECRET)` | Worker, API  |

## Email and delivery

| Variable                   | Description                               | Default value                                             | Scope             |
| -------------------------- | ----------------------------------------- | --------------------------------------------------------- | ----------------- |
| `SMTP_HOST`                | SMTP host(s) (comma-separated)            | `localhost` in config helper, `unset` in compose examples | API, worker email |
| `SMTP_PORT`                | SMTP port(s) (comma-separated)            | `587` in config helper                                    | API, worker email |
| `SMTP_USER`                | SMTP username(s) (comma-separated)        | `unset`                                                   | API, worker email |
| `SMTP_PASS`                | SMTP password(s) (comma-separated)        | `unset`                                                   | API, worker email |
| `FROM_EMAIL`               | Sender email override                     | `unset`                                                   | API, worker email |
| `FROM_EMAIL_NAME`          | Sender display name                       | `TokenTimer`                                              | API, worker email |
| `SMTP_SECURE`              | Force SMTPS/SSL                           | `false`                                                   | API, worker email |
| `SMTP_REQUIRE_TLS`         | Require STARTTLS upgrade                  | `true`                                                    | API, worker email |
| `SMTP_REJECT_UNAUTHORIZED` | Reject invalid TLS certs                  | `unset`                                                   | API, worker email |

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
| `WEBHOOK_PROVIDER_HOSTS`                  | Extra allowed provider hosts                                                | `empty (built-in list still allowed)` | Webhook security     |
| `WEBHOOK_EXTRA_PROVIDER_HOSTS`            | Additional allowed hosts                                                    | `empty`                               | Webhook security     |
| `VAULT_ADDRESS_ALLOWLIST`                 | Vault integration host allowlist                                            | `empty (no host restriction)`         | Integration security |
| `AZURE_VAULT_ADDRESS_ALLOWLIST`           | Azure Key Vault host allowlist                                              | `empty (no host restriction)`         | Integration security |
| `GITHUB_ADDRESS_ALLOWLIST`                | GitHub host allowlist                                                       | `empty (no host restriction)`         | Integration security |
| `GITLAB_ADDRESS_ALLOWLIST`                | GitLab host allowlist                                                       | `empty (no host restriction)`         | Integration security |
| `INTEGRATION_SCAN_LIMITS`                 | JSON plan-to-limit map (core defaults unlimited)                            | `{"oss":Infinity}`                    | Integration quotas   |
| `CONTACT_GROUP_LIMITS`                    | JSON plan-to-limit map (core defaults unlimited)                            | `{"oss":Infinity}`                    | Contact groups       |
| `CONTACT_GROUP_MEMBER_LIMITS`             | JSON plan-to-limit map (core defaults unlimited)                            | `{"oss":Infinity}`                    | Contact groups       |
| `WORKSPACE_PLAN_LIMITS`                   | JSON plan-to-limit map (core defaults unlimited)                            | `{"oss":Infinity}`                    | Workspaces           |
| `MEMBER_PLAN_LIMITS`                      | JSON plan-to-limit map (core defaults unlimited)                            | `{"oss":Infinity}`                    | Workspace members    |

## Metrics and observability

| Variable             | Description                                                | Default value | Scope          |
| -------------------- | ---------------------------------------------------------- | ------------- | -------------- |
| `ENABLE_METRICS`     | Enable `/metrics` and metric push attempts when `true`     | `false`       | API, worker    |
| `PUSHGATEWAY_URL`    | Prometheus Pushgateway endpoint                            | `unset`       | Worker metrics |
| `ENVIRONMENT_SUFFIX` | Metrics environment label (if you have multiple instances) | `unset`       | Worker metrics |

## WhatsApp (Twilio)

| Variable                                    | Description                              | Default value | Scope               |
| ------------------------------------------- | ---------------------------------------- | ------------- | ------------------- |
| `TWILIO_ACCOUNT_SID`                        | Twilio account SID                       | `unset`       | WhatsApp            |
| `TWILIO_AUTH_TOKEN`                         | Twilio auth token                        | `unset`       | WhatsApp            |
| `TWILIO_WHATSAPP_FROM`                      | WhatsApp sender (E.164)                  | `unset`       | WhatsApp            |
| `TWILIO_WHATSAPP_ALERT_CONTENT_SID_EXPIRES` | Content template SID for expiring alerts | `unset`       | WhatsApp            |
| `TWILIO_WHATSAPP_ALERT_CONTENT_SID_EXPIRED` | Content template SID for expired alerts  | `unset`       | WhatsApp            |
| `TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_DOWN` | Content template SID for endpoint down alerts | `unset` | WhatsApp |
| `TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_RECOVERED` | Content template SID for endpoint recovered alerts | `unset` | WhatsApp |
| `TWILIO_WHATSAPP_WEEKLY_DIGEST_CONTENT_SID` | Content template SID for weekly digest   | `unset`       | WhatsApp            |
| `TWILIO_WHATSAPP_TEST_CONTENT_SID`          | Content template SID for test messages   | `unset`       | WhatsApp            |
| `WHATSAPP_RATE_PER_MIN`                     | Outbound WhatsApp message rate cap       | `unset`       | WhatsApp throttling |
| `WHATSAPP_DRY_RUN`                          | Log messages without sending when `true` | `false`       | WhatsApp testing    |

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
