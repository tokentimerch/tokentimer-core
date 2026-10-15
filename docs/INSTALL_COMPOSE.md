# Install Core with Docker Compose

## Step 1 - Clone and configure

Install Git as well as Docker and Docker Compose. The commands below use Bash; on Windows, run them in Git Bash.

```bash
git clone https://github.com/tokentimerch/tokentimer-core.git
cd tokentimer-core/deploy/compose
cp .env.example .env
```

## Step 2 - Edit `.env`

Minimal required configuration (production-safe baseline):

```bash
# Core runtime
NODE_ENV=production
SESSION_SECRET=replace_with_a_long_random_value

# Database
DB_HOST=postgres
DB_PORT=5432
DB_NAME=tokentimer
DB_USER=tokentimer
DB_PASSWORD=replace_with_secure_password

# Initial admin bootstrap (first start only)
ADMIN_EMAIL=admin@your-company.com
ADMIN_PASSWORD=ChangeThisSecurePassword123!
ADMIN_NAME=Administrator

# Public URLs (what users/browsers should use)
APP_URL=https://tokentimer.example.com
API_URL=https://tokentimer.example.com

# Required only if you plan to connect a CertOps agent. Compose enables CertOps
# by default (CERTOPS_ENABLED:-true); without these two keys the CertOps UI
# appears but agent registration and job dispatch fail closed.
# Generate each with: openssl rand -hex 32
# CERTOPS_SIGNING_ENCRYPTION_KEY=
# CERTOPS_REGISTRATION_ENCRYPTION_KEY=
# Or set CERTOPS_ENABLED=false if you do not use CertOps at all.
```

Optional but common additions: SMTP sender identity (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `FROM_EMAIL`, `FROM_EMAIL_NAME`) and host port remaps (`API_PORT`, `DASHBOARD_PORT`; keep `APP_URL`/`API_URL` in sync if you remap).

> **Warning**
>
> If you run locally on `http://localhost` with `NODE_ENV=production`, authentication can fail because secure session cookies are not persisted or sent by the browser on plain local HTTP. Put HTTPS in front of the API and dashboard (reverse proxy with TLS), or use `NODE_ENV=development` for local non-TLS testing. As a last-resort local troubleshooting option only, set `SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE=true`.

> **Note**
>
> If the API sits behind a reverse proxy or load balancer, set `TRUST_PROXY_HOPS` to the number of proxy hops (the Compose default is 2, covering LB plus reverse proxy; set 0 when nothing is in front).

<a id="compose-start"></a>

## Step 3 - Start all services

Use the released images for deployment. Select a published release tag and use the same tag for every Core service. The override still inherits build definitions, so `--no-build` makes this choice explicit.

```bash
read -r -p 'Core release tag: ' TT_IMAGE_TAG
export TT_IMAGE_TAG
docker compose -f docker-compose.yml -f docker-compose.images.yml pull
docker compose -f docker-compose.yml -f docker-compose.images.yml up -d --no-build
```

For source builds and local development, follow [DEVELOPMENT.md](https://github.com/tokentimerch/tokentimer-core/blob/main/DEVELOPMENT.md).


The Compose stack starts PostgreSQL, runs database migrations as a one-shot `migrations` service, then starts the API, the dashboard, and the six worker containers (`worker-discovery`, `worker-delivery`, `worker-weekly-digest`, `worker-auto-sync`, `worker-endpoint-check`, `worker-certops`).

## Step 4 - Verify

```bash
# View logs
docker compose logs -f

# Check health
curl http://localhost:4000/health

# View running services
docker compose ps
```

**You should see:** the API, dashboard, database, and worker containers running (API and dashboard with healthy healthchecks). The one-shot `migrations` service should have exited with code `0`; it does not stay `Up`. The health endpoint should respond with:

```json
{
  "status": "healthy",
  "timestamp": "2026-03-19T12:00:00.000Z",
  "uptime": 123.456,
  "environment": "production"
}
```

Open the dashboard at your configured `APP_URL`. The health command above checks the local API port; it does not test the reverse proxy or email delivery.

<a id="first-login"></a>

## First login

TokenTimer creates the admin user automatically on first startup from `ADMIN_EMAIL` and `ADMIN_PASSWORD`.

1. Navigate to your dashboard URL and open the login page.
2. Log in with your configured `ADMIN_EMAIL` and `ADMIN_PASSWORD`.
3. **You should see** your default admin workspace.

> **Warning**
>
> After first login, remove `ADMIN_PASSWORD` from your `.env` file (or values). It is only needed for the bootstrap on first start.

Recommended next steps: invite team members (Workspace Settings, Members), add your first [token](https://tokentimer.ch/docs/self-hosted/tokens), configure alert thresholds and channels in [Expiry reminders and thresholds](https://tokentimer.ch/docs/self-hosted/alerts), and configure SMTP (via System Settings UI or [env vars](CONFIGURATION.md)).

Continue with [First asset and alert check](FIRST_ASSET.md). For settings and restarts, see [Configuration basics](CONFIGURATION_BASICS.md).

## Private-CA Vault connections

The API forwards `NODE_EXTRA_CA_CERTS`, but the referenced PEM CA file must also
be mounted in its container. Use a customer Compose override, for example:

```yaml
services:
  api:
    environment:
      NODE_EXTRA_CA_CERTS: /etc/tokentimer/ca/vault-ca.pem
    volumes:
      - ./vault-ca.pem:/etc/tokentimer/ca/vault-ca.pem:ro
```

Run Compose with the main file and this override. Use only the public CA
certificate, keep TLS verification enabled, and verify the mount exists before
starting the API. This is the server inventory scanner's trust configuration;
customer distribution agents configure Vault trust independently on their hosts.
The production Compose file requires an explicit non-empty `DB_PASSWORD`.
