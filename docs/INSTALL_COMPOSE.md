# Install Core with Docker Compose

## Choose the VM topology

Use the standard Compose installation for your edition when deploying on one VM. Core operators can start with [Clone and configure](#step-1---clone-and-configure).

- **Your hypervisor can restart the VM after host failure.** Install on one VM, allow for downtime while it restarts, then [rehearse recovery](#recover-a-single-vm-after-host-failure).
- **You need service to continue when an application VM fails.** Use the [Enterprise Compose guide](https://tokentimer.ch/docs/enterprise/install-compose) with a bundle containing the two-VM overlay. Provide a redundant load balancer, an HA PostgreSQL writer endpoint, and a cluster manager that fences the old worker host before starting workers on its peer. During takeover, verify that an existing session can save a record and that exactly one worker set is active.
- **Some or all HA dependencies are missing.** Install on one VM and [test a backup restore](#test-recovery-from-backup). If the measured downtime or data loss exceeds your requirements, identify and test the missing infrastructure before relying on automatic failover.

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

# Production API startup requires both keys when CertOps is enabled (the default).
# Generate each separately with openssl rand -hex 32 and keep them with your backups.
CERTOPS_SIGNING_ENCRYPTION_KEY=replace_with_first_generated_key
CERTOPS_REGISTRATION_ENCRYPTION_KEY=replace_with_second_generated_key
# To run without CertOps, set CERTOPS_ENABLED=false and omit both keys.
```

Optional but common additions: SMTP sender identity (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `FROM_EMAIL`, `FROM_EMAIL_NAME`) and host port remaps (`API_PORT`, `DASHBOARD_PORT`; keep `APP_URL`/`API_URL` in sync if you remap).

> **Warning**
>
> If you run locally on `http://localhost` with `NODE_ENV=production`, authentication can fail because secure session cookies are not persisted or sent by the browser on plain local HTTP. Put HTTPS in front of the API and dashboard (reverse proxy with TLS), or use `NODE_ENV=development` for local non-TLS testing. As a last-resort local troubleshooting option only, set `SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE=true`.

> **Note**
>
> Compose defaults to `TRUST_PROXY_HOPS=0` for direct access. Behind a reverse proxy or load balancer, set the actual trusted hop count, restrict direct API access, and ensure proxies sanitize forwarding headers.

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

## Recover a single VM after host failure

Configure the hypervisor to restart the same VM on a surviving host with access to its disks, including the PostgreSQL volume. Preserve its network identity and public URL, and enable Docker at boot. During a host-loss rehearsal, time the interruption until you can sign in through that URL, open an existing asset and save a test change. If you use CertOps, check for a fresh agent heartbeat. If the VM or its disks cannot be recovered, use the backup procedure below.

## Test recovery from backup

During the rehearsal, save timestamped test records at regular intervals until the simulated failure. Follow the Compose restore procedure for your edition ([Core recovery steps](BACKUP_RESTORE.md#restore)) on an isolated VM with an empty database, matching software versions, configuration and keys. Record the time from the simulated failure until you can sign in through the test URL, read a restored asset and save a test change. Compare the latest restored timestamped test record with the time of failure to measure the data gap. If you use CertOps, verify a lab agent can reach the restored instance.

## Private-CA Vault connections

The API forwards `NODE_EXTRA_CA_CERTS`, but the referenced PEM CA file must also
be mounted in its container. Use your own Compose override, for example:

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
distribution agents configure Vault trust independently on their hosts.
The production Compose file requires an explicit non-empty `DB_PASSWORD`.
