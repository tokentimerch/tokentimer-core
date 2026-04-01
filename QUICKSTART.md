# TokenTimer Core - Quick Start Guide

Get TokenTimer Core running in under 5 minutes.

> [!TIP]
> **Reference docs:** [Full configuration variables](docs/CONFIGURATION.md) &bull; [Auth model & RBAC](docs/AUTHENTICATION.md) &bull; [Helm chart options](deploy/helm/README.md) &bull; [Helm values file](deploy/helm/values.yaml) &bull; [Compose .env example](deploy/compose/.env.example)

## Prerequisites

- Docker and Docker Compose
- Or Node.js >= 22.0.0 + PostgreSQL 14+
- pnpm (recommended package manager for this monorepo)

## Option 1: Docker Compose (Fastest)

### 1. Clone and Configure

```bash
cd tokentimer-core/deploy/compose
cp .env.example .env
```

### 2. Edit .env

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
APP_URL=http://localhost:5173
API_URL=http://localhost:4000

# Optional host port remap for Docker Compose only.
# Change these only if ports 4000/5173 are already used on your host.
# If you remap, keep APP_URL/API_URL in sync with the new host ports.
# API_PORT=4000
# DASHBOARD_PORT=5173

# Optional but common: SMTP sender identity
# SMTP_HOST=smtp.example.com
# SMTP_PORT=465
# SMTP_USER=noreply@example.com
# SMTP_PASS=your_smtp_password
# FROM_EMAIL=noreply@example.com
# FROM_EMAIL_NAME=TokenTimer
```

> [!WARNING]
> If you run locally on `http://localhost` with `NODE_ENV=production`, authentication can fail because secure session cookies are not persisted/sent by the browser on local HTTP.
> Put HTTPS in front of API/dashboard (reverse proxy with TLS), or use `NODE_ENV=development` for local non-TLS testing.
> As a last-resort local troubleshooting option only, set `SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE=true`.

### 3. Start All Services

```bash
# A) Build from local source (default)
docker compose up -d

# B) Use prebuilt images (Pattern A override file)
# Optional vars in .env: TT_IMAGE_REGISTRY, TT_IMAGE_OWNER, TT_IMAGE_TAG
docker compose -f docker-compose.yml -f docker-compose.images.yml up -d
```

### 4. Access the Dashboard

Open `http://localhost:5173` in your browser.

### 5. Check Status

```bash
# View logs
docker compose logs -f

# Check health
curl http://localhost:4000/health

# View running services
docker compose ps
```

## Option 2: Local Development

### 1. Install Dependencies

```bash
cd tokentimer-core
pnpm install
```

### 2. Start PostgreSQL

```bash
# Using Docker
docker run -d --name tokentimer-pg \
  -p 5432:5432 \
  -e POSTGRES_USER=tokentimer \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=tokentimer \
  postgres:17
```

### 3. Configure Environment

Create `.env` in the root directory:

```bash
NODE_ENV=development
SESSION_SECRET=dev_session_secret_change_in_production

DB_HOST=localhost
DB_PORT=5432
DB_NAME=tokentimer
DB_USER=tokentimer
DB_PASSWORD=password

ADMIN_EMAIL=admin@localhost.local
ADMIN_PASSWORD=AdminPassword123!
ADMIN_NAME=Administrator

APP_URL=http://localhost:5173
API_URL=http://localhost:4000
```

### 4. Run Migrations

```bash
pnpm run migrate
```

### 5. Start Development Servers

```bash
pnpm run dev
```

This starts:

- API on `http://localhost:4000`
- Worker (background process)
- Dashboard on `http://localhost:5173`

### 6. Access the Dashboard

Open `http://localhost:5173` in your browser.

## Option 3: Kubernetes (Helm)

> [!NOTE]
> All configurable values are documented in [`deploy/helm/values.yaml`](deploy/helm/values.yaml). For a full environment variable reference, see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

### 1. Install the Helm Chart

**Option A — from OCI registry (recommended)**

```bash
helm install tokentimer oci://ghcr.io/tokentimerch/charts/tokentimer \
  --namespace tokentimer --create-namespace \
  --set config.adminEmail="admin@your-company.com" \
  --set config.adminPassword="SecurePassword123!" \
  --set config.sessionSecret="replace-with-long-random-value" \
  --set postgresql.auth.password="your-db-password" \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host="tokentimer.your-domain.com"
```

**Option B — from local source**

```bash
cd deploy/helm

helm install tokentimer . \
  --namespace tokentimer --create-namespace \
  --set config.adminEmail="admin@your-company.com" \
  --set config.adminPassword="SecurePassword123!" \
  --set config.sessionSecret="replace-with-long-random-value" \
  --set postgresql.auth.password="your-db-password" \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host="tokentimer.your-domain.com"
```

**Option C — with a values file (recommended for production)**

Use the chart defaults as a starting point:

```bash
# Copy and edit the values file
cp deploy/helm/values.yaml my-values.yaml
# See deploy/helm/values.yaml for all options
# See docs/CONFIGURATION.md for the full env variable reference

helm install tokentimer oci://ghcr.io/tokentimerch/charts/tokentimer \
  --namespace tokentimer --create-namespace \
  -f my-values.yaml
```

### 2. Wait for Pods

```bash
kubectl get pods -n tokentimer -w
```

### 3. Access Dashboard

```bash
# If using ingress
open https://tokentimer.your-domain.com

# Or port-forward
kubectl port-forward svc/tokentimer-dashboard 3000:80 -n tokentimer
open http://localhost:3000
```

## First Steps After Installation

### 1. Login as Admin

**Important**: TokenTimer creates the admin user automatically on first startup using the `ADMIN_EMAIL` and `ADMIN_PASSWORD` you configured.

1. Navigate to http://localhost:5173/login
2. Login with:
   - Email: Your `ADMIN_EMAIL`
   - Password: Your `ADMIN_PASSWORD`
3. You'll see your default admin workspace

**Security**: After first login, remove `ADMIN_PASSWORD` from your `.env` file!

### 2. Invite Team Members (Optional)

1. Go to Workspace Settings → Members
2. Click "Invite User"
3. Enter email and select role (Admin, Manager, or Viewer)
4. Share the invitation URL with the user
5. They set their password and join automatically

### 3. Add Your First Token

1. Go to Dashboard
2. Click "Add Token"
3. Fill in:
   - Name (e.g., "AWS Access Key")
   - Type (e.g., "API Key")
   - Expiration Date
   - Category (optional)
4. Click "Save"

### 4. Configure Alerts

1. Go to Workspace Settings
2. Click "Alert Preferences"
3. Configure:
   - Alert thresholds (days before expiry: 30, 14, 7, 1, 0)
   - Email notifications (enabled by default)
   - Webhook URLs (optional)
4. Add contacts to receive alerts
5. Save settings

### 5. Test Alerts

The worker runs every 5 minutes and will:

- Scan tokens for upcoming expirations
- Queue alerts based on thresholds
- Send notifications via configured channels

To test immediately, check the `alert_queue` table:

```sql
SELECT * FROM alert_queue ORDER BY queued_at DESC LIMIT 10;
```

## Troubleshooting

### API won't start

**Check database connection:**

```bash
# Test PostgreSQL
psql postgresql://tokentimer:password@localhost:5432/tokentimer

# Check logs
docker compose logs api
```

### Worker not sending alerts

**Check worker logs:**

```bash
docker compose logs worker-discovery worker-delivery worker-weekly-digest worker-auto-sync worker-endpoint-check
```

**Verify SMTP configuration:**

```bash
# SMTP check command is deployment-specific. Verify values first:
docker compose exec api env | grep -E "SMTP_|FROM_EMAIL"
```

**Check alert queue:**

```sql
SELECT * FROM alert_queue WHERE status = 'pending' LIMIT 10;
```

### Dashboard shows errors

**Check browser console** for JavaScript errors

**Verify API connectivity:**

```bash
curl http://localhost:4000/health
```

### Login returns 401 on localhost in production mode

If `NODE_ENV=production` and your local URLs are `http://localhost`, the API uses secure cookies for sessions and the browser may not send/persist them on local HTTP.

Fix options:

1. Put HTTPS in front of API and dashboard (reverse proxy with TLS).
2. For local non-TLS testing only, switch to `NODE_ENV=development`.
3. As a last resort for local troubleshooting only, set `SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE=true`.

## Configuration Reference

### Minimum required variables (Docker Compose)

```bash
SESSION_SECRET=long-random-string        # required — long random value
DB_PASSWORD=secure-db-password           # required
ADMIN_EMAIL=admin@your-company.com       # required — bootstraps the admin account
ADMIN_PASSWORD=secure-admin-password     # required on first start; remove afterwards
APP_URL=http://localhost:5173
API_URL=http://localhost:4000
```

For every available variable (SMTP, Slack, integrations, worker tuning, security overrides), see:

- **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** — full environment variable reference
- **[deploy/compose/.env.example](deploy/compose/.env.example)** — annotated Compose template
- **[deploy/helm/values.yaml](deploy/helm/values.yaml)** — all Helm chart knobs

## Health Checks

### API Health

```bash
curl http://localhost:4000/health
```

Expected response:

```json
{
  "status": "healthy",
  "timestamp": "2026-03-19T12:00:00.000Z",
  "uptime": 123.456,
  "memory": { "rss": 52428800 },
  "environment": "production"
}
```

### Database Health

```bash
docker compose exec postgres pg_isready
```

## Backup and Restore

### Backup Database

```bash
docker compose exec postgres pg_dump -U tokentimer tokentimer > backup.sql
```

### Restore Database

```bash
docker compose exec -T postgres psql -U tokentimer tokentimer < backup.sql
```

## Upgrading

### Docker Compose

```bash
# Pull latest images
docker compose pull

# Restart services
docker compose up -d

# Verify health
curl http://localhost:4000/health
```

### Kubernetes

```bash
# Update to new version
helm upgrade tokentimer ./deploy/helm -n tokentimer

# Monitor rollout
kubectl rollout status deployment/tokentimer-api
```

## Uninstalling

### Docker Compose

```bash
cd deploy/compose

# Stop and remove containers (keeps data)
docker compose down

# Stop and remove everything including volumes
docker compose down -v
```

### Kubernetes

```bash
helm uninstall tokentimer
```

## Getting Help

- **Configuration**: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
- **Authentication**: [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md)
- **Helm chart**: [deploy/helm/README.md](deploy/helm/README.md)
- **Issues**: [GitHub Issues](https://github.com/tokentimerch/tokentimer-core/issues)
- **Support**: support@tokentimer.ch

## Next Steps

After getting TokenTimer running:

1. **Configure SMTP** for email alerts (via System Settings UI or env vars)
2. **Add your tokens** (API keys, certificates, secrets)
3. **Set up alert thresholds** for your workflow
4. **Add team members** to workspaces
5. **Integrate with CI/CD** via API

---

**TokenTimer Core** - Never let a secret expire again.
