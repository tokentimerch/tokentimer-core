# TokenTimer Core - Local Development

## Quick Start

Run these commands from the repository root. They work in Windows PowerShell,
Git Bash, WSL, Linux, and macOS.

```bash
pnpm install
pnpm run migrate
pnpm run dev
```

`pnpm run dev` starts:

- API on http://localhost:4000
- Dashboard on http://localhost:5173
- Worker runner for discovery, delivery, auto-sync, endpoint checks, and weekly digest scheduling

The worker runner uses the same cron schedules as the Kubernetes CronJobs by
default. Jobs wait for their next scheduled run; they do not run immediately on
startup unless a `*_RUN_ON_START=true` variable is set. For local development,
`pnpm run dev` also uses `--safe-local-defaults`, so auto-sync and endpoint
checks do not inherit a global `WORKER_RUN_ON_START=true` unless their
worker-specific variable is set.

Stop the full local stack with `Ctrl+C`.

## Environment

Create `.env` in the repository root:

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

# Optional: override worker cron schedules. Defaults match Kubernetes Helm.
# WORKER_DISCOVERY_CRON="*/5 * * * *"
# WORKER_DELIVERY_CRON="1/5 * * * *"
# WORKER_AUTO_SYNC_CRON="0 * * * *"
# WORKER_ENDPOINT_CHECK_CRON="*/1 * * * *"
# WORKER_WEEKLY_DIGEST_CRON="0 9 * * 1"
```

The root `migrate` and `dev:*` scripts load this file before starting package
scripts.

## PostgreSQL

Using Docker:

```bash
docker run -d --name tokentimer-pg -p 5432:5432 -e POSTGRES_USER=tokentimer -e POSTGRES_PASSWORD=password -e POSTGRES_DB=tokentimer postgres:17
```

If the container already exists:

```bash
docker start tokentimer-pg
```

## Useful Commands

```bash
pnpm run migrate
pnpm run dev
pnpm run dev:api
pnpm run dev:dashboard
pnpm run dev:worker
```

Worker-only commands:

```bash
pnpm --filter @tokentimer/worker dev
pnpm --filter @tokentimer/worker dev:discovery
pnpm --filter @tokentimer/worker dev:delivery
pnpm --filter @tokentimer/worker dev:auto-sync
pnpm --filter @tokentimer/worker dev:endpoint-check
pnpm --filter @tokentimer/worker dev:weekly-digest
```

One-shot worker commands remain available for tests, CI, and Kubernetes CronJobs:

```bash
pnpm --filter @tokentimer/worker start:discovery
pnpm --filter @tokentimer/worker start:delivery
pnpm --filter @tokentimer/worker start:auto-sync
pnpm --filter @tokentimer/worker start:endpoint-check
pnpm --filter @tokentimer/worker start:weekly-digest
```

## Worker Runner

`apps/worker/src/runner.js` is the long-running worker scheduler used by local
development and Docker Compose. It reuses the existing one-shot job functions and
does not duplicate business logic.

Examples:

```bash
node apps/worker/src/runner.js discovery
node apps/worker/src/runner.js delivery
node apps/worker/src/runner.js auto-sync
node apps/worker/src/runner.js endpoint-check
node apps/worker/src/runner.js weekly-digest
node apps/worker/src/runner.js all
node apps/worker/src/runner.js discovery --once
```

Schedules are explicit and configurable. Cron defaults match
`deploy/helm/values.yaml`:

| Worker | Cron variable | Default schedule | Runs on start |
|--------|---------------|------------------|---------------|
| Alert Discovery | `WORKER_DISCOVERY_CRON` | `*/5 * * * *` | No |
| Alert Delivery | `WORKER_DELIVERY_CRON` | `1/5 * * * *` | No |
| Auto Sync | `WORKER_AUTO_SYNC_CRON` | `0 * * * *` | No |
| Endpoint Check | `WORKER_ENDPOINT_CHECK_CRON` | `*/1 * * * *` | No |
| Weekly Digest | `WORKER_WEEKLY_DIGEST_CRON` | `0 9 * * 1` | No |

```bash
WORKER_DISCOVERY_CRON="*/5 * * * *"
WORKER_DELIVERY_CRON="1/5 * * * *"
WORKER_AUTO_SYNC_CRON="0 * * * *"
WORKER_ENDPOINT_CHECK_CRON="*/1 * * * *"
WORKER_WEEKLY_DIGEST_CRON="0 9 * * 1"
WORKER_RUN_ON_START=false
WORKER_EXIT_ON_ERROR=false
```

Cron schedules use the process/container timezone. Set `TZ` for Docker
containers if you need a specific timezone.

Set a worker cron variable to `interval` to use the legacy millisecond interval
mode:

```bash
WORKER_DISCOVERY_CRON=interval
WORKER_DISCOVERY_INTERVAL_MS=60000
```

Weekly digest does not inherit the global `WORKER_RUN_ON_START` setting. Set
`WORKER_WEEKLY_DIGEST_RUN_ON_START=true` if you need to run it immediately.

The worker `dev` script passes `--safe-local-defaults`, so auto-sync and
endpoint checks do not run on start during local development even if
`WORKER_RUN_ON_START=true` is present. Use the worker-specific
`WORKER_AUTO_SYNC_RUN_ON_START=true` or
`WORKER_ENDPOINT_CHECK_RUN_ON_START=true` variables when immediate local runs
are intentional.

## Docker Compose

Docker Compose uses the long-running worker runner with the same explicit cron
schedules as Kubernetes. `restart: unless-stopped` is kept only for crash
recovery, not as the scheduler.

```bash
cd deploy/compose
docker compose up -d
```

For backend in Docker with local dashboard hot reload:

```bash
cd deploy/compose
docker compose up -d postgres api worker-discovery worker-delivery worker-auto-sync worker-endpoint-check worker-weekly-digest

cd ../..
pnpm run dev:dashboard
```

## Production Scheduling Model

- Docker Compose: use the long-running worker runner with Kubernetes-matching
  cron schedules.
- Kubernetes: keep using CronJobs for periodic one-shot tasks, or deploy the
  runner as a Deployment when an in-process scheduler is preferred.

The existing one-shot worker scripts are intentionally preserved for Kubernetes
CronJobs, CI, tests, and manual operations.

## Checks

```bash
curl http://localhost:4000/health
curl http://localhost:5173
```
