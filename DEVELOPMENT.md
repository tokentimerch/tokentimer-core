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

Intervals are explicit and configurable:

| Worker | Environment variable | Default | Runs on start |
|--------|----------------------|---------|---------------|
| Alert Discovery | `WORKER_DISCOVERY_INTERVAL_MS` | `60000` (60 seconds) | Yes |
| Alert Delivery | `WORKER_DELIVERY_INTERVAL_MS` | `30000` (30 seconds) | Yes |
| Auto Sync | `WORKER_AUTO_SYNC_INTERVAL_MS` | `300000` (5 minutes) | Yes |
| Endpoint Check | `WORKER_ENDPOINT_CHECK_INTERVAL_MS` | `60000` (60 seconds) | Yes |
| Weekly Digest | `WORKER_WEEKLY_DIGEST_INTERVAL_MS` | `86400000` (24 hours) | No |

```bash
WORKER_DISCOVERY_INTERVAL_MS=60000
WORKER_DELIVERY_INTERVAL_MS=30000
WORKER_AUTO_SYNC_INTERVAL_MS=300000
WORKER_ENDPOINT_CHECK_INTERVAL_MS=60000
WORKER_WEEKLY_DIGEST_INTERVAL_MS=86400000
WORKER_RUN_ON_START=true
WORKER_EXIT_ON_ERROR=false
```

Weekly digest does not run on start by default. Set
`WORKER_WEEKLY_DIGEST_RUN_ON_START=true` if you need that behavior.

## Docker Compose

Docker Compose uses the long-running worker runner with explicit intervals.
`restart: unless-stopped` is kept only for crash recovery, not as the scheduler.

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

- Docker Compose: use the long-running worker runner with explicit intervals.
- Kubernetes: keep using CronJobs for periodic one-shot tasks, or deploy the
  runner as a Deployment when polling workers are preferred.

The existing one-shot worker scripts are intentionally preserved for Kubernetes
CronJobs, CI, tests, and manual operations.

## Checks

```bash
curl http://localhost:4000/health
curl http://localhost:5173
```
