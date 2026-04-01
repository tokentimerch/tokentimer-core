# TokenTimer Core - Local Development

## Quick Start

### Backend in Docker, Frontend Local (Recommended)

```bash
# 1. Start API and Worker in Docker
cd deploy/compose
docker compose up api worker postgres -d

# 2. Run dashboard locally (hot reload)
cd ../../apps/dashboard
pnpm install
pnpm run dev
```

**Access:**

- Dashboard: http://localhost:5173 (local Vite dev server with hot reload)
- API: http://localhost:4000 (Docker)

**Benefits:**

- Instant hot reload for frontend changes
- No Docker rebuild needed
- Backend still in Docker (easier database setup)

### All Local

```bash
# 1. Start PostgreSQL
docker run -d -p 5432:5432 \
  -e POSTGRES_USER=tokentimer \
  -e POSTGRES_PASSWORD=tokentimer_dev_password \
  -e POSTGRES_DB=tokentimer \
  postgres:17

# 2. Install all packages
cd tokentimer-core
pnpm install
cd packages/config && pnpm install && cd ../..
cd packages/contracts && pnpm install && cd ../..

# 3. Run migrations
cd apps/api
pnpm install
pnpm run migrate

# 4. Start API
pnpm run dev  # Runs on port 4000

# 5. In another terminal, start worker
cd apps/worker
pnpm install
pnpm run dev

# 6. In another terminal, start dashboard
cd apps/dashboard
pnpm install
pnpm run dev  # Opens http://localhost:5173
```

### Environment Variables

Create `apps/api/.env`:

```bash
DB_HOST=localhost
DB_PORT=5432
DB_NAME=tokentimer
DB_USER=tokentimer
DB_PASSWORD=tokentimer_dev_password
SESSION_SECRET=dev_secret
ADMIN_EMAIL=admin@localhost.local
ADMIN_PASSWORD=AdminPassword123!
ADMIN_NAME=Admin
APP_URL=http://localhost:5173
```

Create `apps/dashboard/.env`:

```bash
VITE_API_URL=http://localhost:4000
```

## Tips

**Fast Frontend Dev:**

```bash
# Backend once
docker compose up api worker postgres -d

# Frontend with hot reload
cd apps/dashboard
pnpm run dev
```

**Full Docker (slower but complete):**

```bash
cd deploy/compose
docker compose up -d
```

**Check Services:**

```bash
# API health
curl http://localhost:4000/health

# Dashboard
curl http://localhost:5173
```
