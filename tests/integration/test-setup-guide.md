# Test Setup Guide

## Overview

This guide explains how to properly set up and run the integration tests for the TokenTimer application.

## Prerequisites

1. **Docker and Docker Compose** must be installed
2. **Node.js** (version 22 or higher) must be installed
3. **pnpm** must be available

## Quick Start

### 1. Start the Test Environment

```bash
# Run the CI script which sets up everything
pnpm run test:local:full
```

This script will:

- Install all dependencies
- Create necessary environment files
- Start Docker Compose services
- Wait for services to be ready

### 2. Run the Tests

```bash
# Run all tests
pnpm run test:core

# Run specific test files
pnpm run test:core -- tests/integration/token-validation.test.js
pnpm run test:core -- tests/integration/token-update-validation.test.js
```

## Manual Setup (Alternative)

If you prefer to set up manually:

### 1. Install Dependencies

```bash
pnpm install --frozen-lockfile
cd apps/api && pnpm install --frozen-lockfile && cd ../..
cd apps/dashboard && pnpm install --frozen-lockfile && cd ../..
```

### 2. Create Environment File

```bash
cat > .env << EOF
NODE_ENV=test
PORT=4000
DATABASE_URL=postgresql://tokentimer:password@localhost:5432/tokentimer
SESSION_SECRET=test-session-secret-key
APP_URL=http://localhost:5173
API_URL=http://localhost:4000
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USER=test@example.com
SMTP_PASS=test-password
EOF
```

### 3. Start Services

```bash
# Clean up any existing containers
docker compose down -v --remove-orphans

# Start services
docker compose up -d

# Wait for services to be ready
timeout 120 bash -c 'until curl -f http://localhost:4000/; do sleep 2; done'
```

### 4. Run Tests

```bash
pnpm run test:core
```

## Test Structure

### Test Files

1. **`token-validation.test.js`** - Tests for token creation validation
2. **`token-update-validation.test.js`** - Tests for token update validation
3. **`token-categories.test.js`** - Tests for token category functionality
4. **`tokens.test.js`** - General token management tests

### Test Utilities

- **`test-server.js`** - Server connection and utility functions
- **`test-data-manager.js`** - Test data management and cleanup
- **`shared-test-utils.js`** - Shared test utilities

## Common Issues

### 1. Connection Refused Errors

**Problem**: `ECONNREFUSED: Connection refused`

**Solution**: Ensure Docker Compose services are running:

```bash
docker compose ps
```

If services are not running:

```bash
docker compose up -d
```

### 2. TestDataManager Constructor Error

**Problem**: `TypeError: TestDataManager is not a constructor`

**Solution**: This has been fixed in the latest code. The import should be:

```javascript
const { TestDataManager } = require("./test-data-manager");
```

### 3. Server Not Ready

**Problem**: `Server not ready after 10 attempts`

**Solution**: Check if the api service is healthy:

```bash
docker compose logs api
```

### 4. Database Connection Issues

**Problem**: Database connection failures

**Solution**: Ensure PostgreSQL is running and healthy:

```bash
docker compose logs postgres
```

## Test Categories

### Token Validation Tests

- Required field validation
- Field length validation
- Category-specific validation
- Type validation per category

### Token Update Tests

- Field name consistency (`expiresAt` vs `expiration`)
- Date validation and processing
- Partial update functionality
- Category-specific validation during updates

### Token Categories Tests

- Certificate tokens (require domains and issuer)
- License tokens (require vendor)
- Key/Secret tokens
- General tokens

## Cleanup

After running tests, you can clean up the environment:

```bash
# Stop all services
docker compose down

# Remove volumes (optional - will delete all data)
docker compose down -v
```

## Debugging

### View Logs

```bash
# View all service logs
docker compose logs

# View specific service logs
docker compose logs api
docker compose logs postgres
```

### Check Service Status

```bash
# Check if services are running
docker compose ps

# Check service health
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
```

### Manual Database Access

```bash
# Connect to PostgreSQL
docker compose exec postgres psql -U tokentimer -d tokentimer
```

## Environment Variables

The test environment uses these key environment variables:

- `NODE_ENV=test` - Sets test mode
- `PORT=4000` - Backend port
- `DATABASE_URL` - PostgreSQL connection string
- `SESSION_SECRET` - Session encryption key
- `SMTP_HOST=localhost` - MailHog for email testing

## Test Data Management

The `TestDataManager` class provides:

- **Dataset isolation** - Each test gets its own dataset
- **Automatic cleanup** - Test data is cleaned up after tests
- **User creation** - Creates test users with authentication
- **Token creation** - Creates test tokens with various categories
- **Session management** - Manages authenticated sessions

## Best Practices

1. **Always use TestDataManager** for creating test data
2. **Clean up after tests** - Use the `after` hook
3. **Handle authentication** - Use the provided session management
4. **Test both positive and negative cases** - Validate error conditions
5. **Use descriptive test names** - Make failures easy to understand
