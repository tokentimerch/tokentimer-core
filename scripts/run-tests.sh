#!/usr/bin/env bash
# ============================================================
# TokenTimer Core - Integration Test Runner
# Usage:  bash scripts/run-tests.sh          (from project root)
#         pnpm test                           (same thing via pnpm)
#
# What it does:
#   1. Loads .env.test so Mocha / setup.js can reach the containers
#   2. Starts docker-compose.test.yml  (postgres, api, mailhog, workers)
#   3. Waits until the API is healthy
#   4. Installs test devDependencies if needed
#   5. Runs Mocha integration tests
#   6. Tears everything down (volumes removed for a clean slate)
# ============================================================

set -euo pipefail

# ---- paths --------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$PROJECT_ROOT/deploy/compose/docker-compose.test.yml"
ENV_FILE="$PROJECT_ROOT/.env.test"

# ---- logging ------------------------------------------------
mkdir -p "$PROJECT_ROOT/logs"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$PROJECT_ROOT/logs/test-output-${TIMESTAMP}.log"
DOCKER_LOG_FILE="$PROJECT_ROOT/logs/docker-logs-${TIMESTAMP}.log"
COMBINED_LOG_FILE="$PROJECT_ROOT/logs/combined-logs-${TIMESTAMP}.log"
TEST_EXIT_CODE=0
DOCKER_LOG_PID=""

# ---- cleanup on exit ----------------------------------------
cleanup() {
  echo ""
  if [ -n "${DOCKER_LOG_PID}" ]; then
    kill "${DOCKER_LOG_PID}" 2>/dev/null || true
  fi

  {
    echo "=== TOKENTIMER CORE TESTS - COMBINED LOG ==="
    echo "Timestamp: ${TIMESTAMP}"
    echo ""
    echo "=== DOCKER LOGS ==="
    if [ -f "$DOCKER_LOG_FILE" ]; then cat "$DOCKER_LOG_FILE"; else echo "(no docker logs captured)"; fi
    echo ""
    echo "=== TEST OUTPUT ==="
    if [ -f "$LOG_FILE" ]; then cat "$LOG_FILE"; else echo "(no test output captured)"; fi
  } > "$COMBINED_LOG_FILE"

  echo "==> Stopping test containers..."
  docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans 2>/dev/null || true
  echo "==> Done.  Exit code: ${TEST_EXIT_CODE}"
  echo "==> Test output : ${LOG_FILE}"
  echo "==> Docker logs : ${DOCKER_LOG_FILE}"
  echo "==> Combined    : ${COMBINED_LOG_FILE}"
}
trap cleanup EXIT

# ---- load .env.test into this shell -------------------------
if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found. Cannot configure test env."
  exit 1
fi

echo "=== TokenTimer Core Integration Tests ==="
echo "Timestamp : ${TIMESTAMP}"
echo "Compose   : ${COMPOSE_FILE}"
echo "Env file  : ${ENV_FILE}"
echo ""

# Export every non-comment, non-empty line from .env.test
# Strip Windows carriage returns if present (common on CRLF checkouts)
ENV_CLEAN=$(mktemp)
tr -d '\r' < "$ENV_FILE" > "$ENV_CLEAN"
set -a
# shellcheck disable=SC1090
source "$ENV_CLEAN"
set +a
rm -f "$ENV_CLEAN"

# ---- stop any leftover containers --------------------------
echo "==> Cleaning up previous containers..."
docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans 2>/dev/null || true

# ---- start services -----------------------------------------
echo "==> Starting test services (postgres, api, mailhog, workers)..."
if [ "${TT_SKIP_COMPOSE_BUILD:-0}" = "1" ] || [ "${TT_SKIP_COMPOSE_BUILD:-}" = "true" ]; then
  echo "==> TT_SKIP_COMPOSE_BUILD enabled, reusing existing images (no --build)."
  docker compose -f "$COMPOSE_FILE" up -d
else
  docker compose -f "$COMPOSE_FILE" up --build -d
fi

echo "==> Capturing docker logs..."
docker compose -f "$COMPOSE_FILE" logs -f > "$DOCKER_LOG_FILE" 2>&1 &
DOCKER_LOG_PID=$!

# ---- wait for API -------------------------------------------
echo "==> Waiting for API to be ready at ${TEST_API_URL:-http://localhost:4000} ..."
MAX_WAIT=60
WAITED=0
until curl -sf "${TEST_API_URL:-http://localhost:4000}/" >/dev/null 2>&1; do
  WAITED=$((WAITED + 2))
  if (( WAITED >= MAX_WAIT )); then
    echo ""
    echo "ERROR: API did not become ready within ${MAX_WAIT}s."
    echo "--- API container logs ---"
    docker compose -f "$COMPOSE_FILE" logs api || true
    exit 1
  fi
  printf "."
  sleep 2
done
echo ""
echo "==> API is ready (took ~${WAITED}s)."

# ---- install test dependencies (host side) ------------------
cd "$PROJECT_ROOT"
if [ -x "$(command -v pnpm)" ] \
  && pnpm exec mocha --version >/dev/null 2>&1 \
  && node -e "const path=require('path');const roots=[process.cwd(),path.join(process.cwd(),'apps','api')];let resolved=null;for(const r of roots){try{resolved=require.resolve('prom-client',{paths:[r]});break;}catch(_){}}if(!resolved)process.exit(2);const p=require(resolved);if(!p||!p.register)process.exit(2);" >/dev/null 2>&1; then
  echo "==> Test dependencies already available, skipping install."
else
  echo "==> Installing test dependencies..."
  INSTALL_OK=0
  for args in \
    "--frozen-lockfile --ignore-scripts --prefer-offline --child-concurrency=1"
  do
    if CI=true pnpm install ${args}; then
      if node -e "const path=require('path');const roots=[process.cwd(),path.join(process.cwd(),'apps','api')];let resolved=null;for(const r of roots){try{resolved=require.resolve('prom-client',{paths:[r]});break;}catch(_){}}if(!resolved)process.exit(2);const p=require(resolved);if(!p||!p.register)process.exit(2);" >/dev/null 2>&1; then
        INSTALL_OK=1
        break
      fi
    fi
    sleep 2
  done
  if [ "$INSTALL_OK" -ne 1 ] && [ "${TT_ALLOW_FORCE_INSTALL:-0}" = "1" ]; then
    echo "==> Non-force install failed, trying force mode (TT_ALLOW_FORCE_INSTALL=1)..."
    for args in \
      "--frozen-lockfile --ignore-scripts --prefer-offline --force --child-concurrency=1" \
      "--ignore-scripts --prefer-offline --force --child-concurrency=1"
    do
      if CI=true pnpm install ${args}; then
        if node -e "const p=require('prom-client');if(!p||!p.register)process.exit(2);" >/dev/null 2>&1; then
          INSTALL_OK=1
          break
        fi
      fi
      sleep 2
    done
  fi
  if [ "$INSTALL_OK" -ne 1 ]; then
    echo "ERROR: unable to install/verify test dependencies."
    exit 1
  fi
fi

# ---- run mocha ----------------------------------------------
echo ""
SUITE_NAME="${TT_TEST_SUITE:-core}"
echo "==> Running integration tests (suite: ${SUITE_NAME})..."
set +e
TT_AUTO_INSTALL_TEST_DEPS="${TT_AUTO_INSTALL_TEST_DEPS:-0}" node scripts/run-integration-suite.js "${SUITE_NAME}" 2>&1 | tee -a "$LOG_FILE"
TEST_EXIT_CODE=${PIPESTATUS[0]}
set -e

echo ""
echo "=== Tests finished with exit code: ${TEST_EXIT_CODE} ==="
echo "Log file: ${LOG_FILE}"
exit ${TEST_EXIT_CODE}
