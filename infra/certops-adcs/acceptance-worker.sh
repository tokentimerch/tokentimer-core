#!/usr/bin/env bash
# The operator journey observes a real maintenance worker. Start it only for
# acceptance, then stop it so focused scheduler tests retain their isolation.
set -euo pipefail
action="${1#*=}"
cd /opt/ttqualification
file=/opt/ttqualification/acceptance-worker.compose.yml
case "$action" in
  start)
    cat > "$file" <<'YAML'
services:
  acceptance-worker:
    build:
      context: /opt/ttqualification
      dockerfile: apps/worker/Dockerfile.dev
    environment:
      NODE_ENV: test
      DB_HOST: postgres
      DB_PORT: '5432'
      DB_NAME: tokentimer
      DB_USER: tokentimer
      DB_PASSWORD: password
      CERTOPS_ENABLED: 'true'
      CERTOPS_SIGNING_ENCRYPTION_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
      CERTOPS_REGISTRATION_ENCRYPTION_KEY: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
    networks: [tokentimer-test]
    # The normal worker performs one maintenance pass and exits. Docker reruns
    # that production executable; the harness never calls scheduler functions.
    restart: unless-stopped
    command: [node, src/certops-worker.js]
YAML
    docker compose -f deploy/compose/docker-compose.test.yml -f "$file" up -d --build acceptance-worker
    echo CERTOPS_STAGE=acceptance-worker-started
    ;;
  stop)
    test -f "$file"
    docker compose -f deploy/compose/docker-compose.test.yml -f "$file" stop acceptance-worker
    echo CERTOPS_STAGE=acceptance-worker-stopped
    ;;
  *) echo 'Unsupported acceptance worker action' >&2; exit 1 ;;
esac
