#!/usr/bin/env bash
# The operator journey observes a real maintenance worker. Start it only for
# acceptance, then stop it so focused scheduler tests retain their isolation.
set -euo pipefail
action="${1#*=}"
cd /opt/ttqualification
file=/opt/ttqualification/acceptance-worker.compose.yml
candidate=$(git rev-parse HEAD)
[[ "$candidate" =~ ^[a-f0-9]{40}$ ]] || exit 1
compose=(-f deploy/compose/docker-compose.test.yml -f "$file")
report=/opt/ttqualification/acceptance-worker-report.json
assert_owned() {
  test "$(docker inspect --format '{{ index .Config.Labels "com.tokentimer.qualification.candidate" }}' "$1")" = "$candidate"
  test "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.service" }}' "$1")" = acceptance-worker
  test "$(docker inspect --format '{{json .Config.Cmd}}' "$1")" = '["node","src/runner.js","certops"]'
}
case "$action" in
  start)
    # Refuse another scheduler instead of competing for a shared database.
    for container in $(docker ps -q); do
      command=$(docker inspect --format '{{json .Config.Cmd}}' "$container")
      case "$command" in *runner.js*|*certops-worker.js*) echo 'Another worker is already running' >&2; exit 1 ;; esac
    done
    if test -f "$file"; then
      prior=$(docker compose "${compose[@]}" ps -aq acceptance-worker)
      test -z "$prior" || assert_owned "$prior"
    fi
    cat > "$file" <<'YAML'
services:
  acceptance-worker:
    build:
      context: /opt/ttqualification
      dockerfile: apps/worker/Dockerfile.dev
    environment:
      NODE_ENV: production
      WORKER_EXIT_ON_ERROR: 'true'
      DB_HOST: postgres
      DB_PORT: '5432'
      DB_NAME: tokentimer
      DB_USER: tokentimer
      DB_PASSWORD: password
      CERTOPS_ENABLED: 'true'
      CERTOPS_SIGNING_ENCRYPTION_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
      CERTOPS_REGISTRATION_ENCRYPTION_KEY: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
    networks: [tokentimer-test]
    # Use the operator's production scheduler and its default one-minute cron.
    # A failure must remain visible rather than being hidden by restart loops.
    restart: 'no'
    stop_grace_period: 45s
    command: [node, src/runner.js, certops]
YAML
    printf '    labels:\n      com.tokentimer.qualification.candidate: "%s"\n' "$candidate" >> "$file"
    docker compose "${compose[@]}" up -d --build acceptance-worker
    container=$(docker compose "${compose[@]}" ps -q acceptance-worker)
    test -n "$container"; assert_owned "$container"
    [[ "$container" =~ ^[a-f0-9]{64}$ ]]
    # Require an actual scheduled maintenance completion before handing the
    # deployment to browser acceptance; never invoke maintenance in-process.
    ready=0
    for attempt in $(seq 1 180); do
      test "$(docker inspect --format '{{.State.Running}}' "$container")" = true
      logs=$(docker logs "$container" 2>&1)
      if grep -Fq 'worker-runner-job-finish' <<< "$logs"; then ready=1; break; fi
      sleep 1
    done
    test "$ready" = 1
    grep -Fq 'worker-runner-worker-started' <<< "$logs"
    grep -Fq 'CertOps maintenance worker finished' <<< "$logs"
    test "$(grep -c 'worker-runner-worker-started' <<< "$logs")" = 1
    startup=$(grep -F 'worker-runner-worker-started' <<< "$logs")
    grep -Fq '"scheduleMode":"cron"' <<< "$startup"
    grep -Fq '"cronExpression":"*/1 * * * *"' <<< "$startup"
    grep -Fq '"runOnStart":false' <<< "$startup"
    printf '{"candidateSha":"%s","containerId":"%s","entrypoint":"src/runner.js certops","defaultCron":true,"scheduledMaintenanceObserved":true,"status":"running"}\n' "$candidate" "$container" > "$report"
    echo CERTOPS_STAGE=acceptance-worker-started
    ;;
  stop)
    test -f "$file"
    container=$(docker compose "${compose[@]}" ps -aq acceptance-worker)
    test -n "$container"; assert_owned "$container"
    docker compose "${compose[@]}" stop -t 45 acceptance-worker
    test "$(docker inspect --format '{{.State.Running}}' "$container")" = false
    test "$(docker inspect --format '{{.State.ExitCode}}' "$container")" = 0
    test "$(docker inspect --format '{{.State.OOMKilled}}' "$container")" = false
    logs=$(docker logs "$container" 2>&1)
    grep -Fq 'worker-runner-stopping' <<< "$logs"
    test "$(grep -c 'worker-runner-worker-started' <<< "$logs")" = 1
    starts=$(grep -c 'worker-runner-job-start' <<< "$logs")
    finishes=$(grep -c 'worker-runner-job-finish' <<< "$logs")
    test "$starts" -gt 0; test "$starts" = "$finishes"
    if grep -Eq 'worker-runner-job-failure|worker-runner-shutdown-timeout|worker-runner-pool-close-failure|worker-runner-skip-overlap' <<< "$logs"; then exit 1; fi
    printf '{"candidateSha":"%s","containerId":"%s","entrypoint":"src/runner.js certops","defaultCron":true,"scheduledMaintenanceObserved":true,"scheduledStarts":%s,"scheduledFinishes":%s,"exitCode":0,"nativeDrained":true,"status":"passed"}\n' "$candidate" "$container" "$starts" "$finishes" > "$report"
    echo CERTOPS_STAGE=acceptance-worker-stopped
    ;;
  *) echo 'Unsupported acceptance worker action' >&2; exit 1 ;;
esac
