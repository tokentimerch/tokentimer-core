# Upgrade Core

Use the target release notes to choose a supported transition. Keep the API, dashboard, workers, configuration, and chart from the same release. Source-development updates are covered in [DEVELOPMENT.md](https://github.com/tokentimerch/tokentimer-core/blob/main/DEVELOPMENT.md).

## Before upgrading

1. Record the running version, image tags or digests, and Compose files or Helm values.
2. Back up the database **and matching secrets and configuration** using [Backup and restore](BACKUP_RESTORE.md). Preserve `SESSION_SECRET`, CertOps wrapping keys, and agent state; changing them is not an upgrade step.
3. Read migration and compatibility notes for the target release. For agents, follow [upgrade ordering](https://github.com/tokentimerch/tokentimer-core/blob/main/docs/certops/agent/operations.md).
4. Plan downtime if the release requires it. Keep the recovery set available before starting.

### Upgrading to 0.17.0 fingerprint inventory

Follow [fingerprint inventory upgrade guidance](CONFIGURATION.md#upgrading-to-fingerprint-inventory) before enabling the new CertOps actions. Back up the database and matching secrets, drain old automation, prevent lifecycle writes, and deploy matching API, workers and ingestion with migrations 62–66. Review ambiguous historical retirement evidence and verify grouping, rotation, endpoint removal/re-add, quota and decommission eligibility before resuming automation. Legacy retirement clients must supply the expected certificate identity. Reverting images does not reverse these migrations.

## Docker Compose

From the installed Compose directory, update the deployment files to the target release and review `.env.example` changes without overwriting your `.env`. Set `TT_IMAGE_TAG` to the selected published release in `.env`, then:

```bash
docker compose -f docker-compose.yml -f docker-compose.images.yml pull
docker compose -f docker-compose.yml -f docker-compose.images.yml up -d --no-build
docker compose -f docker-compose.yml -f docker-compose.images.yml ps -a
docker compose -f docker-compose.yml -f docker-compose.images.yml logs --tail 100 migrations api
curl http://localhost:4000/health
```

Confirm migrations exited successfully and every long-running service is healthy. Use the public API URL too if the deployment sits behind a proxy.

## Kubernetes

Review the target chart's values and release notes, keeping your own secrets and configuration:

```bash
read -r -p 'Target Core chart version: ' CORE_CHART_VERSION
helm upgrade tokentimer oci://ghcr.io/tokentimerch/charts/tokentimer \
  --version "$CORE_CHART_VERSION" -f my-values.yaml -n tokentimer --wait
kubectl rollout status deployment/tokentimer-api -n tokentimer
kubectl get jobs,cronjobs -n tokentimer
```

Check the migration Job and all six worker CronJobs. New CronJob specifications apply to subsequent Jobs. Existing pods retain environment values until restarted; see [Configuration basics](CONFIGURATION_BASICS.md#restart).

## Verify the result

Sign in, check the inventory and workspace recipients, run the SMTP test, and inspect discovery/delivery worker results. Follow [First asset and alert check](FIRST_ASSET.md) when verifying the full notification path. If you use CertOps, confirm agent compatibility and renewal state before scheduling real work.

Use the existing setup records when repeating the
[operator walkthroughs](OPERATOR_WALKTHROUGHS.md). Verify a signed dry run
after agent upgrades, then inspect an actual renewal and deployment result
before declaring automation healthy. A green heartbeat alone is insufficient.

## Recover a failed upgrade

Stop and inspect migration and application logs. Reverting an image or running `helm rollback` does not undo database migrations. Use the release's recovery instructions and a matching database/configuration backup; do not start an older binary against a changed schema unless that transition is explicitly supported.

## Dashboard errors after deployment

An open browser tab can still reference lazy page chunks from an older Vite
build after a deployment replaces those assets. The dashboard recognizes known
dynamic import and CSS preload failures and offers a refresh with an unsaved
changes warning. It never refreshes automatically, because a failed navigation
can occur while an operator is editing a form. Optional import failures show a non-destructive notice that keeps the current page and unsaved form state mounted until the operator chooses to refresh.

A tab-scoped session marker remembers a refresh attempt for one minute. If a
loader failure recurs during that interval, the error screen explains that the
refresh did not resolve the problem. Refresh remains an explicit user action,
including when session storage is unavailable, so recovery cannot loop.
Unrelated application errors retain the normal error boundary message.

If refreshing does not help, check connectivity and ensure the deployment serves
the current HTML and its referenced assets consistently. Retaining previous
hashed assets during a rollout can keep older tabs working. Loader failures can
also indicate network problems; they do not prove that a deployment occurred.
