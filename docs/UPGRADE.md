# Upgrade Core

Use the target release notes to choose a supported transition. Keep the API, dashboard, workers, configuration, and chart from the same release. Source-development updates are covered in [DEVELOPMENT.md](https://github.com/tokentimerch/tokentimer-core/blob/main/DEVELOPMENT.md).

## Before upgrading

1. Record the running version, image tags or digests, and Compose files or Helm values.
2. Back up the database **and matching secrets and configuration** using [Backup and restore](BACKUP_RESTORE.md). Preserve `SESSION_SECRET`, CertOps wrapping keys, and agent state; changing them is not an upgrade step.
3. Read migration and compatibility notes for the target release. For agents, follow [upgrade ordering](https://github.com/tokentimerch/tokentimer-core/blob/main/docs/certops/agent/operations.md).
4. Plan downtime if the release requires it. Keep the recovery set available before starting.

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

## Recover a failed upgrade

Stop and inspect migration and application logs. Reverting an image or running `helm rollback` does not undo database migrations. Use the release's recovery instructions and a matching database/configuration backup; do not start an older binary against a changed schema unless that transition is explicitly supported.
