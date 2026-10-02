<a id="scope"></a>

## What to back up

PostgreSQL stores tokens, workspaces, users, queues, audit and delivery logs, and system settings. A database backup must be paired with the deployment configuration and the keys needed to decrypt stored settings.

Keep a recoverable copy of:

- A consistent database backup.
- Deployment configuration: Compose `.env` and mounted configuration files, or Helm values and referenced Kubernetes Secrets. Record the application and database versions used by the backup.
- The original `SESSION_SECRET`. It signs sessions **and derives the encryption key for stored SMTP/Twilio and integration credentials**. Replacing it invalidates sessions and can make those stored credentials unreadable.
- When CertOps agents are enabled, `CERTOPS_SIGNING_ENCRYPTION_KEY` and `CERTOPS_REGISTRATION_ENCRYPTION_KEY`, which wrap job-signing private keys and short-lived registration-replay credentials respectively. Existing enrolled-agent credentials are stored as hashes, not encrypted with the registration key. See [Configuration](CONFIGURATION.md).
- For Enterprise SSO, the complete `SSO_SECRETS_KEYRING` or its `_FILE` contents, including keys referenced by existing encrypted provider secrets. See [Enterprise configuration](https://tokentimer.ch/docs/enterprise/configuration#secrets-keyring-required-for-ui-stored-secrets).

Store secrets under your organization's access and backup controls. They can be held separately from database dumps, but the restore procedure must recover the matching values. A database dump alone is not a complete recovery set. Agent host state and any certificate private keys held on target hosts need their own host backup procedures.

> **Warning**
>
> Restore the matching keys before starting the API and workers. Do not generate replacement keys as a shortcut during recovery. Verify sign-in, settings decryption, and a test alert after restoration; for Enterprise, also verify SSO, and for CertOps, agent communication.

<a id="compose"></a>

## Docker Compose

The Compose stack runs PostgreSQL as the `postgres` service (container `tokentimer-db`), with database and user both named `tokentimer` by default.

### Backup

```bash
docker compose exec -T postgres pg_dump -U tokentimer tokentimer > backup.sql
```

For scheduled backups, add a timestamp and compress:

```bash
set -o pipefail
docker compose exec -T postgres pg_dump -U tokentimer tokentimer | gzip > "tokentimer-$(date +%F).sql.gz"
```

### Restore

Prefer a fresh, isolated restore environment with an empty database, the original
application/database versions, and the matching configuration and encryption
keys. Provision the database and its application role before restoring; keep the
API, migrations and workers stopped until the import succeeds. A dump does not
include cluster-wide roles.

For an existing deployment, enter maintenance first: stop incoming requests,
external writers, the API and all deployed workers. From the same Compose
directory and with the same Compose files you normally use:

```bash
docker compose stop api worker-discovery worker-delivery worker-weekly-digest \
  worker-auto-sync worker-endpoint-check worker-certops
docker compose ps -a
```

Confirm those services have stopped and no migration job or other client is
writing. Keep PostgreSQL running. Restore only into an empty database; use a
fresh database/volume if the current database contains data. Do not overlay a
dump onto existing tables.

```bash
docker compose exec -T postgres psql -U tokentimer --dbname=tokentimer \
  --set=ON_ERROR_STOP=1 --single-transaction < backup.sql
```

Check that the import exited successfully, expected records and ownership are
present, and the matching keys are configured. Then start only the API/workers
that were running before maintenance:

```bash
docker compose start api worker-discovery worker-delivery worker-weekly-digest \
  worker-auto-sync worker-endpoint-check worker-certops
```

Verify sign-in, settings decryption, and a test alert before reopening access.

If you changed `DB_USER` or `DB_NAME` in your `.env`, use those values in the commands above.

<a id="kubernetes"></a>

## Kubernetes (Helm / CloudNativePG)

For the default release named `tokentimer`, the Helm chart provisions the CloudNativePG `Cluster` `tokentimer-pg`. Use the actual Cluster name from your deployment if you changed the release name or fullname override.

### Option A - CNPG-native backups (recommended)

If you enabled the chart's backup support (`postgresql.cloudnative.backup.enabled`), CloudNativePG handles base backups and WAL archiving to object storage (barman object store with S3 credentials and a retention policy). Prefer this for production: it gives you point-in-time recovery and does not depend on manual dumps.

Trigger an on-demand backup with a CNPG `Backup` resource, and restore by bootstrapping a new cluster from the object store (see the CloudNativePG recovery documentation for your operator version).

### Option B - Manual pg_dump against the current primary

These commands use the local `postgres` OS/database identity in the PostgreSQL
container. CloudNativePG's fixed local authentication rule uses
[peer authentication](https://cloudnative-pg.io/docs/1.25/postgresql_conf/#the-pg_hba-section);
`-U tokentimer` over that socket does not authenticate as the application user.
No database password is needed for this local administrative connection.

Set the namespace, actual Cluster name and database. Select the primary by its
[instance-role label](https://cloudnative-pg.io/docs/1.25/labels_annotations/#predefined-labels),
rather than assuming pod `-1` remains primary after a failover:

```bash
CNPG_NAMESPACE=tokentimer
CNPG_CLUSTER=tokentimer-pg
CNPG_DATABASE=tokentimer
PRIMARY_POD="$(kubectl get pods -n "$CNPG_NAMESPACE" \
  -l "cnpg.io/cluster=$CNPG_CLUSTER,cnpg.io/instanceRole=primary" \
  -o jsonpath='{.items[0].metadata.name}')"
test -n "$PRIMARY_POD" || { echo 'No CNPG primary found' >&2; exit 1; }

kubectl exec -n "$CNPG_NAMESPACE" "$PRIMARY_POD" -c postgres -- \
  pg_dump --host=/controller/run --username=postgres \
  --dbname="$CNPG_DATABASE" > backup.sql
```

#### Restore without application writers

Prefer a new, isolated Cluster with the original PostgreSQL/application versions
and an empty database owned by the same application role. Provision that role
and database before importing; a database dump does not include cluster-wide
roles. Keep the TokenTimer API, workers and migration jobs stopped until the
restore completes.

For an existing deployment, enter maintenance before the import:

1. Record the API replica count and each worker CronJob's current suspend state.
   Pause reconcilers/autoscalers that could restart application writers.
2. Suspend the release's worker CronJobs, scale its API Deployment to zero, and
   wait for API pods and already-running worker/migration Jobs to stop. Suspending
   a CronJob prevents future runs; it does not stop an existing Job. Also stop
   external clients that write directly to the database. Leave PostgreSQL and
   the CloudNativePG operator running.
3. Confirm the target database is empty and all application writers are stopped.
   For a fresh restore, do not start application workloads before the import.

Set `CNPG_NAMESPACE`, `CNPG_CLUSTER` and `CNPG_DATABASE` for the **restore target**.
Re-select its primary immediately before restoring; it may differ from the
backup's primary or be in another Cluster:

```bash
PRIMARY_POD="$(kubectl get pods -n "$CNPG_NAMESPACE" \
  -l "cnpg.io/cluster=$CNPG_CLUSTER,cnpg.io/instanceRole=primary" \
  -o jsonpath='{.items[0].metadata.name}')"
test -n "$PRIMARY_POD" || { echo 'No CNPG primary found' >&2; exit 1; }

kubectl exec -i -n "$CNPG_NAMESPACE" "$PRIMARY_POD" -c postgres -- \
  psql --host=/controller/run --username=postgres --dbname="$CNPG_DATABASE" \
  --set=ON_ERROR_STOP=1 --single-transaction < backup.sql
```

Confirm the command succeeded and check restored records and ownership. Restore
the matching encryption keys, then return API replicas and worker schedules to
their recorded states. Verify sign-in, settings decryption and a test alert
before reopening access. Keep failed imports isolated and investigate the error
before starting application writers.

### External PostgreSQL

If you pointed the chart at an external database (`postgresql.external`), use your existing backup tooling for that instance, and preserve the deployment configuration and encryption keys listed above.

### PVCs on uninstall

Do not rely on `helm uninstall` to preserve the database. The release owns the CloudNativePG `Cluster`; deleting it can also delete its PVCs and underlying storage, depending on ownership and the volume reclaim policy. Take and verify a separate backup before uninstalling. If you need to preserve cluster storage, follow the [CloudNativePG procedures for your operator version](https://cloudnative-pg.io/docs/1.25/kubectl-plugin/#cluster-hibernation) and verify the result before deleting the release. Retained volumes are not a substitute for a backup.

<a id="cadence"></a>

## Recommended cadence and retention

| Environment | Cadence | Retention |
|---|---|---|
| Production | Daily automated dump or continuous CNPG WAL archiving | 30 days, plus monthly archives per your compliance needs |
| Staging / lab | Weekly, or before risky changes | 7 days |

Whatever the schedule, periodically test a restore into a scratch environment. A backup you have never restored is not verified.

<a id="pre-upgrade"></a>

## Before every upgrade

Always take and verify a backup before major upgrades or database migrations.
Use the Compose or CNPG backup steps above with a name such as
`pre-upgrade-backup.sql`; re-select the current CNPG primary for each backup.

Then follow [Upgrade Core](UPGRADE.md).
