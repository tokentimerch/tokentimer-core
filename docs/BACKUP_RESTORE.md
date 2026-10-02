<a id="scope"></a>

## What to back up

PostgreSQL stores tokens, workspaces, users, queues, audit and delivery logs, and system settings. A database backup must be paired with the deployment configuration and the keys needed to decrypt stored settings.

Keep a recoverable copy of:

- A consistent database backup.
- Deployment configuration: Compose `.env` and mounted configuration files, or Helm values and referenced Kubernetes Secrets. Record the application and database versions used by the backup.
- The original `SESSION_SECRET`. It signs sessions **and derives the encryption key for stored SMTP/Twilio and integration credentials**. Replacing it invalidates sessions and can make those stored credentials unreadable.
- When CertOps agents are enabled, `CERTOPS_SIGNING_ENCRYPTION_KEY` and `CERTOPS_REGISTRATION_ENCRYPTION_KEY`, which wrap control-plane signing and registration credentials. See [Configuration](CONFIGURATION.md).
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
docker compose exec -T postgres pg_dump -U tokentimer tokentimer | gzip > "tokentimer-$(date +%F).sql.gz"
```

### Restore

```bash
docker compose exec -T postgres psql -U tokentimer tokentimer < backup.sql
```

> **Warning**
>
> Restore into an empty database. If the target database already contains data, drop and recreate it first (or restore into a fresh volume), otherwise the restore can fail on conflicts or leave a mixed state.

If you changed `DB_USER` or `DB_NAME` in your `.env`, use those values in the commands above.

<a id="kubernetes"></a>

## Kubernetes (Helm / CloudNativePG)

The Helm chart provisions PostgreSQL as a CloudNativePG `Cluster` named `<release>-pg` by default (for a release named `tokentimer`, the cluster and its pods are `tokentimer-pg`).

### Option A - CNPG-native backups (recommended)

If you enabled the chart's backup support (`postgresql.cloudnative.backup.enabled`), CloudNativePG handles base backups and WAL archiving to object storage (barman object store with S3 credentials and a retention policy). Prefer this for production: it gives you point-in-time recovery and does not depend on manual dumps.

Trigger an on-demand backup with a CNPG `Backup` resource, and restore by bootstrapping a new cluster from the object store (see the CloudNativePG recovery documentation for your operator version).

### Option B - Manual pg_dump against the cluster pod

For ad-hoc dumps or when CNPG backups are not configured, exec into the current primary pod:

```bash
# Find the primary pod of the CNPG cluster
kubectl get pods -n tokentimer -l cnpg.io/cluster=tokentimer-pg

# Dump (adjust pod name to the current primary, e.g. tokentimer-pg-1)
kubectl exec -n tokentimer tokentimer-pg-1 -- \
  pg_dump -U tokentimer tokentimer > backup.sql
```

Restore into an empty database:

```bash
kubectl exec -i -n tokentimer tokentimer-pg-1 -- \
  psql -U tokentimer tokentimer < backup.sql
```

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

Always take a backup before major upgrades or database migrations:

```bash
# Compose
docker compose exec -T postgres pg_dump -U tokentimer tokentimer > pre-upgrade-backup.sql

# Kubernetes (CNPG)
kubectl exec -n tokentimer tokentimer-pg-1 -- \
  pg_dump -U tokentimer tokentimer > pre-upgrade-backup.sql
```

Then follow the upgrade steps in the [install runbook](https://tokentimer.ch/docs/self-hosted/runbooks/install).
