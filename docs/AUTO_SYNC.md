# Import assets and keep them current

Use a named configuration for each provider connection and scope. Core supports scheduled GitHub and GitLab scans; Enterprise adds entitled providers, including AWS, Azure Key Vault, Entra ID and GCP. Cloud performs one-time scans and does not offer scheduled provider sync.

## Connect, preview and import

1. Open **Import tokens** in the intended workspace. For a file, select the file option and review the parsed rows. For GitHub/GitLab, provide the instance URL and a suitably scoped credential, then scan.
2. Apply filters and review the preview. A preview has not saved inventory. Select the intended rows, confirm **Import selected**, and wait for the result.
3. Return to the same workspace inventory. Check the imported record's source, expiration and recipients before enabling unattended updates.

TokenTimer tracks metadata rather than the secret value. A one-time scan does not create a saved sync connection; an explicitly enabled self-hosted sync keeps its credentials encrypted on your infrastructure.

### Filter scan results

AWS, Azure Key Vault, Entra ID and GCP accept `filterRules`, as do GitHub, GitLab and Vault. Choose **name**, **description** or **location**, then **include** or **exclude**, with **exact** or **regex** matching. Excludes win; if includes exist, an item must match one. Exact means case-sensitive whole-field equality. Regex uses JavaScript syntax and is case-sensitive unless explicit flags are supplied; unsafe patterns are rejected. Rules apply before import and can be saved with scheduled configurations. Filtering alone does not silence existing alerts, but enabled cleanup can remove excluded inventory after a complete scan. Keep cleanup off while changing filters; manage contact groups, recipient preferences and alert controls separately.

### Separate Entra managed identities

`managedIdentityMode` defaults to `all` when omitted. `all` and `exclude` honor the application/service-principal include switches. `only` forces service-principal scanning on and applications off. Managed means Graph's exact `servicePrincipalType: ManagedIdentity`, covering system-assigned and user-assigned identities, not names or missing type values. This scans their exposed credential metadata, not access tokens.

Only managed-identity locations change to `azure-ad:managedIdentities/...`; canonical source identity stays stable. Saved location rules evaluate both this path and the derived old `azure-ad:servicePrincipals/...` path, keeping exact matching and regex expressions unchanged. Use the native mode for a true split. Imports prefer canonical source identity; otherwise they adopt only one unattributed record at the exact derived old location, even after a provider rename. Ambiguous matches fail instead of creating duplicates. IDs, operator metadata, alert state and associations remain intact; there is no blanket migration.

### Safely split a saved Entra connection

Entra schedules require Enterprise. Multiple configurations require the existing [System settings activation](#deployment-activation-and-rollback), including draining old workers.

1. Create the **managed-only** configuration first with `managedIdentityMode: only` and cleanup **off**. Run/import successfully so existing matching assets gain its association.
2. Set the remaining configuration to `exclude`, with cleanup **off**, and complete its first run.
3. Inspect run history, configuration associations and contact-group assignments before optionally enabling cleanup.

Overlapping associations prevent deletion. Manual inventory remains after detachment. Filters and scan modes do not transfer existing alert assignments to a different contact group.

## Enable a schedule

Use **Enable auto-sync**, give the configuration a recognizable name, then choose frequency, time and timezone. Select the notification groups for assets created by future runs. Existing assets keep their own group assignments.

The worker's polling cadence (`WORKER_AUTO_SYNC_CRON` in Compose or `worker.cronjobs.autoSync.schedule` in Helm) determines when due configurations are checked. It is separate from each connection's own schedule. Confirm the configured worker is running.

Use **Manage auto-sync** to review or edit a saved connection. **Run now** requests a scan; repeated clicks while one is active coalesce into one later run. Disabled configurations do not run queued requests until enabled.

## Verify an update

1. Open the selected configuration's run history. Check completion, partial/error status and separate created/updated counts. **Earlier runs** loads older results.
2. Inspect the same inventory record after a provider-side metadata change and successful run. Match its source identity, not just a name. Two previews are not evidence of a persisted update.
3. In asset details, review **Auto-sync** ownership/configuration and association history where present. Manual assets without sync provenance have no such section.

Overlapping configurations may discover one provider identity and share its inventory record. Changing a name or schedule preserves the configuration. Changing credentials, scope or scan settings supersedes active work and queues a replacement when enabled.

## New inventory metrics

With `ENABLE_METRICS=true`, API `/metrics` exposes
`auto_sync_items_created_total{provider}` on every scrape, including zero before
the first creation. It counts committed auto-sync additions and persists across
restarts and deletions; historical imports are not backfilled. For `increase()`
alerts, scrape one stable API target per database and record a baseline first.
Do not sum replica copies. Monitor scrape failures separately.

Migration 80 also exposes `auto_sync_run_outcomes_total{provider,status}` for
committed `success`, `partial`, `failed`, and `superseded` run outcomes. Each run
counts once when it first leaves `running`, including lease recovery and API
supersession. Existing history is not backfilled; totals survive history deletion.
The separate name distinguishes this durable counter from the worker's
process-local `auto_sync_runs_total`.

`auto_sync_last_attempt_timestamp_seconds{provider}` records the latest run start;
`auto_sync_last_success_timestamp_seconds{provider}` records the latest fully
successful completion. Both are Unix seconds, persist after restart/deletion,
and expose zero until observed. Partial and failed runs never refresh success.
For freshness alerts, require a timestamp greater than zero before comparing
`time() - auto_sync_last_success_timestamp_seconds` with your expected schedule;
handle never-successful providers separately. Provider aggregates describe the
installation, so one healthy configuration can hide another configuration's
failure; use configuration run history to investigate individual connections.

`auto_sync_enabled_configurations{provider}` is the current number of enabled
connections. Scope freshness and failure alerts to values greater than zero so
unused providers and disabled or deleted connections do not page operators.
Apply the opt-in `deploy/helm/examples/values-auto-sync-alerts.yaml` after your
normal values. For standalone Prometheus, extract its
`monitoring.prometheusRules.groups` into a rule file under the top-level `groups`
key. Use a unique `installation` label per database, shared by its replicas;
match Prometheus Operator selectors and check target discovery/rule loading.

The creation alert detects rolling 15-minute activity, not one notification per
asset. `increase()` can extrapolate fractional values. The failure alert requires
three observed failures in three hours and no persisted full success in that
window. It excludes counter resets and deduplicates replicas without extrapolation;
scrape gaps, resets and replacement targets can undercount. Tune the 25-hour
freshness/grace periods for your longest schedule. Alertmanager controls delivery.
Collector errors can return HTTP 500; connection failures may terminate the API.
Both cause scrape failures, not evidence of zero activity.

Owner labels do not belong on aggregates: `auto_sync_items_created_total` spans
owners, `auto_sync_items_created_by_kind_total` groups asset types, and enabled
configuration, run-outcome, attempt and success metrics describe connection/run
health rather than a PAT. The worker's process-local run metrics likewise have
no single asset owner. These metrics retain their low-cardinality labels.

### Optional configuration and asset labels

- Apply migrations through 111 with matching API/dashboard code; aggregate counters stay unchanged.
- System Settings → Auto-sync independently overrides metrics/labels and monitoring group, locking integration controls. Otherwise, integrations retain their choices.
- Environment wins: `AUTO_SYNC_METRICS_ENABLED=true/false`, optional `AUTO_SYNC_METRICS_LABELS` (CSV or `none`), and independent `AUTO_SYNC_METRICS_MONITORING_GROUP`. Empty restores saved values; `AUTO_SYNC_METRICS_EXTRA_LABELS` optionally restricts asset labels.
- Helm: `monitoring.metrics.autoSyncEnabled`, `autoSyncLabels`, `autoSyncMonitoringGroup` (under `tokentimer` in Enterprise). Available labels are listed beside these settings.
- **Warning:** label combinations multiply detailed series and expose metadata. Names/scopes cover future creations; old samples remain until retention expires.

### GitLab PAT owner labels

- `owner_username` resolves the GitLab PAT's owner ID to a username, never the importer or configuration creator. Missing IDs, inaccessible/deleted users, older servers and lookup limits leave it empty; old PAT coverage is not guaranteed.
- Disabled by default. Select **GitLab PAT owner username** in **System Settings → Auto-sync → Override integration metrics** for all connections, or in individual connection settings. An empty `AUTO_SYNC_METRICS_EXTRA_LABELS` uses saved System Settings permissions. A nonempty list restricts permitted labels, for example `owner_username` (Helm: `monitoring.metrics.extraLabels: [owner_username]`); `none` denies them. Owner permission never selects the label: the effective global or connection selection must also include it. Connection selection alone grants no permission.
- Both `auto_sync_last_creation_timestamp_seconds` and `auto_sync_items_created_detailed_total` use creation-time metadata, not expiry. Rediscovery or renaming does not create an event or enrich old inventory; unknown/unselected owners are empty.
- Usernames increase cardinality and expose personal metadata to metrics readers and alert recipients. Effective opt-ins gate scan/statistics capture, not just display. Opt-out hides retained statistics; configuration deletion removes them. Persisted scan metadata remains until its scan/workspace is deleted; old Prometheus samples follow Prometheus retention.
- In Grafana/Prometheus, explicit `max by (...)` lists must preserve `owner_username`; annotations can use `{{ $labels.owner_username }}`. Aggregation that drops it cannot show the owner.

## Cleanup and removal

Destructive cleanup is explicit opt-in; leave it off while changing filters or splitting configurations. Partial, truncated, rate-limited or inaccessible scans must not be treated as proof that an asset disappeared and do not authorize cleanup of incomplete scope. Complete scans reconcile only the scope actually covered. Another configuration's association prevents deletion, and manually owned inventory survives detachment.

**Disable auto-sync** deletes the selected configuration and detaches its associations; it does not blanket-delete inventory. Retained or manually adopted assets stay visible. Other configurations continue to protect their associated records. Inspect run/provenance history before deleting anything manually.

## Deployment activation and rollback

Apply migration 111 before the new API reads or writes statistics. Upgrade the
entire API/dashboard fleet before saving owner selections: older validators do
not recognize them. Keep this label off during mixed-version rollout; existing
settings and ownerless dimension hashes remain unchanged. No ownership backfill
is performed.

For an installation upgrading to multiple configurations, migration leaves activation off. As a system administrator:

1. Deploy the new API fleet, drain every old worker, then deploy and verify the fencing-aware worker image.
2. Activate from **System settings**, or `POST /api/v1/admin/auto-sync/activation` with `{"workers_drained":true,"worker_image_verified":true}`. These are operator attestations; the API cannot inspect your external fleet. The activation card disappears afterward.
3. After activation, never return old API/worker versions to the installation. Roll forward or restore a pre-activation backup; changing image tags back is insufficient.

Before starting a standard Compose installation, populate both CertOps encryption keys as described in [Configuration](CONFIGURATION.md). Compose enables CertOps by default; an inventory-only first task does not bypass startup requirements. Keep the configured keys with protected backups.
