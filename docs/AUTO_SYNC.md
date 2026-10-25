# Import assets and keep them current

Use one configuration per provider connection. Core supports scheduled GitHub and GitLab scans; Enterprise adds entitled providers. Cloud performs one-time scans and does not offer scheduled provider sync.

## Connect, preview and import

1. Open **Import tokens** in the intended workspace. For a file, select the file option and review the parsed rows. For GitHub/GitLab, provide the instance URL and a suitably scoped credential, then scan.
2. Apply filters and review the preview. A preview has not saved inventory. Select the intended rows, confirm **Import selected**, and wait for the result.
3. Return to the same workspace inventory. Check the imported record's source, expiration and recipients before enabling unattended updates.

TokenTimer tracks metadata rather than the secret value. A one-time scan does not create a saved sync connection; an explicitly enabled self-hosted sync keeps its credentials encrypted on your infrastructure.

## Enable a schedule

Use **Enable auto-sync**, give the configuration a recognizable name, then choose frequency, time and timezone. Select the notification groups for assets created by future runs. Existing assets keep their own group assignments.

The worker's polling cadence (`WORKER_AUTO_SYNC_CRON` in Compose or `worker.cronjobs.autoSync.schedule` in Helm) determines when due configurations are checked. It is separate from each connection's own schedule. Confirm the configured worker is running.

Use **Manage auto-sync** to review or edit a saved connection. **Run now** requests a scan; repeated clicks while one is active coalesce into one later run. Disabled configurations do not run queued requests until enabled.

## Verify an update

1. Open the selected configuration's run history. Check completion, partial/error status and separate created/updated counts. **Earlier runs** loads older results.
2. Inspect the same inventory record after a provider-side metadata change and successful run. Match its source identity, not just a name. Two previews are not evidence of a persisted update.
3. In asset details, review **Auto-sync** ownership/configuration and association history where present. Manual assets without sync provenance have no such section.

Overlapping configurations may discover one provider identity and share its inventory record. Changing a name or schedule preserves the configuration. Changing credentials, scope or scan settings supersedes active work and queues a replacement when enabled.

## Cleanup and removal

Enable destructive cleanup only when it matches your retention policy. Partial, truncated, rate-limited or inaccessible scans must not be treated as proof that an asset disappeared. Complete scans reconcile only the scope actually covered.

**Disable auto-sync** deletes the selected configuration and detaches its associations; it does not blanket-delete inventory. Retained or manually adopted assets stay visible. Other configurations continue to protect their associated records. Inspect run/provenance history before deleting anything manually.

## Deployment activation and rollback

For an installation upgrading to multiple configurations, migration leaves activation off. As a system administrator:

1. Deploy the new API fleet, drain every old worker, then deploy and verify the fencing-aware worker image.
2. Activate from **System settings**, or `POST /api/v1/admin/auto-sync/activation` with `{"workers_drained":true,"worker_image_verified":true}`. These are operator attestations; the API cannot inspect your external fleet. The activation card disappears afterward.
3. After activation, never return old API/worker versions to the installation. Roll forward or restore a pre-activation backup; changing image tags back is insufficient.

Before starting a standard Compose installation, populate both CertOps encryption keys as described in [Configuration](CONFIGURATION.md). Compose enables CertOps by default; an inventory-only first task does not bypass startup requirements. Keep the configured keys with protected backups.
