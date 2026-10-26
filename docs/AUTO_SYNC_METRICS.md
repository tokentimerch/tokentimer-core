# Auto-sync metrics and alerts

Apply migrations 79–80 and enable `ENABLE_METRICS=true` on the API. The API reads
committed database state on each `/metrics` scrape; these metrics do not require
the worker's Pushgateway. Retrying an import, updating an existing asset, or
restarting an API does not create a new creation event.

## What the metrics mean

- `auto_sync_items_created_total{provider}` counts newly committed auto-sync
  inventory rows since migration 79. Manual imports and adoption are excluded.
  Deletion does not subtract from the total. Recreating a deleted object is a
  new inventory creation and counts again.
- `auto_sync_run_outcomes_total{provider,status}` counts each run's first
  committed terminal transition since migration 80. Status is `success`,
  `partial`, `failed`, or `superseded`. A crash followed by lease recovery is
  recorded as superseded, not silently turned into a failed run.
- `auto_sync_last_attempt_timestamp_seconds{provider}` is the latest run start.
  `auto_sync_last_success_timestamp_seconds{provider}` is the latest fully
  successful completion. Partial runs do not refresh success. Zero means no
  observation, not an attempt on 1 January 1970.
- `auto_sync_enabled_configurations{provider}` is the current enabled-connection
  count. It returns to zero when the provider's connections are disabled or
  deleted, while its historical totals and timestamps remain.

No historical activity is backfilled. All seven supported providers are exposed
in Enterprise, and GitHub/GitLab in Core, including zero values before use.

## Install the opt-in examples

For a Prometheus Operator installation, apply the dedicated example **after**
your normal Core values:

```sh
helm upgrade --install tokentimer ./deploy/helm \
  -f your-values.yaml \
  -f deploy/helm/examples/values-auto-sync-alerts.yaml
```

Set the example's `installation` replacement to a unique identifier for this
database. All replicas for that database must use the same installation label,
scrape job and namespace. Different databases need different installation labels.
Change the `release` labels to match your Prometheus Operator's ServiceMonitor
and PrometheusRule selectors. Confirm that Prometheus discovers the targets and
loads the rules; enabling `prometheusRules` with an empty `groups` array installs
no rules. Enterprise uses `tokentimer.monitoring`; its dedicated example uses
that nesting already.

For standalone Prometheus, load
[`deploy/prometheus/auto-sync.rules.yaml`](../deploy/prometheus/auto-sync.rules.yaml)
through `rule_files` and attach a unique installation label in `static_configs`.
Inspect your actual target labels and change the `TokenTimerAPIDown` job selector
from `tokentimer-api` if needed. `up` detects scrape failures of discovered
targets; monitor service discovery separately if a target can disappear entirely.

## Alert on newly created assets

The informational example uses:

```promql
max by (installation, namespace, job, provider) (
  increase(auto_sync_items_created_total[15m])
) > 0
```

This detects **observed new creations in a rolling 15-minute window**. It does
not alert merely because a lifetime total is nonzero. Establish a baseline with
at least two successful scrapes before relying on increases. Creations that
already happened before the first sample cannot be inferred from that sample.
Use a window comfortably longer than the scrape interval, and monitor scrape
failures separately.

Every API replica exposes a copy of the same database total. Prefer a stable
scrape target for each database. The example takes the maximum of the per-target
increases to avoid doubling replica copies; it never sums them. Target churn
still needs a new per-target baseline, and changes during an unobserved interval
may be missed. Preserve installation labels when aggregating multiple databases.

Prometheus extrapolates `increase()` to the window boundaries, so its value can
be fractional even when the database counted one creation. Use `> 0` for activity
or tune a larger threshold for a volume alert; use run history for exact event
accounting. This is one active alert per provider, not a notification per asset.
It clears when the window contains no observed increase. Alertmanager grouping,
repeat interval and routing determine notifications. The example has severity
`info` and is opt-in; omit it if routine discovery should not notify anyone.

## Health alert expectations

- `AutoSyncProviderFailures`: at least three observed failed outcomes in three
  hours, no persisted full success in that window, and an enabled connection.
  It uses the per-target maximum minus minimum, excludes targets with counter
  resets, then deduplicates replicas with a maximum. No extrapolation is used.
  Scrape gaps, target replacement and resets may undercount; use run history
  for exact accounting. A success already present at the first scrape suppresses
  the alert through its persisted timestamp.
  Partial and superseded outcomes are not counted as failed. This is an
  installation/provider aggregate; another connection's success can suppress it.
- `AutoSyncNotRunning`: an enabled provider previously started, but its latest
  attempt is older than 25 hours.
- `AutoSyncNoRecentSuccess`: an enabled provider previously succeeded, but its
  latest full success is older than 25 hours. Attempts can still be occurring.
- `AutoSyncNeverStarted` and `AutoSyncNeverSucceeded`: an enabled provider has
  no observed attempt or full success, respectively, for 25 hours of continuous
  alert evaluation. New or unused providers do not page immediately. As with
  other `for` timers, evaluation interruptions can restart this grace period.
- `TokenTimerAPIDown`: the API scrape has failed for two minutes. Database read
  or validation errors can return HTTP 500; connection failures may terminate
  the API. Both are scrape failures, not evidence of zero activity.

**Change 25 hours to exceed your longest configured schedule**, including weekly
or monthly connections, and tune the failure window for your run frequency.
Health alerts stop when no connections for that provider remain enabled. These
provider-level metrics cannot prove that every connection is healthy; inspect
individual connection history when one healthy connection could mask another.
