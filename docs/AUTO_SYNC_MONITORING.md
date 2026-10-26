# Alert on inventory created by auto-sync

Use Prometheus and your existing Alertmanager email receiver to notify operators
when auto-sync inserts new inventory. This is an installation-wide signal by
provider. It does not include token names or identify a particular workspace or
configuration, and it does not add a native discovery-email setting to TokenTimer.

## Counter semantics

The API's `/metrics` endpoint exposes:

```text
# TYPE auto_sync_items_created_total counter
auto_sync_items_created_total{provider="github"} 0
auto_sync_items_created_total{provider="gitlab"} 0
```

The counter records newly inserted inventory rows from auto-sync imports. Updating
an existing row, attaching it to another configuration, or importing it manually
does not count as a new auto-sync creation. A newly discovered row can represent
an older provider token: this measures creation in TokenTimer, not when GitLab or
another provider issued the credential.

The increment commits in the same database transaction as the import. Totals
survive API and worker restarts and are retained when tokens, configurations, run
history or workspaces are deleted. Committed creations still count if another
batch or a later stage of the run fails. A rolled-back import does not count.

Every API replica reads the same database totals. The metric has only a `provider`
label; the initial GitHub and GitLab series are present at zero before any new
creations. It is not a per-worker counter and is not sent through Pushgateway.

The counter starts at zero when its database migration is installed; previous
imports are not backfilled. Upgrade every API writer and use the current fenced
auto-sync worker before relying on complete counting. During a mixed-version
rollout, an older API can commit creations without incrementing this metric.
Restoring an older database backup can also move the total backwards; treat
that recovery as a new monitoring baseline rather than an exact discovery count.

## Enable and scrape the metric

1. Enable API metrics with `ENABLE_METRICS=true`. For Helm, set
   `monitoring.metrics.enabled: true`.
2. Make the API's internal `/metrics` endpoint reachable by Prometheus. With the
   Helm NetworkPolicy enabled, set `networkPolicy.monitoringNamespace` to the
   namespace containing Prometheus. Use the internal API Service rather than
   exposing this endpoint publicly for this integration.
3. Add a **dedicated scrape job with one stable target per TokenTimer database**.
   In Kubernetes, use the API Service DNS name, with a stable `instance` label.
   A request can reach any API replica because all replicas report the same total.
4. Keep the ordinary per-pod API ServiceMonitor for HTTP/process metrics. Restrict
   the dedicated job to `auto_sync_items_created_total`; use its `job` and
   `deployment` labels in discovery-alert queries. Do not sum the copies of this
   database-wide counter scraped from separate API pods, and do not relabel
   several pod targets into a single time series.

The [standalone Prometheus example](../deploy/helm/examples/prometheus-auto-sync-created.yaml)
scrapes every 30 seconds with a 10-second timeout. Its target assumes a Helm
release and namespace both named `tokentimer`, using the default API Service port
4000. Change the Service address and the `deployment`/`instance` labels for your
installation. Keep the logical labels stable across API rollouts; give different
databases different identities. Finish rolling out API versions that expose this
metric before enabling the alert.

This example is Prometheus configuration, not TokenTimer Helm values. Merge its
`scrape_configs` entry into your existing Prometheus configuration. For a
Prometheus Operator deployment, supply that entry through the operator's
[additional scrape configuration](https://prometheus-operator.dev/docs/api-reference/api/#monitoring.coreos.com/v1.PrometheusSpec)
or your monitoring chart's equivalent. Leave TokenTimer's existing ServiceMonitor
unchanged. No Pushgateway setting is needed for this counter.

## Alert on a recent creation

For the example job and deployment, a GitLab creation alert uses:

```promql
increase(auto_sync_items_created_total{
  job="tokentimer-auto-sync-metrics",
  deployment="tokentimer-production",
  provider="gitlab"
}[15m]) > 0
```

The [example rule file](../deploy/helm/examples/auto-sync-created.rules.yaml)
contains this alert and two collection-health alerts. For standalone Prometheus,
load the file with `rule_files`. For TokenTimer's Helm `PrometheusRule`, copy its
`groups` list into `monitoring.prometheusRules.groups`, enable
`monitoring.prometheusRules.enabled`, and set the labels required by your
Prometheus rule selector. Merge with any existing groups rather than replacing
them. Update the job/deployment selectors in the rules whenever you customize the
scrape configuration.

Evaluate the rules every 30 seconds. The discovery alert has no pending delay;
the 15-minute lookback keeps an observed increase visible across multiple
evaluations. Route `TokenTimerAutoSyncCreated` through your Alertmanager email
receiver. Alertmanager's grouping and repeat settings control notifications;
closely spaced discoveries can keep one alert firing. An alert value is an
extrapolated increase, so use it as a signal that inventory was added rather than
an exact count for the email. The metric cannot supply the newly added token names.

### Monitor collection separately

The example rules also check:

- `up == 0` for two minutes: the dedicated API scrape or its database-backed
  collection is failing.
- No GitLab counter samples for five minutes: the scrape job, metric, or expected
  provider series is missing, including a deployment with metrics disabled.

A successful scrape with an unchanged counter does not prove that scheduled
syncs are running. Check configuration run history and the existing worker
failure/liveness monitoring as well. Zero discoveries can be normal, so it is
not itself a sync-failure condition.

Each scrape reads the database. A collection error fails the scrape instead of
returning a cached total or a zero fallback. `/metrics` returns HTTP 500 when the
process remains available; the existing database connection-error handler can
terminate the API on connection failures. The scrape-health alert covers both
outcomes.

## Establish a baseline and verify delivery

1. After installation or upgrade, confirm a successful scrape and the expected
   provider series. For a new counter, let Prometheus record its zero value before
   running a scan expected to create inventory. For an existing total, let it
   record that current value as the baseline.
2. Run a sync that imports one genuinely new inventory row. Confirm that the
   counter increases and that `TokenTimerAutoSyncCreated` reaches Alertmanager
   and the intended email receiver.
3. Run the same sync again without adding provider objects. The counter should
   stay unchanged. The alert remains active until the original increase leaves
   its lookback window; that does not indicate another discovery.
4. Verify the two health rules in your monitoring environment before relying on
   the notification.

Prometheus must observe a baseline and a later value to infer the usual counter
increase. If the first sample already includes a creation, `increase()` cannot
recover it from that sample alone. Persistent totals prevent process restarts
from losing the count, but a monitoring outage longer than the query's useful
history can still miss the notification. Increasing the lookback trades a longer
detection window for longer-lived alerts; it does not reconstruct event timing.

This is a monitoring signal, not a durable per-token notification feed. For a
list of additions or a separate notification for every event, use persisted
inventory/run data with a consumer that tracks its own progress and retries.

See the Prometheus references for
[`increase()`](https://prometheus.io/docs/prometheus/latest/querying/functions/#increase),
[initial zero values](https://prometheus.io/docs/practices/instrumentation/#avoid-missing-metrics),
and [Alertmanager notification timing](https://prometheus.io/docs/alerting/latest/configuration/#route).
