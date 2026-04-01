import client from "prom-client";

export const metricsRegister = new client.Registry();
// Ensure no default labels are applied implicitly
try {
  const env =
    process.env.ENVIRONMENT_SUFFIX || process.env.NODE_ENV || "unknown";
  metricsRegister.setDefaultLabels({ env });
} catch (_) {}
// Clear default registry (useful in dev/hot-reload to avoid duplicate registrations)
try {
  client.register.clear();
} catch (_) {}

// Removed collectDefaultMetrics to avoid including default Node/process metrics

export const gQueueDepth = new client.Gauge({
  name: "alerts_queue_depth",
  help: "Alert queue depth by status",
  labelNames: ["status"],
  registers: [metricsRegister],
});

export const gQueueDueNow = new client.Gauge({
  name: "alerts_queue_due_now",
  help: "Alerts due now (pending/failed and not under cooldown)",
  registers: [metricsRegister],
});

export const gCooldownInEffect = new client.Gauge({
  name: "alerts_cooldown_in_effect",
  help: "Count of alerts with active cooldown (next_attempt_at > now)",
  registers: [metricsRegister],
});

export const gRunnerUp = new client.Gauge({
  name: "runner_up",
  help: "Alert runner heartbeat by component",
  labelNames: ["component"],
  registers: [metricsRegister],
});

export const cDelivery = new client.Counter({
  name: "alerts_delivery_total",
  help: "Alert deliveries by channel/provider and status",
  labelNames: ["channel", "provider", "status"],
  registers: [metricsRegister],
});

export const cRetry = new client.Counter({
  name: "alerts_retry_total",
  help: "Retries by channel and kind (auto/manual)",
  labelNames: ["channel", "kind"],
  registers: [metricsRegister],
});

export const cDeniedHost = new client.Counter({
  name: "alerts_webhook_denied_host_total",
  help: "Denied webhook hosts (provider allowlist)",
  labelNames: ["provider", "host"],
  registers: [metricsRegister],
});

export const cLimitWarning = new client.Counter({
  name: "alerts_limit_warning_total",
  help: "80% limit warnings sent",
  labelNames: ["plan"],
  registers: [metricsRegister],
});

export const cChannelLimitWarning = new client.Counter({
  name: "alerts_channel_limit_warning_total",
  help: "80% per-channel limit warnings sent",
  labelNames: ["channel", "plan"],
  registers: [metricsRegister],
});

export const cLimitBlocked = new client.Counter({
  name: "alerts_limit_blocked_total",
  help: "Alerts blocked due to plan limits",
  labelNames: ["plan"],
  registers: [metricsRegister],
});

export const hLatency = new client.Histogram({
  name: "alerts_delivery_latency_seconds",
  help: "Delivery latency by channel and provider",
  labelNames: ["channel", "provider"],
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2, 5],
  registers: [metricsRegister],
});

export const hLimitUtilRatio = new client.Histogram({
  name: "alerts_limit_utilization_ratio",
  help: "Observed monthly utilization ratios (0..1+), by plan",
  labelNames: ["plan"],
  buckets: [0.2, 0.4, 0.6, 0.8, 1, 1.2],
  registers: [metricsRegister],
});

export const gMonthlyChannelUsage = new client.Gauge({
  name: "alerts_monthly_channel_usage",
  help: "Successful deliveries this month by channel (global)",
  labelNames: ["channel"],
  registers: [metricsRegister],
});

// Weekly digest metrics
export const cWeeklyDigestSent = new client.Counter({
  name: "weekly_digest_sent_total",
  help: "Weekly digests sent by channel and status",
  labelNames: ["channel", "status"],
  registers: [metricsRegister],
});

export const gWeeklyDigestProcessed = new client.Gauge({
  name: "weekly_digest_processed",
  help: "Count of workspaces/groups processed in last digest run",
  registers: [metricsRegister],
});

export const gWeeklyDigestTokensIncluded = new client.Gauge({
  name: "weekly_digest_tokens_included",
  help: "Average number of tokens included per digest",
  registers: [metricsRegister],
});

export const gWeeklyDigestLastRun = new client.Gauge({
  name: "weekly_digest_last_run_timestamp",
  help: "Unix timestamp of last successful weekly digest run",
  registers: [metricsRegister],
});

export const gWeeklyDigestLastRunSuccess = new client.Gauge({
  name: "weekly_digest_last_run_success",
  help: "Whether the last weekly digest run was successful (1) or failed (0)",
  registers: [metricsRegister],
});

// Centralized error counter for logger
export const cLogError = new client.Counter({
  name: "app_log_errors_total",
  help: "Count of error-level log events by service",
  labelNames: ["service"],
  registers: [metricsRegister],
});

export async function pushMetrics(job) {
  if (process.env.ENABLE_METRICS !== "true") return;
  const url = process.env.PUSHGATEWAY_URL;
  if (!url) return;
  const gateway = new client.Pushgateway(url, {}, metricsRegister);
  const groupings = job ? { worker: job } : {};
  await new Promise((resolve, reject) => {
    // pushAdd uses POST. Per Pushgateway docs, POST replaces series for metric
    // names that appear in this body (same grouping key) and leaves series for
    // metric names not in the body untouched. push (PUT) replaces the entire
    // grouping with the body only. This registry is the only Pushgateway path;
    // gauges, counters, and histograms are all pushed together with no separate
    // handling per metric type.
    gateway.pushAdd(
      { jobName: "tokentimer-alerts", groupings },
      (err, _resp, body) => (err ? reject(err) : resolve(body)),
    );
  });
}
