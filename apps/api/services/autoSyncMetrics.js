"use strict";

const { pool } = require("../db/database");

const { registerAutoSyncDetailMetrics } = require("./autoSyncDetailMetrics");

const METRIC_NAME = "auto_sync_items_created_total";
const METRIC_HELP =
  "Inventory items created by auto-sync since instrumentation was enabled, by provider";
const OUTCOMES = ["success", "partial", "failed", "superseded"];

function registerRunMetrics(register, providers) {
  const definitions = [
    {
      name: "auto_sync_enabled_configurations", type: "gauge",
      help: "Currently enabled auto-sync configurations by provider; use to scope freshness alerts",
      sql: "SELECT provider, COUNT(*) AS value FROM auto_sync_configs WHERE enabled = TRUE GROUP BY provider ORDER BY provider",
      labels: providers.map(provider => ({ provider })),
    },
    {
      name: "auto_sync_run_outcomes_total", type: "counter",
      help: "Committed terminal auto-sync runs since instrumentation was enabled, by provider and status",
      sql: "SELECT provider, status, runs_total AS value FROM auto_sync_run_outcome_stats ORDER BY provider, status",
      labels: providers.flatMap(provider => OUTCOMES.map(status => ({ provider, status }))),
    },
    ...["attempt", "success"].map(kind => ({
      name: `auto_sync_last_${kind}_timestamp_seconds`, type: "gauge",
      help: `Unix timestamp of the latest auto-sync ${kind === "attempt" ? "run start" : "fully successful completion"}; zero if not observed since instrumentation was enabled`,
      sql: `SELECT provider, COALESCE(EXTRACT(EPOCH FROM last_${kind}_at), 0) AS value FROM auto_sync_run_freshness ORDER BY provider`,
      labels: providers.map(provider => ({ provider })),
    })),
  ];
  for (const definition of definitions) {
    if (register.getSingleMetric(definition.name)) continue;
    register.registerMetric({
      name: definition.name, type: definition.type, help: definition.help,
      async get() {
        const { rows } = await pool.query(definition.sql);
        const key = labels => JSON.stringify(labels);
        const samples = new Map(definition.labels.map(labels => [key(labels), { labels, value: 0 }]));
        for (const row of rows) {
          const labels = { provider: row.provider };
          if (definition.type === "counter") {
            if (!OUTCOMES.includes(row.status)) throw new Error("Invalid auto-sync run outcome");
            labels.status = row.status;
          }
          const value = Number(row.value);
          if (row.value === null || row.value === undefined || String(row.value).trim() === "" ||
              !Number.isFinite(value) || value < 0 ||
              (definition.type === "counter" && !Number.isSafeInteger(value))) {
            throw new Error("Invalid auto-sync run metric value");
          }
          samples.set(key(labels), { labels, value });
        }
        return { name: this.name, help: this.help, type: this.type, aggregator: "max",
          values: [...samples.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, sample]) => sample) };
      },
    });
  }
}

/**
 * Register an installation-wide counter collected directly from PostgreSQL.
 * Each scrape gets its own snapshot; there is no process-local counter to
 * reset, shared sample buffer, or worker Pushgateway publication to lose.
 * Database/validation errors reject the scrape instead of fabricating zero.
 * Replicas expose copies of the same total, so consumers must not sum them.
 */
function registerAutoSyncMetrics(register, { providers = ["github", "gitlab"] } = {}) {
  registerRunMetrics(register, [...new Set(providers)]);
  registerAutoSyncDetailMetrics(register, [...new Set(providers)]);
  const existing = register.getSingleMetric(METRIC_NAME);
  if (existing) return existing;

  const zeroProviders = [...new Set(providers)];
  const metric = {
    name: METRIC_NAME,
    help: METRIC_HELP,
    type: "counter",
    async get() {
      const { rows } = await pool.query(
        "SELECT provider, items_created_total FROM auto_sync_provider_stats ORDER BY provider",
      );
      // Include known providers before their first creation, and preserve
      // stored totals even if a provider has no remaining configuration.
      const totals = new Map(zeroProviders.map((provider) => [provider, 0]));
      for (const row of rows) {
        const raw = row.items_created_total;
        const value = Number(raw);
        if (
          raw === null || raw === undefined || String(raw).trim() === "" ||
          !Number.isSafeInteger(value) || value < 0
        ) {
          throw new Error("Invalid auto-sync creation total");
        }
        totals.set(row.provider, value);
      }
      return {
        // prom-client normalizes counter names for OpenMetrics exposition.
        name: this.name,
        help: this.help,
        type: "counter",
        aggregator: "max",
        values: [...totals.entries()]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([provider, value]) => ({ labels: { provider }, value })),
      };
    },
  };
  register.registerMetric(metric);
  return metric;
}

module.exports = { registerAutoSyncMetrics };
