"use strict";

const { pool } = require("../db/database");

const METRIC_NAME = "auto_sync_items_created_total";
const METRIC_HELP =
  "Inventory items created by auto-sync since instrumentation was enabled, by provider";

/**
 * Register an installation-wide counter collected directly from PostgreSQL.
 * Each scrape gets its own snapshot; there is no process-local counter to
 * reset, shared sample buffer, or worker Pushgateway publication to lose.
 * Database/validation errors reject the scrape instead of fabricating zero.
 * Replicas expose copies of the same total, so consumers must not sum them.
 */
function registerAutoSyncMetrics(register, { providers = ["github", "gitlab"] } = {}) {
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
