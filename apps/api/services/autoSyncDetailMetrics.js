"use strict";
const { pool } = require("../db/database");
const { OPTIONAL_LABELS, KNOWN_KINDS, effectiveMetricSettings } = require("./autoSyncMetricLabels");

function counter(value) {
  const number = Number(value);
  if (value === null || value === undefined || String(value).trim() === "" || !Number.isSafeInteger(number) || number < 0)
    throw new Error("Invalid auto-sync breakdown counter");
  return number;
}
async function detailedSamples() {
  const { rows } = await pool.query(`SELECT c.id AS configuration_id, c.provider,
    c.connection_key AS configuration_name, c.metrics_settings,
    s.kind, s.asset_name, s.project, s.group_name, s.items_created_total,
    EXTRACT(EPOCH FROM s.last_created_at) AS last_created
    FROM auto_sync_creation_stats s JOIN auto_sync_configs c ON c.id = s.config_id
    WHERE c.metrics_settings->>'enabled' = 'true'
    ORDER BY c.id, s.dimension_key`);
  const samples = new Map();
  for (const row of rows) {
    const settings = effectiveMetricSettings(row.metrics_settings);
    if (!settings.enabled) continue;
    // A new selection gets a distinct series, even when optional values are blank.
    // Configuration identity is mandatory so deletion cannot subtract from another config's counter.
    const labels = { provider: row.provider, configuration_id: row.configuration_id,
      label_set: settings.labels.join(",") };
    for (const label of OPTIONAL_LABELS) labels[label] = settings.labels.includes(label)
      ? label === "monitoring_group" ? settings.monitoring_group
        : label === "group" ? row.group_name : row[label]
      : "";
    const timestamp = Number(row.last_created);
    if (row.last_created === null || row.last_created === undefined || String(row.last_created).trim() === "" || !Number.isFinite(timestamp) || timestamp < 0)
      throw new Error("Invalid auto-sync creation timestamp");
    const key = JSON.stringify(labels);
    const existing = samples.get(key) || { labels, value: 0, timestamp: 0 };
    existing.value = counter(existing.value + counter(row.items_created_total));
    existing.timestamp = Math.max(existing.timestamp, timestamp);
    samples.set(key, existing);
  }
  return [...samples.values()];
}
function registerAutoSyncDetailMetrics(register, providers) {
  const kindName = "auto_sync_items_created_by_kind_total";
  if (!register.getSingleMetric(kindName)) register.registerMetric({
    name: kindName, type: "counter", help: "Committed auto-sync creations by asset kind since breakdown instrumentation was enabled", aggregator: "max",
    async get() {
      const { rows } = await pool.query("SELECT provider, kind, items_created_total FROM auto_sync_kind_stats ORDER BY provider, kind");
      const values = new Map();
      const add = (provider, kind, value) => values.set(JSON.stringify([provider, kind]), { labels: { provider, kind }, value });
      for (const provider of providers) {
        add(provider, "other", 0);
        for (const kind of KNOWN_KINDS) {
          const owner = kind.startsWith("azure-ad-") ? "azure-ad" : kind.split("-")[0];
          if (owner === provider) add(provider, kind, 0);
        }
      }
      for (const row of rows) add(row.provider, row.kind, counter(row.items_created_total));
      return { name: this.name, help: this.help, type: this.type, values: [...values.values()] };
    },
  });
  for (const definition of [
    { name: "auto_sync_items_created_detailed_total", type: "counter", help: "Opt-in committed auto-sync creations with selected configuration and asset metadata" },
    { name: "auto_sync_last_creation_timestamp_seconds", type: "gauge", help: "Unix timestamp of the latest committed creation with selected metadata; supports first-scrape detection" },
  ]) {
    if (register.getSingleMetric(definition.name)) continue;
    register.registerMetric({ ...definition, aggregator: "max",
      async get() {
        const samples = await detailedSamples();
        return { name: this.name, help: this.help, type: this.type,
          values: samples.map(sample => ({ labels: sample.labels, value: this.type === "counter" ? sample.value : sample.timestamp })) };
      },
    });
  }
}
module.exports = { registerAutoSyncDetailMetrics };
