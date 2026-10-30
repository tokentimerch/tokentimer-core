"use strict";

// Only unapplied migrations move. Never rename or renumber an applied row.
const ENROLLMENT = "certops_certificate_enrollments";
const EVIDENCE = "certops_adcs_evidence_types";
const ISSUER = "certops_profile_issuer";
const ALERT = "certops_job_alert_context";
const DISTRIBUTION = "certops_material_distribution";
const REVIEW = "certops_distribution_review";
const TRANSFER = "certops_distribution_transfer";
const canonical = [ENROLLMENT, EVIDENCE, ISSUER, ALERT, DISTRIBUTION, REVIEW, TRANSFER];
const histories = [
  canonical,
  [ENROLLMENT, EVIDENCE, ISSUER, DISTRIBUTION, REVIEW, TRANSFER, ALERT],
  [DISTRIBUTION, REVIEW, TRANSFER, ENROLLMENT, EVIDENCE, ISSUER, ALERT],
  [ENROLLMENT, DISTRIBUTION, REVIEW, TRANSFER, EVIDENCE, ISSUER, ALERT],
];

function composeMigrations(migrations, recorded = []) {
  for (const [offset, name] of canonical.entries()) {
    const matches = migrations.filter(entry => entry.name === name);
    if (matches.length !== 1 || matches[0].version !== 70 + offset) {
      throw new Error(`Missing or inconsistent pinned Core migration: ${name}`);
    }
  }
  // Released main owns 78 (installed assurance) and 79-82 (auto-sync).
  // Providers append at 83. Preserve the known unreleased PR histories:
  // providers at 78, then installed at 79; or installed at 78, providers at 79.
  // Only unapplied entries move, in these explicitly recognized sequences.
  const installed = "certops_installed_file_distribution", providers = "certops_material_providers";
  const telemetry = ["auto_sync_provider_stats", "auto_sync_run_metrics", "auto_sync_metric_labels", "auto_sync_system_metrics"].filter(name => migrations.some(entry => entry.name === name));
  const canonicalExtensions = [installed, ...telemetry, providers];
  const applied = recorded.filter(entry => entry.version >= 78 && entry.version < 78 + canonicalExtensions.length).slice().sort((a, b) => a.version - b.version);
  // Known provider positions: 78/79, 81 (66f94086) and 82 (6d685f95).
  // Append later telemetry after those applied prefixes, never relabel them.
  const previewOrders = [0, 1, 3, 4].map(index => {
    const names = [installed, ...telemetry];
    names.splice(index, 0, providers);
    return names;
  });
  const extensionOrder = [canonicalExtensions, ...previewOrders]
    .find(names => applied.every((row, offset) => row.version === 78 + offset && row.name === names[offset]));
  if (new Set(migrations.map(entry => entry.version)).size !== migrations.length)
    throw new Error("Duplicate Core migration version");
  const extensions = migrations.some(entry => entry.name === installed) && migrations.some(entry => entry.name === providers) && extensionOrder
    ? new Map(extensionOrder.map((name, offset) => {
      const entry = migrations.find(migration => migration.name === name);
      return [name, { ...entry, version: 78 + offset }];
    })) : new Map();
  const registry = migrations.map(entry => extensions.get(entry.name) || entry);
  if (new Set(registry.map(entry => entry.version)).size !== registry.length)
    throw new Error("Duplicate Core migration version");
  const tail = recorded.filter(entry => entry.version >= 70).slice().sort((a, b) => a.version - b.version);
  const order = histories.find(names => tail.every((row, offset) => {
    if (offset < names.length) return row.version === 70 + offset && row.name === names[offset];
    return row.version === 70 + offset && registry.some(entry => entry.version === row.version && entry.name === row.name);
  }));
  if (!order) throw new Error(`Unsupported Core migration history at version ${tail[0]?.version}`);
  const distributionFirst = order[0] === DISTRIBUTION;
  const replacements = new Map(order.map((name, offset) => {
    const migration = migrations.find(entry => entry.name === name);
    // Preserve the SQL previously applied by the Enterprise preview adapter.
    const sql = distributionFirst && name === ENROLLMENT
      ? migration.sql.replace("'continue-enrollment', 'adcs-preflight'", "'continue-enrollment', 'adcs-preflight', 'deploy-from-store'")
      : distributionFirst && name === DISTRIBUTION
        ? migration.sql.replace("'continue-enrollment','adcs-preflight'", "'continue-enrollment'")
        : migration.sql;
    return [name, {...migration, version: 70 + offset, sql}];
  }));
  return registry.map(entry => replacements.get(entry.name) || entry).sort((a, b) => a.version - b.version);
}

module.exports = { composeMigrations };
