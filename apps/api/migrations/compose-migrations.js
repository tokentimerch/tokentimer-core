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
  const tail = recorded.filter(entry => entry.version >= 70).slice().sort((a, b) => a.version - b.version);
  if (new Set(migrations.map(entry => entry.name)).size !== migrations.length ||
    new Set(migrations.map(entry => entry.version)).size !== migrations.length ||
    new Set(recorded.map(entry => entry.name)).size !== recorded.length ||
    tail.some((row,index) => row.version !== 70 + index))
    throw new Error("Unsupported Core migration history: duplicate or noncontiguous entries");
  const order = histories.find(names => tail.filter(row => row.version < 77).every((row, offset) =>
    row.name === names[offset]));
  if (!order) throw new Error(`Unsupported Core migration history at version ${tail[0]?.version}`);
  const onboarding = tail.find(row => row.version === 77);
  if (onboarding && !migrations.some(entry => entry.version === 77 && entry.name === onboarding.name))
    throw new Error("Unsupported Core migration history at version 77");
  // 78+ includes published main and independently applied PR previews. Identify
  // those entries by their exact registered names, never by a numeric alias.
  // Providers at 78/79, PagerDuty at 79/81, recipient/digest at 81/82 and
  // lifecycle at 81-85 are preserved. Only missing SQL receives a new number.
  const extensionRows = tail.filter(row => row.version >= 78);
  const extensions = migrations.filter(entry => entry.version >= 78).sort((a,b)=>a.version-b.version);
  const known = new Set(extensions.map(entry => entry.name));
  if (extensionRows.some(row => !known.has(row.name)))
    throw new Error("Unsupported Core migration history: unknown extension");
  const dependencies = {
    auto_sync_run_metrics: ["auto_sync_provider_stats"],
    auto_sync_metric_labels: ["auto_sync_run_metrics"],
    certops_distribution_lifecycle: ["certops_installed_file_distribution"],
    certops_distribution_incident_delivery: ["certops_distribution_lifecycle"],
    certops_material_cleanup: ["certops_distribution_lifecycle"],
    certops_consumer_verification_failures: ["certops_material_cleanup"],
    weekly_digest_recipient_claim_token: ["recipient_channel_verification"],
    certops_distribution_resolution_delivery: ["certops_distribution_incident_delivery"],
  };
  const seen = new Set();
  for (const row of extensionRows) {
    if ((dependencies[row.name] || []).some(name => !seen.has(name)))
      throw new Error(`Incomplete Core migration dependency: ${row.name}`);
    seen.add(row.name);
  }
  const versions = new Map(extensionRows.map(row => [row.name,row.version]));
  let nextVersion = Math.max(77,...extensionRows.map(row=>row.version)) + 1;
  for (const entry of extensions) if (!versions.has(entry.name)) versions.set(entry.name,nextVersion++);
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
  return migrations.map(entry => replacements.get(entry.name) ||
    (versions.has(entry.name) ? {...entry,version:versions.get(entry.name)} : entry)).sort((a, b) => a.version - b.version);
}

module.exports = { composeMigrations };
