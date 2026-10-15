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
  const order = histories.find(names => tail.every((row, offset) => {
    if (offset < names.length) return row.version === 70 + offset && row.name === names[offset];
    return row.version === 70 + offset && migrations.some(entry => entry.version === row.version && entry.name === row.name);
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
  return migrations.map(entry => replacements.get(entry.name) || entry).sort((a, b) => a.version - b.version);
}

module.exports = { composeMigrations };
