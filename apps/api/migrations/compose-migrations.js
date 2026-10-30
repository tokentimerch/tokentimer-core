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
    const preview = `${row.version}:${row.name}`;
    return row.version === 70 + offset && (
      migrations.some(entry => entry.version === row.version && entry.name === row.name)
      || preview === "81:recipient_channel_verification"
      || preview === "82:weekly_digest_recipient_claim_token"
    );
  }));
  if (!order) {
    const collision = tail.find((row) =>
      row.version >= 81
      && row.name !== "auto_sync_metric_labels"
      && row.name !== "recipient_channel_verification"
      && row.name !== "weekly_digest_recipient_claim_token"
    );
    if (collision) {
      throw new Error(
        `Migration ${collision.version} ${collision.name} is not part of this build. Keep that applied row and allocate the next version after 83.`,
      );
    }
    throw new Error(`Unsupported Core migration history at version ${tail[0]?.version}`);
  }
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
  const composed = migrations.map(entry => replacements.get(entry.name) || entry).sort((a, b) => a.version - b.version);
  return applyRecipientPreview(composed, recorded);
}

function applyRecipientPreview(migrations, recorded) {
  const byVersion = new Map((recorded || []).map((row) => [row.version, row.name]));
  if (byVersion.get(81) !== "recipient_channel_verification") return migrations;
  if (byVersion.get(82) !== "weekly_digest_recipient_claim_token") return migrations;
  if (byVersion.get(78) !== "certops_installed_file_distribution") return migrations;
  if (byVersion.get(79) !== "auto_sync_provider_stats") return migrations;
  if (byVersion.get(80) !== "auto_sync_run_metrics") return migrations;
  const recipient = migrations.find((entry) => entry.name === "recipient_channel_verification");
  const digest = migrations.find((entry) => entry.name === "weekly_digest_recipient_claim_token");
  const labels = migrations.find((entry) => entry.name === "auto_sync_metric_labels");
  if (!recipient || !digest || !labels) return migrations;
  return migrations
    .filter((entry) => entry.name !== recipient.name && entry.name !== digest.name && entry.name !== labels.name)
    .concat([
      { ...recipient, version: 81 },
      { ...digest, version: 82 },
      { ...labels, version: 83 },
    ])
    .sort((a, b) => a.version - b.version);
}

module.exports = { composeMigrations };
