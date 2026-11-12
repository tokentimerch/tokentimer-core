"use strict";

// Canonical, unapplied numbering for integration of the concurrently open PRs.
// Reservations never install another PR's schema or alias an applied ledger.
const reservations = Object.freeze({
  81: "auto_sync_metric_labels",
  82: "auto_sync_system_metrics",
  83: "certops_material_providers",
  84: "recipient_channel_verification",
  85: "weekly_digest_recipient_claim_token",
  86: "certops_distribution_lifecycle",
  87: "certops_distribution_incident_delivery",
  88: "certops_stable_consumer_discovery",
  89: "certops_material_cleanup",
  90: "certops_consumer_verification_failures",
  91: "certops_distribution_resolution_delivery",
  92: "pagerduty_incident_lifecycle",
  93: "pagerduty_resolution_reason",
  94: "pagerduty_operator_actions",
  95: "remove_pagerduty_rest_lookup",
  96: "certops_consumer_staging",
  97: "certops_review_authority_epochs",
  98: "certops_manual_rollout_authority",
  99: "operator_connections",
  100: "operator_enrollment_grants",
  101: "operator_action_requests",
  102: "operator_oauth",
  103: "operator_connection_lifetimes",
  104: "operator_inventory",
  105: "operator_oauth_retention",
  106: "operator_issuance",
  107: "certops_issuance_job_identity",
  108: "certops_issuance_identity_transfer",
  109: "certops_period_creator_delete",
  110: "recipient_member_verification",
  111: "auto_sync_owner_username",
  112: "agent_credential_rotations",
  113: "agent_credential_rotation_ack",
});

function validateMigrationReservations(migrations) {
  const versions = new Set(), names = new Set();
  for (const migration of migrations) {
    if (versions.has(migration.version) || names.has(migration.name)) throw new Error("Duplicate Core migration version or name");
    versions.add(migration.version);
    names.add(migration.name);
    const reserved = Object.entries(reservations).find(([, name]) => name === migration.name);
    if ((reservations[migration.version] && reservations[migration.version] !== migration.name) ||
      (reserved && Number(reserved[0]) !== migration.version)) {
      throw new Error(`Conflicting canonical Core migration ${migration.version}/${migration.name}; see docs/migrations/open-pr-numbering.md`);
    }
  }
}

module.exports = { reservations, validateMigrationReservations };
