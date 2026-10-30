"use strict";

// Canonical, unapplied numbering for integration of the concurrently open PRs.
// Reservations never install another PR's schema or alias an applied ledger.
const reservations = Object.freeze({
  81: "auto_sync_metric_labels", // released main (#513)
  82: "auto_sync_system_metrics", // released main (#516)
  83: "certops_material_providers", // #460
  84: "recipient_channel_verification", // #461
  85: "weekly_digest_recipient_claim_token", // #461
  86: "pagerduty_incident_lifecycle", // #496
  87: "certops_distribution_lifecycle", // #498
  88: "certops_distribution_incident_delivery", // #498
  89: "certops_stable_consumer_discovery", // #498
  90: "certops_material_cleanup", // #498
  91: "certops_consumer_verification_failures", // #498
  92: "certops_distribution_resolution_delivery", // #498
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
