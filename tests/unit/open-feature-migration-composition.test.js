"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { migrations } = require("../../apps/api/migrations/migrate");
const {
  composeMigrations,
} = require("../../apps/api/migrations/compose-migrations");
const tail = [
  [78, "certops_installed_file_distribution"],
  [79, "auto_sync_provider_stats"],
  [80, "auto_sync_run_metrics"],
  [81, "auto_sync_metric_labels"],
  [82, "auto_sync_system_metrics"],
  [83, "certops_material_providers"],
  [84, "recipient_channel_verification"],
  [85, "weekly_digest_recipient_claim_token"],
  [86, "certops_distribution_lifecycle"],
  [87, "certops_distribution_incident_delivery"],
  [88, "certops_stable_consumer_discovery"],
  [89, "certops_material_cleanup"],
  [90, "certops_consumer_verification_failures"],
  [91, "certops_distribution_resolution_delivery"],
  [92, "pagerduty_incident_lifecycle"],
  [93, "pagerduty_resolution_reason"],
  [94, "pagerduty_operator_actions"],
  [95, "remove_pagerduty_rest_lookup"],
  [96, "certops_consumer_staging"],
  [97, "certops_review_authority_epochs"],
];
const names = new Set(migrations.map((row) => row.name));
const combined = [
  ...migrations,
  ...tail
    .filter(([, name]) => !names.has(name))
    .map(([version, name]) => ({ version, name, sql: "SELECT 1;" })),
];
const prefix = migrations
  .filter((row) => row.version < 78)
  .map(({ version, name }) => ({ version, name, executed_at: "unchanged" }));
const main = [
  ...prefix,
  ...tail
    .filter(([version]) => version <= 82)
    .map(([version, name]) => ({ version, name, executed_at: "unchanged" })),
];
test("the feature build retains every released main migration identity", () => {
  const plan = composeMigrations(migrations, main);
  for (const row of main)
    assert.equal(
      plan.find((entry) => entry.version === row.version)?.name,
      row.name,
    );
});
test("all feature schemas coexist without duplicate identities or no-op reservations", () => {
  const plan = composeMigrations(combined, main);
  assert.equal(new Set(plan.map((row) => row.name)).size, plan.length);
  assert.equal(new Set(plan.map((row) => row.version)).size, plan.length);
  for (const [version, name] of tail)
    assert.equal(plan.find((row) => row.name === name)?.version, version);
});
for (const alreadyApplied of [[], [83], [84, 85], [92], [92, 93], [83, 84, 85, 92, 93]])
  test(
    "independent applied feature rows survive later companion integration: " +
      alreadyApplied,
    () => {
      const recorded = [
        ...main,
        ...tail
          .filter(([version]) => alreadyApplied.includes(version))
          .map(([version, name]) => ({
            version,
            name,
            executed_at: "unchanged",
          })),
      ].sort((a, b) => a.version - b.version);
      const snapshot = structuredClone(recorded),
        plan = composeMigrations(combined, recorded);
      assert.deepEqual(recorded, snapshot);
      for (const row of recorded)
        assert.equal(
          plan.find((entry) => entry.version === row.version)?.name,
          row.name,
        );
      assert.deepEqual(
        composeMigrations(
          combined,
          plan.map(({ version, name }) => ({ version, name })),
        ),
        plan,
      );
    },
  );
test("unknown and conflicting history remains rejected before SQL", () => {
  assert.throws(() =>
    composeMigrations(combined, [
      ...main,
      { version: 92, name: "unknown_feature" },
    ]),
  );
  assert.throws(() =>
    composeMigrations(combined, [
      ...main,
      { version: 83, name: "certops_stable_consumer_discovery" },
    ]),
  );
  assert.throws(() =>
    composeMigrations(combined, [
      ...main,
      { version: 92, name: "recipient_channel_verification" },
    ]),
  );
  assert.throws(() =>
    composeMigrations(combined, [
      ...main,
      { version: 84, name: "weekly_digest_recipient_claim_token" },
    ]),
  );
});
