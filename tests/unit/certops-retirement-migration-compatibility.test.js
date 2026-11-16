"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { migrations, validateMigrationHistory } = require("../../apps/api/migrations/migrate");
const { composeMigrations } = require("../../apps/api/migrations/compose-migrations");
const ledger = migrations.map(({ version, name }) => ({ version, name }));
const preview = [...ledger.filter((row) => row.version <= 108), { version: 109, name: "certops_retirement_dossiers" }];
const appended = [
  { version: 110, name: "certops_period_creator_delete" },
  { version: 111, name: "recipient_member_verification" },
  { version: 112, name: "auto_sync_owner_username" },
  { version: 113, name: "certops_material_reconciliation" },
  ...ledger.filter(({ version }) => version >= 114).map((row) =>
    row.name === "certops_adcs_preflight_lookup_index" ? { ...row, version: 123 } : row,
  ),
];
test("retirement preview preserves identities through partial released-main upgrades", () => {
  for (let count = 0; count <= appended.length; count++) {
    const rows = [...preview, ...appended.slice(0, count)];
    validateMigrationHistory(rows);
    const plan = composeMigrations(migrations, rows).map(({ version, name }) => ({ version, name }));
    assert.deepEqual(plan, [...preview, ...appended]);
    validateMigrationHistory(plan);
    assert.deepEqual(composeMigrations(migrations, plan).map(({version,name}) => ({version,name})), plan);
  }
});
test("released main retains identities before appending retirement", () => {
  const rows = ledger.filter((row) => row.version <= 111);
  validateMigrationHistory(rows);
  assert.deepEqual(composeMigrations(migrations, rows).map(({ version, name }) => ({ version, name })), ledger);
});

test("retirement preview with the preflight index retains its ledger when secure-agent tails arrive", () => {
  const earlierRegistry = migrations
    .filter((row) => row.name !== "distribution_pagerduty_recovery")
    .map((row) => row.version >= 115 && row.version <= 122 ? { ...row, version: row.version - 1 } : row);
  const before = composeMigrations(earlierRegistry, preview);
  assert.equal(before.find((row) => row.name === "certops_adcs_preflight_lookup_index").version, 122);

  const names = ["agent_credential_rotations", "agent_credential_rotation_ack"];
  const future = names.map((name, index) => ({ version: 123 + index, name, sql: `reviewed-${name}` }));
  const registry = [...migrations, ...future];
  const after = composeMigrations(registry, before);
  assert.deepEqual(after.slice(0, before.length), before);
  assert.deepEqual(after.slice(before.length).map(({ version, name }) => ({ version, name })), [
    { version: 123, name: "distribution_pagerduty_recovery" },
    { version: 124, name: "agent_credential_rotations" },
    { version: 125, name: "agent_credential_rotation_ack" },
  ]);
  assert.deepEqual(composeMigrations(registry, after), after);
  const forged = after.map((row) => ({ ...row }));
  [forged.at(-1).name, forged.at(-2).name] = [forged.at(-2).name, forged.at(-1).name];
  assert.throws(() => composeMigrations(registry, forged), /Unsupported Core retirement preview/);
});
test("retirement preview rejects forged or non-prefix appended identity", () => {
  for (const rows of [[...preview, {version:110,name:"recipient_member_verification"}], [...preview, {version:111,name:"recipient_member_verification"}]]) {
    assert.throws(() => validateMigrationHistory(rows), /Unsupported Core retirement preview migration history/);
  }
});
