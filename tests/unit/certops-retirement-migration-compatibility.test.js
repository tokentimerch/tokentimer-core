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
  ...ledger.filter(({ version }) => version >= 114 && version <= 122),
  { version: 123, name: "certops_adcs_receipt_deadline" },
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
test("retirement preview retains a recorded Store receipt deadline and appends IIS", () => {
  const store = ["store_issuance_explicit_renewal_consent", "certops_acme_store_enrollment_identity",
    "certops_adcs_expected_identity_receipts", "certops_adcs_receipt_deadline"];
  const recovery = "distribution_pagerduty_recovery";
  const observed = "certops_observed_revocation";
  const base = appended.slice(0, 4).map(({ name }) => name);
  const iis = ledger.filter(({ version }) => version >= 118 && version <= 121).map(({ name }) => name);
  const at = (names, first = 110) => names.map((name, index) => ({ version: first + index, name }));
  const identities = (rows) => rows.map(({ version, name }) => ({ version, name }));
  for (const tail of [[...base, recovery, observed, ...store],
    [...base, recovery, ...store.slice(0, 3), observed, store[3]], [...base, ...store, recovery, observed]]) {
    const recorded = [...preview, ...at(tail)];
    const expected = [...recorded, ...at(iis, 110 + tail.length)];
    validateMigrationHistory(recorded);
    assert.deepEqual(identities(composeMigrations(migrations, recorded)), expected);
    validateMigrationHistory(expected);
    assert.deepEqual(identities(composeMigrations(migrations, expected)), expected);
  }

  const wrongOrder = [...preview, ...at([...base, recovery, observed, store[3], ...store.slice(0, 3)])];
  assert.throws(() => validateMigrationHistory(wrongOrder), /Unsupported Core.*migration history/);
});
test("released main retains identities before appending retirement", () => {
  const rows = ledger.filter((row) => row.version <= 111);
  validateMigrationHistory(rows);
  assert.deepEqual(composeMigrations(migrations, rows).map(({ version, name }) => ({ version, name })), ledger);
});
test("retirement preview rejects forged or non-prefix appended identity", () => {
  for (const rows of [[...preview, {version:110,name:"recipient_member_verification"}], [...preview, {version:111,name:"recipient_member_verification"}]]) {
    assert.throws(() => validateMigrationHistory(rows), /Unsupported Core retirement preview migration history/);
  }
});
