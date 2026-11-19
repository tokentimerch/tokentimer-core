"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { migrations, validateMigrationHistory } = require("../../apps/api/migrations/migrate");
const { composeMigrations } = require("../../apps/api/migrations/compose-migrations");
const ledger = migrations.map(({ version, name }) => ({ version, name }));
const preview = [...ledger.filter((row) => row.version <= 108), { version: 109, name: "certops_retirement_dossiers" }];
const baseNames = ["certops_period_creator_delete", "recipient_member_verification", "auto_sync_owner_username", "certops_material_reconciliation"];
const storeNames = ["store_issuance_explicit_renewal_consent", "certops_acme_store_enrollment_identity", "certops_adcs_expected_identity_receipts", "certops_adcs_receipt_deadline"];
const recovery = "distribution_pagerduty_recovery";
const appended = [...baseNames, recovery, ...storeNames].map((name, index) => ({ version: 110 + index, name }));
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

for (let count = 1; count <= storeNames.length; count++) {
  test(`retirement preview retains ${count} already-applied Store migrations when recovery arrives`, () => {
    const oldAppended = [...baseNames, ...storeNames.slice(0, count)]
      .map((name, index) => ({ version: 110 + index, name }));
    const expected = [...preview, ...[
      ...baseNames, ...storeNames.slice(0, count), recovery, ...storeNames.slice(count),
    ].map((name, index) => ({ version: 110 + index, name }))];
    const recorded = [...preview, ...oldAppended];
    validateMigrationHistory(recorded);
    const first = composeMigrations(migrations, recorded).map(({ version, name }) => ({ version, name }));
    assert.deepEqual(first, expected);
    assert.deepEqual(first.slice(0, recorded.length), recorded);
    validateMigrationHistory(first);
    assert.deepEqual(composeMigrations(migrations, first).map(({ version, name }) => ({ version, name })), first);
  });
}

test("canonical Store-first history leaves its existing identities unchanged when recovery fills 114", () => {
  const recorded = ledger.filter(row => row.version !== 114);
  validateMigrationHistory(recorded);
  const first = composeMigrations(migrations, recorded).map(({ version, name }) => ({ version, name }));
  assert.deepEqual(first, ledger);
  validateMigrationHistory(first);
  assert.deepEqual(composeMigrations(migrations, first).map(({ version, name }) => ({ version, name })), first);
});
test("released main retains identities before appending retirement", () => {
  const rows = ledger.filter((row) => row.version <= 111);
  validateMigrationHistory(rows);
  assert.deepEqual(composeMigrations(migrations, rows).map(({ version, name }) => ({ version, name })), ledger);
});
test("retirement preview rejects forged or non-prefix appended identity", () => {
  for (const rows of [[...preview, {version:110,name:"recipient_member_verification"}], [...preview, {version:111,name:"recipient_member_verification"}],
    [...preview, ...appended, {version:119,name:"unrecognized_feature"}],
    [...preview, ...appended.filter(row => row.version !== 116)],
    [...preview, ...appended.slice(0, -1), {version:126,name:"certops_adcs_receipt_deadline"}]]) {
    assert.throws(() => validateMigrationHistory(rows), /Unsupported Core retirement preview migration history/);
  }
});
