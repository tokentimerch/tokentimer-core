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
const revocation = "certops_observed_revocation";
const expiration = "auto_sync_creation_expiration";
const appended = [...baseNames, recovery, ...storeNames.slice(0, 3), revocation, storeNames[3], expiration].map((name, index) => ({ version: 110 + index, name }));
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
    const missing = appended.filter(({ name }) => !oldAppended.some((entry) => entry.name === name));
    const expected = [...preview, ...oldAppended, ...missing.map(({ name }, index) => ({
      version: 110 + oldAppended.length + index, name,
    }))];
    const recorded = [...preview, ...oldAppended];
    validateMigrationHistory(recorded);
    const first = composeMigrations(migrations, recorded).map(({ version, name }) => ({ version, name }));
    assert.deepEqual(first, expected);
    assert.deepEqual(first.slice(0, recorded.length), recorded);
    validateMigrationHistory(first);
    assert.deepEqual(composeMigrations(migrations, first).map(({ version, name }) => ({ version, name })), first);
  });
}

test("retirement preview preserves observed revocation already recorded before Store", () => {
  const recorded = [...preview, ...baseNames.map((name, index) => ({ version: 110 + index, name })),
    { version: 114, name: recovery }, { version: 115, name: revocation }];
  const expected = [...recorded, ...[...storeNames, expiration].map((name, index) => ({ version: 116 + index, name }))];
  validateMigrationHistory(recorded);
  assert.deepEqual(composeMigrations(migrations, recorded).map(({ version, name }) => ({ version, name })), expected);
  validateMigrationHistory(expected);
  assert.deepEqual(composeMigrations(migrations, expected).map(({ version, name }) => ({ version, name })), expected);
});

test("retirement preview preserves a Store receipt deadline already recorded before revocation", () => {
  const recorded = [...preview, ...[...baseNames, recovery, ...storeNames]
    .map((name, index) => ({ version: 110 + index, name }))];
  const expected = [...recorded, { version: 119, name: revocation }, { version: 120, name: expiration }];
  validateMigrationHistory(recorded);
  assert.deepEqual(composeMigrations(migrations, recorded).map(({ version, name }) => ({ version, name })), expected);
  validateMigrationHistory(expected);
  assert.deepEqual(composeMigrations(migrations, expected).map(({ version, name }) => ({ version, name })), expected);
});

test("canonical Store-first history leaves its existing identities unchanged when recovery fills 114", () => {
  const recorded = ledger.filter(row => row.version !== 114);
  validateMigrationHistory(recorded);
  const first = composeMigrations(migrations, recorded).map(({ version, name }) => ({ version, name }));
  assert.deepEqual(first, ledger);
  validateMigrationHistory(first);
  assert.deepEqual(composeMigrations(migrations, first).map(({ version, name }) => ({ version, name })), first);
});

test("an applied expiration preview keeps its migration identity while adding observed revocation", () => {
  const originalExpiration = { version: 115, name: "auto_sync_creation_expiration" };
  const observedRevocation = { version: 116, name: "certops_observed_revocation" };
  const priorTails = [ledger.filter((row) => row.version <= 114), [...preview, ...appended.slice(0, 5)]];
  for (const prior of priorTails) {
    for (const applied of [[originalExpiration], [originalExpiration, observedRevocation]]) {
      const recorded = [...prior, ...applied];
      validateMigrationHistory(recorded);
      const plan = composeMigrations(migrations, recorded).map(({ version, name }) => ({ version, name }));
      assert.deepEqual(plan.slice(0, recorded.length), recorded);
      assert.deepEqual(plan.map(({ name }) => name).sort(), migrations.map(({ name }) => name).sort());
      validateMigrationHistory(plan);
      assert.deepEqual(composeMigrations(migrations, plan).map(({ version, name }) => ({ version, name })), plan);
    }
  }
  assert.throws(() => validateMigrationHistory([...ledger.filter((row) => row.version <= 113), originalExpiration]),
    /Unsupported Core migration history/);
});
test("released main retains identities before appending retirement", () => {
  const rows = ledger.filter((row) => row.version <= 111);
  validateMigrationHistory(rows);
  assert.deepEqual(composeMigrations(migrations, rows).map(({ version, name }) => ({ version, name })), ledger);
});
test("retirement preview rejects forged or non-prefix appended identity", () => {
  for (const rows of [[...preview, {version:110,name:"recipient_member_verification"}], [...preview, {version:111,name:"recipient_member_verification"}],
    [...preview, ...appended, {version:121,name:"unrecognized_feature"}],
    [...preview, ...appended.filter(row => row.version !== 116)],
    [...preview, ...appended.slice(0, -2), {version:126,name:"certops_adcs_receipt_deadline"}]]) {
    assert.throws(() => validateMigrationHistory(rows), /Unsupported Core retirement preview migration history/);
  }
});
