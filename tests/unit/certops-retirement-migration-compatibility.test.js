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
  { version: 114, name: "distribution_pagerduty_recovery" },
  { version: 115, name: "certops_observed_revocation" },
  { version: 116, name: "auto_sync_creation_expiration" },
  { version: 117, name: "shared_sso_schema" },
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
test("an applied expiration preview keeps its migration identity while adding observed revocation", () => {
  const originalExpiration = { version: 115, name: "auto_sync_creation_expiration" };
  const observedRevocation = { version: 116, name: "certops_observed_revocation" };
  const sso = { version: 117, name: "shared_sso_schema" };
  const priorTails = [ledger.filter((row) => row.version <= 114), [...preview, ...appended.slice(0, 5)]];
  for (const prior of priorTails) {
    const recorded = [...prior, originalExpiration];
    validateMigrationHistory(recorded);
    const plan = composeMigrations(migrations, recorded).map(({ version, name }) => ({ version, name }));
    assert.deepEqual(plan, [...recorded, observedRevocation, sso]);
    validateMigrationHistory(plan);
    assert.deepEqual(composeMigrations(migrations, plan).map(({ version, name }) => ({ version, name })), plan);
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
  for (const rows of [[...preview, {version:110,name:"recipient_member_verification"}], [...preview, {version:111,name:"recipient_member_verification"}]]) {
    assert.throws(() => validateMigrationHistory(rows), /Unsupported Core retirement preview migration history/);
  }
});

test("the applied SSO preview retains 115 on released and retirement-preview histories", () => {
  const ssoPreview = { version: 115, name: "shared_sso_schema" };
  const revocation = { version: 116, name: "certops_observed_revocation" };
  const releasedBase = ledger.filter((row) => row.version <= 114);
  const retirementBase = [...preview, ...appended.slice(0, 5)];
  for (const base of [releasedBase, retirementBase]) {
    const history = [...base, ssoPreview];
    const expected = [...history, revocation, { version: 117, name: "auto_sync_creation_expiration" }];
    for (const rows of [history, [...history, revocation], expected]) {
      validateMigrationHistory(rows);
      const plan = composeMigrations(migrations, rows);
      assert.deepEqual(plan.map(({ version, name }) => ({ version, name })), expected);
      for (const entry of plan) assert.equal(entry.sql, migrations.find((item) => item.name === entry.name).sql);
    }
  }
});

test("only the reviewed SSO preview prefix can claim the old SSO slot", () => {
  const releasedBase = ledger.filter((row) => row.version <= 114);
  for (const tail of [
    [{ version: 115, name: "store_issuance_explicit_renewal_consent" }],
    [{ version: 116, name: "shared_sso_schema" }],
    [{ version: 127, name: "shared_sso_schema" }],
    [{ version: 128, name: "shared_sso_schema" }],
    [{ version: 115, name: "shared_sso_schema" }, { version: 116, name: "auto_sync_creation_expiration" }],
    [{ version: 115, name: "shared_sso_schema" }, { version: 117, name: "certops_observed_revocation" }],
  ]) {
    assert.throws(() => validateMigrationHistory([...releasedBase, ...tail]), /Unsupported Core/);
  }
  assert.throws(() => validateMigrationHistory([
    ...releasedBase.filter((row) => row.version !== 113),
    { version: 115, name: "shared_sso_schema" },
  ]), /Unsupported Core/);
});

test("canonical Store migrations keep 115 and never satisfy SSO", () => {
  const store = { version: 115, name: "store_issuance_explicit_renewal_consent", sql: "reviewed Store schema" };
  const registry = [...migrations, store];
  const { validateMigrationReservations } = require("../../apps/api/migrations/migration-reservations.cjs");
  validateMigrationReservations(registry);
  assert.throws(() => validateMigrationReservations(migrations.map((entry) =>
    entry.name === "shared_sso_schema" ? { ...entry, version: 115 } : entry)), /Conflicting canonical/);
  const base = [...ledger.filter((row) => row.version <= 114), store];
  const plan = composeMigrations(registry, base);
  assert.deepEqual(plan.slice(-4).map(({ version, name }) => ({ version, name })), [
    { version: 115, name: store.name },
    { version: 122, name: "certops_observed_revocation" },
    { version: 127, name: "auto_sync_creation_expiration" },
    { version: 128, name: "shared_sso_schema" },
  ]);
  assert.deepEqual(composeMigrations(registry, plan), plan);
});

test("the later SSO preview preserves sparse 127 and shifted retirement 116", () => {
  const expiration = "auto_sync_creation_expiration";
  const standard = [...ledger.filter((row) => row.version <= 122), { version: 127, name: "shared_sso_schema" }];
  const retirement = [...preview, ...appended.slice(0, 6), { version: 116, name: "shared_sso_schema" }];
  for (const [history, version] of [[standard, 128], [retirement, 117]]) {
    const upgraded = [...history, { version, name: expiration }];
    for (const rows of [history, upgraded]) {
      validateMigrationHistory(rows);
      const plan = composeMigrations(migrations, rows);
      assert.deepEqual(plan.map(({ version, name }) => ({ version, name })), upgraded);
      for (const entry of plan) assert.equal(entry.sql, migrations.find((item) => item.name === entry.name).sql);
    }
  }
  assert.throws(() => validateMigrationHistory([
    ...standard.filter((row) => row.version !== 113),
  ]), /Unsupported Core/);
});

test("an applied SSO row requires a registered SSO migration", () => {
  const registry = migrations.filter(({ name }) => name !== "shared_sso_schema");
  const base = ledger.filter(({ version }) => version <= 114);
  assert.throws(() => composeMigrations(registry, [...base, { version: 115, name: "shared_sso_schema" }]),
    /Unsupported Core migration history: unknown extension shared_sso_schema/);
});
