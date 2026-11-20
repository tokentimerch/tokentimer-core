"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { migrations, validateMigrationHistory } = require("../../apps/api/migrations/migrate");
const { composeMigrations } = require("../../apps/api/migrations/compose-migrations");
const ledger = migrations.map(({ version, name }) => ({ version, name }));
const preview = [...ledger.filter((row) => row.version <= 108), { version: 109, name: "certops_retirement_dossiers" }];
const appended = [{ version: 110, name: "certops_period_creator_delete" }, { version: 111, name: "recipient_member_verification" }, { version: 112, name: "auto_sync_owner_username" }, {version:113,name:"certops_material_reconciliation"}, {version:114,name:"distribution_pagerduty_recovery"}, {version:115,name:"agent_credential_rotations"}, {version:116,name:"agent_credential_rotation_ack"}];
test("retirement preview preserves identities through partial released-main upgrades", () => {
  const observedFirst = [...appended.slice(0, 5), { version: 115, name: "certops_observed_revocation" }];
  for (const history of [appended, observedFirst]) {
    for (let count = 0; count <= history.length; count++) {
      const rows = [...preview, ...history.slice(0, count)];
      validateMigrationHistory(rows);
      const plan = composeMigrations(migrations, rows).map(({ version, name }) => ({ version, name }));
      assert.deepEqual(plan.slice(0, rows.length), rows);
      assert.deepEqual(plan.slice(preview.length).map(row => row.name).sort(),
        [...appended.map(row => row.name), "certops_observed_revocation", "auto_sync_creation_expiration"].sort());
      validateMigrationHistory(plan);
      assert.deepEqual(composeMigrations(migrations, plan).map(({version,name}) => ({version,name})), plan);
    }
  }
});

test("retirement preview keeps an already applied rotation tail before recovery", () => {
  const oldAppend = [...appended.slice(0, 4),
    {version:114,name:"agent_credential_rotations"}, {version:115,name:"agent_credential_rotation_ack"}];
  const expected = [...preview, ...oldAppend, {version:116,name:"distribution_pagerduty_recovery"},
    {version:117,name:"certops_observed_revocation"}, {version:118,name:"auto_sync_creation_expiration"}];
  for (const count of [5, 6, 7]) {
    const rows = expected.slice(0, preview.length + count);
    validateMigrationHistory(rows);
    const plan = composeMigrations(migrations, rows).map(({version,name}) => ({version,name}));
    assert.deepEqual(plan, expected);
    assert.deepEqual(composeMigrations(migrations, plan).map(({version,name}) => ({version,name})), expected);
  }
});

const storeDefinitions = [
  [115,"store_issuance_explicit_renewal_consent"],
  [116,"certops_acme_store_enrollment_identity"],
  [117,"certops_adcs_expected_identity_receipts"],
  [126,"certops_adcs_receipt_deadline"],
].map(([version,name]) => ({version,name,sql:"SELECT 1"}));

test("retirement previews preserve Store prefixes with recovery and rotation arriving later", () => {
  const registry = [...migrations, ...storeDefinitions].sort((a,b) => a.version-b.version);
  const base = appended.slice(0,4).map(row => row.name);
  const store = storeDefinitions.map(row => row.name);
  const rotation = ["agent_credential_rotations","agent_credential_rotation_ack"];
  const recovery = "distribution_pagerduty_recovery";
  const preserve = (rows) => {
    const before = JSON.stringify(rows);
    const plan = composeMigrations(registry, rows);
    assert.equal(JSON.stringify(rows), before);
    assert.deepEqual(plan.slice(0,rows.length).map(({version,name}) => ({version,name})), rows);
    assert.deepEqual(composeMigrations(registry,plan), plan);
    for (let end=rows.length;end<=plan.length;end++) {
      assert.deepEqual(composeMigrations(registry,plan.slice(0,end)), plan);
    }
  };
  const canonical = [...base,...registry.filter(row => row.version>=114).map(row => row.name)];
  const fresh = composeMigrations(registry,preview);
  assert.deepEqual(fresh.slice(preview.length).map(row => row.name), canonical);
  for (let count=0;count<=store.length;count++) {
    const priorNames = [...base,...store.slice(0,count)];
    const prior = [...preview,...priorNames.map((name,index) => ({version:110+index,name}))];
    const continued = composeMigrations(registry,prior);
    const missing = registry.filter(row => row.version>=114 && !priorNames.includes(row.name));
    assert.deepEqual(continued.slice(prior.length).map(row => row.name), missing.map(row => row.name));
    const tail = [...store.slice(0,count),recovery,...store.slice(count)];
    for (let cut=0;cut<=tail.length;cut++) {
      const names = [...base,...tail.slice(0,cut),...rotation,...tail.slice(cut)];
      const rows = [...preview,...names.map((name,index) => ({version:110+index,name}))];
      for (let end=preview.length;end<=rows.length;end++) preserve(rows.slice(0,end));
    }
  }
});

test("retirement Store composition rejects swapped, missing and unknown suffix identities", () => {
  const registry = [...migrations,...storeDefinitions].sort((a,b) => a.version-b.version);
  const names = [...appended.slice(0,4).map(row => row.name),
    ...storeDefinitions.map(row => row.name),"distribution_pagerduty_recovery",
    "agent_credential_rotations","agent_credential_rotation_ack"];
  const rows = [...preview,...names.map((name,index) => ({version:110+index,name}))];
  const swapped = rows.map(row => row.version===114 ? {...row,name:names[5]}
    : row.version===115 ? {...row,name:names[4]} : row);
  for (const invalid of [swapped,rows.filter(row => row.version!==115),
    rows.map(row => row.version===114 ? {...row,name:"unrecognized_store_schema"} : row),
    rows.map(row => row.name==="agent_credential_rotations" ? {...row,name:"agent_credential_rotation_ack"}
      : row.name==="agent_credential_rotation_ack" ? {...row,name:"agent_credential_rotations"} : row)]) {
    assert.throws(() => composeMigrations(registry,invalid), /Unsupported Core/);
  }
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
  for (const rows of [[...preview, {version:110,name:"recipient_member_verification"}], [...preview, {version:111,name:"recipient_member_verification"}]]) {
    assert.throws(() => validateMigrationHistory(rows), /Unsupported Core retirement preview migration history/);
  }
});
