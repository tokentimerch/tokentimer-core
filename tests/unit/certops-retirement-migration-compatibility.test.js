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
  { version: 115, name: "agent_credential_rotations" },
  { version: 116, name: "agent_credential_rotation_ack" },
];
test("retirement preview preserves identities through partial released-main upgrades", () => {
  const observedFirst = [...appended.slice(0, 5), { version: 115, name: "certops_observed_revocation" }];
  for (const history of [appended, observedFirst]) {
    for (let count = 0; count <= history.length; count++) {
      const rows = [...preview, ...history.slice(0, count)];
      validateMigrationHistory(rows);
      const plan = composeMigrations(migrations, rows).map(({ version, name }) => ({ version, name }));
      assert.deepEqual(plan.slice(0, rows.length), rows);
      assert.deepEqual(plan.slice(preview.length).map(row => row.name).sort(),
        ledger.filter(row => row.version >= 109 && row.name !== "certops_retirement_dossiers").map(row => row.name).sort());
      validateMigrationHistory(plan);
      assert.deepEqual(composeMigrations(migrations, plan).map(({version,name}) => ({version,name})), plan);
    }
  }
});

test("retirement preview keeps an already applied rotation tail before recovery", () => {
  const oldAppend = [...appended.slice(0, 4),
    {version:114,name:"agent_credential_rotations"}, {version:115,name:"agent_credential_rotation_ack"}];
  const prior = [...preview, ...oldAppend, {version:116,name:"distribution_pagerduty_recovery"},
    {version:117,name:"certops_observed_revocation"}, {version:118,name:"auto_sync_creation_expiration"}];
  for (let count = 5; count <= 9; count++) {
    const rows = prior.slice(0, preview.length + count);
    validateMigrationHistory(rows);
    const plan = composeMigrations(migrations, rows).map(({ version, name }) => ({ version, name }));
    assert.deepEqual(plan.slice(0, rows.length), rows);
    assert.equal(plan.find(({ name }) => name === "agent_credential_rotation_ack").version, 115);
    if (count >= 8) {
      const expected = [...rows, ...ledger.filter(row => !rows.some(old => old.name === row.name))
        .map(({ name }, index) => ({ version: rows.at(-1).version + 1 + index, name }))];
      assert.deepEqual(plan, expected);
    }
    assert.deepEqual(composeMigrations(migrations, plan).map(({ version, name }) => ({ version, name })), plan);
  }
});

const storeDefinitions = [
  [115,"store_issuance_explicit_renewal_consent"],
  [116,"certops_acme_store_enrollment_identity"],
  [117,"certops_adcs_expected_identity_receipts"],
  [126,"certops_adcs_receipt_deadline"],
].map(([version,name]) => ({version,name,sql:"SELECT 1"}));

test("retirement previews preserve Store prefixes with recovery and rotation arriving later", () => {
  const registry = migrations;
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
  const registry = migrations;
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
    const expected = [...recorded, ...at([...iis, "agent_credential_rotations", "agent_credential_rotation_ack", "certops_adcs_preflight_lookup_index", "auto_sync_creation_expiration"], 110 + tail.length)];
    validateMigrationHistory(recorded);
    assert.deepEqual(identities(composeMigrations(migrations, recorded)), expected);
    validateMigrationHistory(expected);
    assert.deepEqual(identities(composeMigrations(migrations, expected)), expected);
  }

  const wrongOrder = [...preview, ...at([...base, recovery, observed, store[3], ...store.slice(0, 3)])];
  assert.throws(() => validateMigrationHistory(wrongOrder), /Unsupported Core.*migration history/);
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
test("retirement preview with the preflight index retains its ledger when secure-agent tails arrive", () => {
  const earlierRegistry = migrations
    .filter(({ name }) => !["distribution_pagerduty_recovery", "agent_credential_rotations", "agent_credential_rotation_ack", "certops_adcs_receipt_deadline", "auto_sync_creation_expiration"].includes(name))
    .map((row) => row.version >= 115 && row.version <= 122 ? { ...row, version: row.version - 1 } : row);
  const before = composeMigrations(earlierRegistry, preview);
  assert.equal(before.find((row) => row.name === "certops_adcs_preflight_lookup_index").version, 122);

  const registry = migrations;
  const after = composeMigrations(registry, before);
  assert.deepEqual(after.slice(0, before.length), before);
  assert.deepEqual(after.slice(before.length).map(({ version, name }) => ({ version, name })), [
    { version: 123, name: "distribution_pagerduty_recovery" },
    { version: 124, name: "agent_credential_rotations" },
    { version: 125, name: "agent_credential_rotation_ack" },
    { version: 126, name: "certops_adcs_receipt_deadline" },
    { version: 127, name: "auto_sync_creation_expiration" },
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
