"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { migrations, validateMigrationHistory } = require("../../apps/api/migrations/migrate");
const { composeMigrations } = require("../../apps/api/migrations/compose-migrations");

test("released ledger appends rotation after current reserved migrations", () => {
  const released = migrations.filter(({ version }) => version <= 111).map(({ version, name }) => ({ version, name }));
  assert.doesNotThrow(() => validateMigrationHistory(released));
  const plan = composeMigrations(migrations, released);
  assert.deepEqual(plan.filter(({ name }) => name.startsWith("agent_credential_rotation")).map(({ version, name }) => ({ version, name })), [
    { version: 114, name: "agent_credential_rotations" },
    { version: 115, name: "agent_credential_rotation_ack" },
  ]);
  const applied = plan.map(({ version, name }) => ({ version, name }));
  assert.doesNotThrow(() => validateMigrationHistory(applied));
  assert.deepEqual(composeMigrations(migrations, applied), plan);
});

test("ambiguous rotation previews fail before composition", () => {
  for (const row of [
    { version: 109, name: "agent_credential_rotations" },
    { version: 110, name: "agent_credential_rotation_ack" },
    { version: 110, name: "agent_credential_rotations" },
  ]) {
    assert.throws(() => validateMigrationHistory([row]), /Unsupported ambiguous agent credential rotation preview history/);
    assert.throws(() => composeMigrations(migrations, [row]), /Unsupported ambiguous agent credential rotation preview history/);
  }
});

test("rotation acknowledgement cannot precede its preparation schema", () => {
  const released = migrations.filter(({ version }) => version <= 111).map(({ version, name }) => ({ version, name }));
  assert.throws(() => composeMigrations(migrations, [...released, { version: 115, name: "agent_credential_rotation_ack" }]), /incomplete dependency agent_credential_rotation_ack/);
});

test("an unrecognized earlier alias does not make a rotation preview safe", () => {
  const invalid = [{ version: 78, name: "certops_material_providers" }, { version: 109, name: "agent_credential_rotations" }];
  assert.throws(() => composeMigrations(migrations, invalid), /Unsupported Core migration history/);
});

test("reviewed rotation preview remains exact and rejects gaps or swapped rows", () => {
  const original = migrations.filter(x => x.version <= 85 || [92, 93].includes(x.version));
  const names = ["operator_connections", "operator_enrollment_grants", "operator_action_requests"];
  const prior = [...original, ...names.map((name, i) => ({ ...migrations.find(x => x.name === name), version: 94 + i }))];
  const legacy = migrations.filter(x => !["certops_retirement_dossiers", "certops_material_reconciliation"].includes(x.name));
  const history = composeMigrations(legacy, prior).map(({ version, name }) => ({ version, name }));
  assert.equal(history.find(x => x.name === "agent_credential_rotations").version, 110);
  assert.equal(history.find(x => x.name === "agent_credential_rotation_ack").version, 111);
  const plan = composeMigrations(migrations, history);
  assert.equal(plan.find(x => x.name === "certops_retirement_dossiers").version, 120);
  assert.equal(plan.find(x => x.name === "certops_material_reconciliation").version, 121);
  assert.throws(() => composeMigrations(migrations, history.filter(x => x.version !== 105)), /Unsupported Core migration history/);
  const swapped = history.map(x => x.version === 110 ? { ...x, version: 111 } : x.version === 111 ? { ...x, version: 110 } : x);
  assert.throws(() => composeMigrations(migrations, swapped), /Unsupported Core migration history/);
});

test("complete credential rotation preview upgrades without rewriting its ledger", () => {
  const original = migrations.filter(({ version }) => version <= 85 || (version >= 92 && version <= 95) || (version >= 98 && version <= 111))
    .map(({ version, name }) => ({ version, name }));
  const history = [...original, { version: 112, name: "agent_credential_rotations" }, { version: 113, name: "agent_credential_rotation_ack" }];
  const plan = composeMigrations(migrations, history);
  const applied = plan.map(({ version, name }) => ({ version, name }));
  assert.deepEqual(applied.filter(({ version }) => version <= 113), history);
  assert.doesNotThrow(() => validateMigrationHistory(history));
  assert.doesNotThrow(() => validateMigrationHistory(applied));
  assert.deepEqual(composeMigrations(migrations, applied), plan);
  for (let end = history.length; end <= applied.length; end++) {
    assert.deepEqual(composeMigrations(migrations, applied.slice(0, end)), plan);
  }
  const mutations = [
    history.filter(({ version }) => version !== 105),
    history.filter(({ version }) => version !== 113),
    history.map((row) => row.version === 110 ? { ...row, name: "auto_sync_owner_username" } : row),
    history.map((row) => row.version === 112 ? { ...row, name: "agent_credential_rotation_ack" } : row.version === 113 ? { ...row, name: "agent_credential_rotations" } : row),
    applied.filter(({ version }) => version !== 114),
  ];
  for (const invalid of mutations) assert.throws(() => composeMigrations(migrations, invalid), /Unsupported/);
});
