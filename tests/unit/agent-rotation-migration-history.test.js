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
    { version: 112, name: "agent_credential_rotations" },
    { version: 113, name: "agent_credential_rotation_ack" },
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
  assert.throws(() => composeMigrations(migrations, [...released, { version: 113, name: "agent_credential_rotation_ack" }]), /incomplete dependency agent_credential_rotation_ack/);
});

test("an unrecognized earlier alias does not make a rotation preview safe", () => {
  const invalid = [{ version: 78, name: "certops_material_providers" }, { version: 109, name: "agent_credential_rotations" }];
  assert.throws(() => composeMigrations(migrations, invalid), /Unsupported Core migration history/);
});
