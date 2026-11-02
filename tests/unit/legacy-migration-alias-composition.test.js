"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { migrations, validateMigrationHistory } = require("../../apps/api/migrations/migrate");
const historical = require("../fixtures/pr72-migrations.json");

for (let end = 39; end <= 45; end++) {
  test(`the composed executor admits the documented historical ledger through ${end}`, () => {
    const rows = [...migrations.filter(row => row.version <= 38), ...historical.filter(row => row.version <= end)]
      .map(({ version, name }) => ({ version, name }));
    const before = structuredClone(rows);
    assert.doesNotThrow(() => validateMigrationHistory(rows));
    assert.deepEqual(rows, before, "composition cannot rewrite applied names or versions");
  });
}

test("legacy aliases do not admit duplicate versions or unrecognized repeated names", () => {
  const rows = [...migrations.filter(row => row.version <= 38), ...historical]
    .map(({ version, name }) => ({ version, name }));
  assert.throws(() => validateMigrationHistory([...rows, rows[0]]), /duplicate entries/);
  const wrong = rows.map(row => row.version === 40 ? { ...row, name: "operational_notifications_schema" } : row);
  assert.throws(() => validateMigrationHistory(wrong), /unexpected name/);
});

test("new migration histories still reject duplicate feature names", () => {
  const rows = migrations.map(({ version, name }) => ({ version, name }));
  rows.find(row => row.version === 80).name = rows.find(row => row.version === 79).name;
  assert.throws(() => validateMigrationHistory(rows), /duplicate entries/);
});
