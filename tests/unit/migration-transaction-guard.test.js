"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { checkTransactionGuarantee } = require("../../scripts/ci-guards/migration-ddl-guard.cjs");
const source = fs.readFileSync(path.resolve(__dirname, "../../apps/api/migrations/migrate.js"), "utf8");

test("the history-aware migration executor retains its transaction guard", () => {
  assert.deepEqual(checkTransactionGuarantee(source), []);
});

for (const keyword of ["BEGIN", "COMMIT", "ROLLBACK"]) {
  test(`removing ${keyword} from the migration executor fails the guard`, () => {
    const unsafe = source.replaceAll(`client.query("${keyword}")`, "client.query('SELECT 1')");
    assert.ok(checkTransactionGuarantee(unsafe).length > 0);
  });
}
