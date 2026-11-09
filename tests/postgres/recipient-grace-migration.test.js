"use strict";

const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { test } = require("node:test");
const { Pool } = require("pg");

test("normal runner upgrades the pre-grace ledger, restarts and preserves its history", { timeout: 120000 }, async () => {
  const database = `recipient_grace_${randomUUID().replaceAll("-", "")}_test`;
  const connection = {
    host: process.env.RV_TEST_DB_HOST || "127.0.0.1",
    port: Number(process.env.RV_TEST_DB_PORT || 54329),
    user: process.env.RV_TEST_DB_USER || "tokentimer",
    password: process.env.RV_TEST_DB_PASSWORD || "password",
  };
  const admin = new Pool({ ...connection, database: process.env.RV_TEST_DB_NAME || "recipient_verification_test" });
  const target = new Pool({ ...connection, database });
  const entry = path.resolve(__dirname, "../../apps/api/migrations/migrate.js");
  const env = {
    ...process.env, NODE_ENV: "test", DB_HOST: connection.host, DB_PORT: String(connection.port),
    DB_USER: connection.user, DB_PASSWORD: connection.password, DB_NAME: database,
    DISABLE_ADMIN_BOOTSTRAP: "true",
  };
  delete env.DB_SSL;
  delete env.PGSSLROOTCERT;
  function migrate(preGrace = false) {
    const source = `
      const m = require(${JSON.stringify(entry)});
      ${preGrace ? "m.migrations.splice(m.migrations.findIndex(row => row.name === 'recipient_legacy_delivery_grace'), 1);" : ""}
      m.runMigrations().then(() => process.exit(0), e => { console.error(e); process.exit(1); });
    `;
    const result = spawnSync(process.execPath, ["-e", source], { env, encoding: "utf8", timeout: 45000, maxBuffer: 8 * 1024 * 1024 });
    assert.equal(result.status, 0, String(result.error || result.stderr || result.stdout));
  }
  try {
    await admin.query(`CREATE DATABASE ${database}`);
    migrate(true);
    const before = (await target.query("SELECT * FROM migrations ORDER BY version")).rows;
    assert.ok(before.length > 90);
    migrate();
    const after = (await target.query("SELECT * FROM migrations ORDER BY version")).rows;
    assert.deepEqual(after.slice(0, -1), before);
    assert.equal(after.at(-1).name, "recipient_legacy_delivery_grace");
    assert.equal(after.at(-1).version, 109);
    assert.equal((await target.query("SELECT count(*)::int AS n FROM contact_channel_legacy_grants")).rows[0].n, 0);
    assert.equal((await target.query("SELECT count(*)::int AS n FROM recipient_legacy_grace_refusals")).rows[0].n, 0);
    assert.ok((await target.query("SELECT 1 FROM pg_trigger WHERE tgname='recipient_legacy_grace_guard_insert'")).rowCount);
    migrate();
    assert.deepEqual((await target.query("SELECT * FROM migrations ORDER BY version")).rows, after);
  } finally {
    await target.end();
    await admin.query(`DROP DATABASE IF EXISTS ${database}`);
    await admin.end();
  }
});
