"use strict";

const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { test } = require("node:test");
const { Pool } = require("pg");

test("normal runner appends member verification to the released ledger and restarts unchanged", { timeout: 120000 }, async () => {
  const database = `recipient_member_${randomUUID().replaceAll("-", "")}_test`;
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
  delete env.DATABASE_URL;
  function migrate(beforeMember = false) {
    const source = `
      const m = require(${JSON.stringify(entry)});
      ${beforeMember ? "m.migrations.splice(m.migrations.findIndex(row => row.version >= 110));" : ""}
      m.runMigrations().then(() => process.exit(0), e => { console.error(e); process.exit(1); });
    `;
    const result = spawnSync(process.execPath, ["-e", source], { env, encoding: "utf8", timeout: 45000, maxBuffer: 8 * 1024 * 1024 });
    assert.equal(result.status, 0, String(result.error || result.stderr || result.stdout));
  }
  try {
    await admin.query(`CREATE DATABASE ${database}`);
    migrate(true);
    const before = (await target.query("SELECT * FROM migrations ORDER BY version")).rows;
    assert.equal(before.at(-1).version, 109);
    assert.equal(before.at(-1).name, "certops_period_creator_delete");
    migrate();
    const after = (await target.query("SELECT * FROM migrations ORDER BY version")).rows;
    assert.deepEqual(after.filter((row) => row.version < 110), before);
    assert.equal(after.find((row) => row.version === 110)?.name, "recipient_member_verification");
    assert.equal(after.find((row) => row.version === 111)?.name, "auto_sync_owner_username");
    assert.ok((await target.query("SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='recipient_verified_email'")).rowCount);
    assert.ok((await target.query("SELECT 1 FROM pg_trigger WHERE tgname='recipient_member_verification_preserve_revocation'")).rowCount);
    migrate();
    assert.deepEqual((await target.query("SELECT * FROM migrations ORDER BY version")).rows, after);
  } finally {
    await target.end();
    await admin.query(`DROP DATABASE IF EXISTS ${database}`);
    await admin.end();
  }
});
