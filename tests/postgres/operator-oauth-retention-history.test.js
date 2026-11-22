"use strict";
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { test } = require("node:test");
const { Pool } = require("pg");

assert.equal(process.env.RV_TEST_DB_HOST, "127.0.0.1");
assert.match(process.env.RV_TEST_DB_PORT || "", /^\d+$/);
assert.ok(process.env.RV_TEST_DB_USER);
const connection = { host: "127.0.0.1", port: Number(process.env.RV_TEST_DB_PORT), user: process.env.RV_TEST_DB_USER, password: process.env.RV_TEST_DB_PASSWORD };
const entry = path.resolve(__dirname, "../../apps/api/migrations/migrate.js");

async function withDatabase(run) {
  const database = `oauth_retention_${randomUUID().replaceAll("-", "")}_test`;
  const admin = new Pool({ ...connection, database: "postgres" });
  let target;
  try {
    await admin.query(`CREATE DATABASE ${database}`);
    target = new Pool({ ...connection, database });
    const env = { ...process.env, NODE_ENV: "test", DB_HOST: connection.host, DB_PORT: String(connection.port), DB_USER: connection.user, DB_PASSWORD: connection.password, DB_NAME: database, DISABLE_ADMIN_BOOTSTRAP: "true" };
    delete env.DB_SSL; delete env.PGSSLROOTCERT; delete env.DATABASE_URL;
    function migrate(omitted = [], fails = false) {
      const source = `const m=require(${JSON.stringify(entry)});const omit=new Set(${JSON.stringify(omitted)});for(let i=m.migrations.length-1;i>=0;i--)if(omit.has(m.migrations[i].name))m.migrations.splice(i,1);m.runMigrations().then(()=>process.exit(0),e=>{console.error(e);process.exit(1)});`;
      const result = spawnSync(process.execPath, ["-e", source], { env, encoding: "utf8", timeout: 90000, maxBuffer: 8 * 1024 * 1024 });
      const output = String(result.error || "") + result.stdout + result.stderr;
      assert.equal(result.status, fails ? 1 : 0, output.slice(-6000));
      return output;
    }
    await run({ target, migrate });
  } finally {
    if (target) await target.end();
    await admin.query(`DROP DATABASE IF EXISTS ${database}`);
    await admin.end();
  }
}

const snapshot = async (db) => ({
  ledger: (await db.query("SELECT version,name,executed_at::text FROM migrations ORDER BY version")).rows,
  constraint: (await db.query("SELECT pg_get_constraintdef(oid) AS definition, convalidated FROM pg_constraint WHERE conrelid='operator_oauth_grants'::regclass AND conname='operator_oauth_grants_generation_count_check'")).rows,
});

test("missing retention in a hypothetical preview migrates and replays", { timeout: 120000 }, async () => {
  await withDatabase(async ({ target, migrate }) => {
    migrate(["operator_oauth_retention"]);
    const before = await snapshot(target);
    assert.equal(before.ledger.some((row) => row.name === "operator_oauth_retention"), false);
    migrate();
    const after = await snapshot(target);
    assert.deepEqual(after.ledger.filter((row) => row.name !== "operator_oauth_retention"), before.ledger);
    assert.equal(after.constraint[0].definition, "CHECK ((generation_count >= 0))");
    migrate();
    assert.deepEqual(await snapshot(target), after);
  });
});

test("missing ledger entry after retention was applied is rejected without mutation", { timeout: 120000 }, async () => {
  await withDatabase(async ({ target, migrate }) => {
    migrate();
    await target.query("DELETE FROM migrations WHERE name='operator_oauth_retention'");
    const before = await snapshot(target);
    assert.match(migrate([], true), /missing operator OAuth retention entry has unexpected schema/);
    assert.deepEqual(await snapshot(target), before);
  });
});

test("missing OAuth prerequisites in a hypothetical preview can be installed first", { timeout: 120000 }, async () => {
  await withDatabase(async ({ target, migrate }) => {
    migrate(["operator_oauth", "operator_connection_lifetimes", "operator_oauth_retention"]);
    const before = (await target.query("SELECT version,name,executed_at::text FROM migrations ORDER BY version")).rows;
    migrate();
    const after = await snapshot(target);
    const names = new Set(["operator_oauth", "operator_connection_lifetimes", "operator_oauth_retention"]);
    assert.deepEqual(after.ledger.filter((row) => !names.has(row.name)), before);
    migrate();
    assert.deepEqual(await snapshot(target), after);
  });
});
