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
  const database = `agent_rotation_${randomUUID().replaceAll("-", "")}_test`;
  assert.match(database, /^agent_rotation_[a-f0-9]{32}_test$/);
  const admin = new Pool({ ...connection, database: "postgres" });
  let target;
  try {
    await admin.query(`CREATE DATABASE ${database}`);
    target = new Pool({ ...connection, database });
    const env = { ...process.env, NODE_ENV: "test", DB_HOST: connection.host, DB_PORT: String(connection.port), DB_USER: connection.user, DB_PASSWORD: connection.password, DB_NAME: database, DISABLE_ADMIN_BOOTSTRAP: "true" };
    delete env.DB_SSL; delete env.PGSSLROOTCERT; delete env.DATABASE_URL;
    function migrate(maxVersion, fails = false, reviewedPreview = false) {
      const source = `const m=require(${JSON.stringify(entry)}); ${maxVersion ? `for(let i=m.migrations.length-1;i>=0;i--)if(m.migrations[i].version>${maxVersion})m.migrations.splice(i,1);` : ""} ${reviewedPreview ? `const {composeMigrations}=require("./apps/api/migrations/compose-migrations"); const original=m.migrations.filter(x=>x.version<=85||[92,93].includes(x.version)); const names=["operator_connections","operator_enrollment_grants","operator_action_requests"]; const prior=[...original,...names.map((name,i)=>({...m.migrations.find(x=>x.name===name),version:94+i}))]; const preview=composeMigrations(m.migrations,prior); m.migrations.splice(0,m.migrations.length,...preview);` : ""} m.runMigrations().then(()=>process.exit(0),e=>{console.error(e);process.exit(1)});`;
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
const ledger = async db => (await db.query("SELECT version,name,executed_at::text FROM migrations ORDER BY version")).rows;

test("fresh database applies the canonical rotation pair and restarts unchanged", { timeout: 120000 }, async () => {
  await withDatabase(async ({ target, migrate }) => {
    migrate();
    const before = await ledger(target);
    assert.deepEqual(before.filter(row => row.version >= 112).map(({ version, name }) => ({ version, name })), [
      { version: 112, name: "agent_credential_rotations" },
      { version: 113, name: "agent_credential_rotation_ack" },
    ]);
    migrate();
    assert.deepEqual(await ledger(target), before);
  });
});
for (const version of [108, 111]) {
  test(`released Core ledger through ${version} appends rotation once without rewriting history`, { timeout: 120000 }, async () => {
    await withDatabase(async ({ target, migrate }) => {
      migrate(version);
      const before = await ledger(target);
      assert.equal(before.at(-1).version, version);
      migrate();
      const after = await ledger(target);
      assert.deepEqual(after.filter(row => row.version <= version), before);
      assert.deepEqual(after.filter(row => row.version >= 112).map(({ version: n, name }) => ({ version: n, name })), [
        { version: 112, name: "agent_credential_rotations" },
        { version: 113, name: "agent_credential_rotation_ack" },
      ]);
      const relation = await target.query("SELECT to_regclass('certops_agent_credential_rotations') AS name");
      assert.equal(relation.rows[0].name, "certops_agent_credential_rotations");
      migrate();
      assert.deepEqual(await ledger(target), after);
    });
  });
}

test("reviewed noncanonical preview retains applied rotation identities on restart", { timeout: 120000 }, async () => {
  await withDatabase(async ({ target, migrate }) => {
    migrate(undefined, false, true);
    const before = await ledger(target);
    assert.equal(before.find(row => row.name === "agent_credential_rotations").version, 110);
    assert.equal(before.find(row => row.name === "agent_credential_rotation_ack").version, 111);
    migrate();
    assert.deepEqual(await ledger(target), before);
  });
});
for (const [version, name] of [[109, "agent_credential_rotations"], [110, "agent_credential_rotation_ack"]]) {
  test(`ambiguous preview ${version}/${name} is rejected without SQL or ledger changes`, { timeout: 120000 }, async () => {
    await withDatabase(async ({ target, migrate }) => {
      migrate(108);
      await target.query("INSERT INTO migrations(version,name) VALUES($1,$2)", [version, name]);
      const before = await ledger(target);
      assert.equal((await target.query("SELECT to_regclass('certops_agent_credential_rotations') AS name")).rows[0].name, null);
      assert.match(migrate(undefined, true), /Unsupported ambiguous agent credential rotation preview history/);
      assert.deepEqual(await ledger(target), before);
      assert.equal((await target.query("SELECT to_regclass('certops_agent_credential_rotations') AS name")).rows[0].name, null);
    });
  });
}
