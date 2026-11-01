"use strict";

// Real PostgreSQL model/row-lock coverage in an explicitly disposable database.
// The HTTP/model interleavings have separate recording-transport unit coverage.
const { before, after, beforeEach, test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");
const { Pool } = require("pg");

let pool, observer, Token, createdSchema = false;
const workspaceId = "11111111-1111-4111-8111-111111111111";
const original = "2090-01-01", observed = "2091-02-02";

before(async () => {
  assert.match(process.env.DB_NAME || "", /_token_expiry_test$/,
    "Use a disposable *_token_expiry_test database");
  const config = {
    host: process.env.DB_HOST || "127.0.0.1", port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
  };
  observer = new Pool(config);
  await observer.query("CREATE SCHEMA token_expiry_guard_test");
  createdSchema = true;
  pool = new Pool({ ...config, options: "-c search_path=token_expiry_guard_test", application_name: "token-expiry-guard-test" });
  await pool.query(`CREATE TABLE tokens (
    id INTEGER PRIMARY KEY, workspace_id UUID NOT NULL, type TEXT, category TEXT,
    source_provider TEXT, expiration DATE, notes TEXT, updated_at TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE TABLE managed_certificates (workspace_id UUID, token_id INTEGER REFERENCES tokens(id));
  CREATE TABLE domain_monitors (workspace_id UUID, token_id INTEGER REFERENCES tokens(id));`);
  const file = path.resolve(__dirname, "../../apps/api/db/models/Token.js");
  const loaded = new Module(file, module);
  loaded.filename = file;
  loaded.paths = Module._nodeModulePaths(path.dirname(file));
  loaded.require = function (name) {
    if (name === "../database") return { pool };
    if (name === "../../utils/logger.js") return { logger: { error() {} } };
    return Module.prototype.require.call(this, name);
  };
  loaded._compile(fs.readFileSync(file, "utf8"), file);
  Token = loaded.exports;
});

beforeEach(async () => {
  await pool.query("TRUNCATE domain_monitors, managed_certificates, tokens");
  await pool.query("INSERT INTO tokens(id,workspace_id,type,category,expiration) VALUES(1,$1,'tls_cert','cert',$2)",
    [workspaceId, original]);
});

after(async () => {
  await pool?.end();
  if (createdSchema) await observer.query("DROP SCHEMA token_expiry_guard_test CASCADE");
  await observer?.end();
});

async function waitForTokenLock() {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const waiting = await observer.query(`SELECT 1 FROM pg_stat_activity
      WHERE application_name='token-expiry-guard-test' AND wait_event_type='Lock'
      AND query LIKE '%FROM tokens%FOR UPDATE%'`);
    if (waiting.rowCount) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.fail("Manual update did not wait for the actual token ownership lock");
}

test("unchanged manual metadata never writes a later provider expiration", async () => {
  await pool.query("UPDATE tokens SET source_provider='vault',expiration=$1 WHERE id=1", [observed]);
  const result = await Token.update(1, { notes: "Metadata edit", expiration: original },
    { manualExpirationSnapshot: original });
  assert.equal(result.expiresAt, observed);
  assert.equal(result.notes, "Metadata edit");
});

for (const ownership of ["provider", "managed_certificates", "domain_monitors"]) {
  test(`manual expiry waits for concurrent ${ownership} ownership and then refuses`, { timeout: 10000 }, async () => {
    const writer = await pool.connect();
    let pending;
    try {
      await writer.query("BEGIN");
      if (ownership === "provider")
        await writer.query("UPDATE tokens SET source_provider='vault',expiration=$1 WHERE id=1", [observed]);
      else
        await writer.query(`INSERT INTO ${ownership}(workspace_id,token_id) VALUES($1,1)`, [workspaceId]);
      pending = Token.update(1, { expiration: "2092-03-03", notes: "Must not write" },
        { manualExpirationSnapshot: original }).then((value) => ({ value }), (error) => ({ error }));
      await waitForTokenLock();
      await writer.query("COMMIT");
      const result = await pending;
      assert.equal(result.error?.code, "VERIFIED_CERTIFICATE_EXPIRY_REQUIRED");
      const row = (await pool.query("SELECT expiration::text,notes FROM tokens WHERE id=1")).rows[0];
      assert.equal(row.expiration, ownership === "provider" ? observed : original);
      assert.equal(row.notes, null);
    } finally {
      await writer.query("ROLLBACK");
      writer.release();
      await pending;
    }
  });
}

test("unowned manual expiry edits and trusted provider updates remain supported", async () => {
  assert.equal((await Token.update(1, { expiration: observed },
    { manualExpirationSnapshot: original })).expiresAt, observed);
  await pool.query("UPDATE tokens SET source_provider='vault' WHERE id=1");
  assert.equal((await Token.update(1, { expiration: "2092-03-03" })).expiresAt, "2092-03-03");
});

test("a caller-owned transaction retains its commit/rollback boundary", async () => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await Token.update(1, { expiration: observed }, { client, manualExpirationSnapshot: original });
    await client.query("ROLLBACK");
    assert.equal((await pool.query("SELECT expiration::text FROM tokens WHERE id=1")).rows[0].expiration, original);
  } finally {
    client.release();
  }
});
