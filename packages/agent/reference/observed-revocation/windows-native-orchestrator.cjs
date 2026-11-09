"use strict";

// A disposable hosted runner must provide a dedicated loopback PostgreSQL
// instance and a private interface for the signed CRL/OCSP responder.
if (process.platform !== "win32" || process.env.CERTOPS_REVOCATION_NATIVE_WINDOWS !== "1" ||
    process.env.RUNNER_ENVIRONMENT !== "github-hosted" || process.env.CI !== "true") {
  throw new Error("Native fixture requires an explicitly enabled disposable GitHub-hosted Windows runner");
}
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { spawn } = require("node:child_process");
const { createRequire } = require("node:module");
const path = require("node:path");
const express = createRequire(path.resolve(__dirname, "../../../../apps/api/package.json"))("express");
const { Client, Pool } = require("pg");
const { migrations, applyMigrationSql, applyPostCommitSql } = require("../../../../apps/api/migrations/migrate");
const { generateAgentCredential } = require("../../../../apps/api/services/certops/agentCredentials");
const { createAgentCredentialAuth } = require("../../../../apps/api/middleware/agent-auth");
const { createCertOpsAgentRouter } = require("../../../../apps/api/routes/certops-agent");

async function main() {
  assert.equal(process.env.DB_HOST, "127.0.0.1");
  assert.equal(process.env.DB_NAME, "revocation_test");
  assert.ok(process.env.CERTOPS_REVOCATION_TEST_IP);
  assert.ok(process.env.CERTOPS_REVOCATION_TEST_HELPER);
  const connection = { host: process.env.DB_HOST, port: Number(process.env.DB_PORT), user: process.env.DB_USER, password: process.env.DB_PASSWORD };
  const database = `tt_native_revocation_${randomUUID().replaceAll("-", "")}`;
  const admin = new Client({ ...connection, database: "revocation_test" });
  await admin.connect();
  let db, server, created = false;
  try {
    await admin.query(`CREATE DATABASE ${database}`);
    created = true;
    db = new Pool({ ...connection, database });
    const migrationClient = await db.connect();
    try { for (const migration of migrations) { await applyMigrationSql(migrationClient, migration); await applyPostCommitSql(migrationClient, migration); } }
    finally { migrationClient.release(); }
    const user = (await db.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method) VALUES('native-probe@example.test','native-probe@example.test','Probe','x','local') RETURNING id")).rows[0];
    const workspace = (await db.query("INSERT INTO workspaces(id,name,plan,created_by,certops_managed_identity_limit) VALUES(gen_random_uuid(),'Native probe','oss',$1,1) RETURNING id", [user.id])).rows[0];
    const agentId = `probe-${randomUUID()}`, credential = generateAgentCredential();
    await db.query("INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash) VALUES($1,$2,'test','1.0.0',$3,$4)", [workspace.id, agentId, credential.credentialPrefix, credential.credentialHash]);
    const app = express();
    app.use(express.json());
    app.use(createCertOpsAgentRouter({ dbPool: db, credentialAuthMiddleware: createAgentCredentialAuth({ client: db }), certOpsEnabledMiddleware: (_req, _res, next) => next() }));
    server = await new Promise((resolve) => { const listener = app.listen(0, "127.0.0.1", () => resolve(listener)); });
    const env = { ...process.env, DB_NAME: database, CERTOPS_REVOCATION_TEST_AGENT_PROBE: "1", CERTOPS_REVOCATION_TEST_DB_PROBE: "0",
      TT_NATIVE_REVOCATION_API: `http://127.0.0.1:${server.address().port}`, TT_NATIVE_REVOCATION_AGENT: agentId,
      TT_NATIVE_REVOCATION_CREDENTIAL: credential.plaintextCredential, TT_NATIVE_REVOCATION_WORKSPACE: workspace.id };
    const code = await new Promise((resolve, reject) => {
      const child = spawn("go", ["test", "-mod=readonly", "-timeout=20m", "-count=1", "-run", "^TestNetworkCRLAndOCSP$", "-v"], { cwd: __dirname, env, stdio: "inherit", windowsHide: true });
      child.on("error", reject); child.on("exit", resolve);
    });
    assert.equal(code, 0, "native Windows revocation test failed");
  } finally {
    try { if (server) await new Promise((resolve) => server.close(resolve)); }
    finally {
      try { if (db) await db.end(); }
      finally {
        try {
          if (created) {
            await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
            const remaining = await admin.query("SELECT 1 FROM pg_database WHERE datname = $1", [database]);
            assert.equal(remaining.rowCount, 0, "owned test database remains");
          }
        }
        finally { await admin.end(); }
      }
    }
  }
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
