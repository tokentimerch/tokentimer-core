"use strict";

// Invoked by the optional network test against its isolated local database.
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { Client, Pool } = require("pg");
const express = require("node:module").createRequire(require.resolve("../../apps/api/package.json"))("express");
const { migrations } = require("../../apps/api/migrations/migrate");
const { listCertificateIdentities } = require("../../apps/api/services/certops/certificateIdentity");
const { generateAgentCredential } = require("../../apps/api/services/certops/agentCredentials");
const { createAgentCredentialAuth } = require("../../apps/api/middleware/agent-auth");
const { createCertOpsAgentRouter } = require("../../apps/api/routes/certops-agent");
const { createProtocolClient } = require("../../packages/agent/src/protocol");

async function main() {
  if (process.env.DB_HOST !== "127.0.0.1" || process.env.DB_NAME !== "revocation_test") throw new Error("probe requires its isolated local test database");
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  const items = JSON.parse(input);
  const options = { host: process.env.DB_HOST, port: Number(process.env.DB_PORT), user: process.env.DB_USER, password: process.env.DB_PASSWORD };
  const database = `tt_revocation_probe_${process.pid}_${Date.now()}`;
  const admin = new Client({ ...options, database: process.env.DB_NAME });
  await admin.connect();
  let db, server;
  try {
    await admin.query(`CREATE DATABASE ${database}`);
    db = new Pool({ ...options, database });
    for (const migration of migrations) await db.query(migration.sql);
    const userId = (await db.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method) VALUES('probe@example.test','probe@example.test','Probe','x','local') RETURNING id")).rows[0].id;
    const workspaceId = (await db.query("INSERT INTO workspaces(id,name,plan,created_by,certops_managed_identity_limit) VALUES(gen_random_uuid(),'Revocation probe','oss',$1,1) RETURNING id", [userId])).rows[0].id;
    const agentId = `probe-${randomUUID()}`;
    const credential = generateAgentCredential();
    await db.query("INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash) VALUES($1,$2,'test','1.0.0',$3,$4)", [workspaceId, agentId, credential.credentialPrefix, credential.credentialHash]);
    const app = express();
    app.use(express.json({ limit: "2mb" }));
    app.use(createCertOpsAgentRouter({ dbPool: db, credentialAuthMiddleware: createAgentCredentialAuth({ client: db }), certOpsEnabledMiddleware: (_req, _res, next) => next() }));
    server = await new Promise((resolve) => { const listener = app.listen(0, "127.0.0.1", () => resolve(listener)); });
    const client = createProtocolClient({ serverUrl: `http://127.0.0.1:${server.address().port}`, allowInsecureLocalHttp: true, agentId, protocolVersion: "1.0.0", getCredential: async () => credential.plaintextCredential });
    await client.reportEvidence({ evidenceItems: items });
    const grouped = await listCertificateIdentities({ workspaceId, client: db });
    assert.equal(grouped.items.length, 1);
    assert.equal(grouped.items[0].observedRevocation.verdict, "revoked");
    assert.equal(grouped.items[0].revocationObservable, true);
    assert.equal(grouped.items[0].locationCount, 2);
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (db) await db.end();
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.end();
  }
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
