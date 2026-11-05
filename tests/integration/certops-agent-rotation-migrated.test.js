"use strict";
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { Client, Pool } = require("pg");
const supertest = require("supertest");
const express = require("node:module").createRequire(require("node:path").resolve(__dirname, "../../apps/api/package.json"))("express");
const { createCertOpsAgentRouter } = require("../../apps/api/routes/certops-agent");
const { createAgentCredentialAuth } = require("../../apps/api/middleware/agent-auth");
const { createCertOpsMachineWritePreParserBoundary } = require("../../apps/api/middleware/certops-executor-body-parser");
const { createCsrfExemptMiddleware, isCertOpsMachineTokenCsrfExemptPath } = require("../../apps/api/middleware/csrf-exempt");
const { createProtocolClient } = require("../../packages/agent/src/protocol/index.js");
const { migrations } = require("../../apps/api/migrations/migrate");
const { generateAgentCredential, validateAgentCredential } = require("../../apps/api/services/certops/agentCredentials");
const { prepareCredentialRotation, confirmCredentialRotation } = require("../../apps/api/services/certops/agentCredentialRotation");
const connection = { host: process.env.DB_HOST || "localhost", port: Number(process.env.DB_PORT || 5432), user: process.env.DB_USER || "tokentimer", password: process.env.DB_PASSWORD || "password" };
const database = `agent_rotation_full_${process.pid}_${Date.now()}`;
describe("Agent credential rotation on migrated schema", function () {
  this.timeout(120000); let db;
  before(async () => {
    const admin = new Client({ ...connection, database: process.env.DB_NAME || "tokentimer" });
    await admin.connect(); try { await admin.query(`CREATE DATABASE ${database}`); } finally { await admin.end(); }
    db = new Pool({ ...connection, database });
    for (const migration of migrations) await db.query(migration.sql);
  });
  after(async () => {
    if (db) await db.end();
    const admin = new Client({ ...connection, database: process.env.DB_NAME || "tokentimer" });
    await admin.connect(); try { await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`); } finally { await admin.end(); }
  });
  it("commits the rotation and exactly one real audit event", async () => {
    const email = `rotation-${randomUUID()}@example.test`;
    const user = (await db.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method) VALUES ($1,$2,'Rotation Test','x','local') RETURNING id", [email, email])).rows[0];
    const workspaceId = randomUUID(); await db.query("INSERT INTO workspaces (id,name,created_by,plan) VALUES ($1,'rotation test',$2,'oss')", [workspaceId,user.id]);
    const old = generateAgentCredential(), next = generateAgentCredential(), agentId = `agent-${randomUUID()}`;
    const agentRow = (await db.query(`INSERT INTO certops_agents (workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
      VALUES ($1,$2,'0.18.2','1.0.0',$3,$4) RETURNING id`, [workspaceId,agentId,old.credentialPrefix,old.credentialHash])).rows[0];
    const agent = (await validateAgentCredential({ client: db, rawCredential: old.plaintextCredential })).agent;
    const operationId = randomUUID().replaceAll("-", ""), env = { CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true" };
    await prepareCredentialRotation({ dbPool: db, agent, operationId, candidatePrefix: next.credentialPrefix, candidateHash: next.credentialHash, env });
    await confirmCredentialRotation({ dbPool: db, operationId, rawCandidate: next.plaintextCredential, env });
    await confirmCredentialRotation({ dbPool: db, operationId, rawCandidate: next.plaintextCredential, env });
    assert.equal((await validateAgentCredential({ client: db, rawCredential: old.plaintextCredential })).valid, false);
    assert.equal((await validateAgentCredential({ client: db, rawCredential: next.plaintextCredential })).agent.id, agentRow.id);
    const events = await db.query("SELECT action, metadata FROM audit_events WHERE workspace_id = $1 AND action = 'CERTOPS_AGENT_CREDENTIAL_ROTATED'", [workspaceId]);
    assert.equal(events.rows.length, 1); assert.equal(events.rows[0].metadata.agentId, agentId);
    assert.equal(JSON.stringify(events.rows).includes(next.plaintextCredential), false);
  });
  it("enforces HTTP gate, auth, body shape and pre-auth rate limit on both steps", async () => {
    const email = `rotation-http-${randomUUID()}@example.test`;
    const user = (await db.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method) VALUES ($1,$2,'Rotation HTTP','x','local') RETURNING id", [email,email])).rows[0];
    const workspaceId = randomUUID(); await db.query("INSERT INTO workspaces (id,name,created_by,plan) VALUES ($1,'rotation HTTP',$2,'oss')", [workspaceId,user.id]);
    const old = generateAgentCredential(), next = generateAgentCredential();
    await db.query(`INSERT INTO certops_agents (workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
      VALUES ($1,$2,'0.18.2','1.0.0',$3,$4)`, [workspaceId,`agent-${randomUUID()}`,old.credentialPrefix,old.credentialHash]);
    const operationId = randomUUID().replaceAll("-", "");
    const paths = { prepare: "/api/v1/certops/agent/credential-rotation/prepare", confirm: "/api/v1/certops/agent/credential-rotation/confirm" };
    const body = { operationId, candidatePrefix: next.credentialPrefix, candidateHash: next.credentialHash };
    const makeApp = (rotationEnv, options = {}) => {
      const app = express();
      app.use(createCertOpsMachineWritePreParserBoundary(options.boundary));
      if (options.fakeSession) app.use((req, _res, nextMiddleware) => { req.session = { userId: 123 }; nextMiddleware(); });
      app.use(createCsrfExemptMiddleware((_req, res) => res.status(403).json({ error: "csrf" }), { allowPath: isCertOpsMachineTokenCsrfExemptPath }));
      app.use(createCertOpsAgentRouter({ dbPool: db, rotationEnv,
        credentialAuthMiddleware: createAgentCredentialAuth({ client: db }),
        certOpsEnabledMiddleware: (_req,_res,nextMiddleware) => nextMiddleware(), ...options.router }));
      return app;
    };
    const disabled = makeApp({});
    assert.equal((await supertest(disabled).post(paths.prepare).send(body)).status, 404);
    assert.equal((await supertest(disabled).post(paths.confirm).send({ operationId })).status, 404);
    const enabled = makeApp({ CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true" });
    assert.equal((await supertest(enabled).post(paths.prepare).send(body)).status, 401);
    assert.equal((await supertest(enabled).post(paths.prepare).set("Authorization", `Bearer ${old.plaintextCredential}`).send({ ...body, extra: 1 })).status, 400);
    assert.equal((await supertest(enabled).post(paths.prepare).set("Authorization", `Bearer ${old.plaintextCredential}`).send(body)).status, 200);
    const sessionApp = makeApp({ CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true" }, { fakeSession: true });
    assert.equal((await supertest(sessionApp).post(paths.confirm).set("Authorization", `Bearer ${next.plaintextCredential}`).send({ operationId })).status, 401);
    const auditsBefore = Number((await db.query("SELECT count(*) FROM audit_events")).rows[0].count);
    const invalidCandidate = generateAgentCredential().plaintextCredential;
    assert.equal((await supertest(enabled).post(paths.confirm).set("Authorization", `Bearer ${invalidCandidate}`).send({ operationId, extra: "-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----" })).status, 401);
    assert.equal(Number((await db.query("SELECT count(*) FROM audit_events")).rows[0].count), auditsBefore);
    assert.equal((await supertest(enabled).post(paths.confirm).set("Authorization", `Bearer ${next.plaintextCredential}`).send({ operationId, extra: 1 })).status, 400);
    assert.equal((await supertest(enabled).post(paths.confirm).set("Authorization", `Bearer ${old.plaintextCredential}`).send({ operationId })).status, 401);
    assert.equal((await supertest(enabled).post(paths.confirm).set("Authorization", `Bearer ${next.plaintextCredential}`).send({ operationId })).status, 200);
    assert.equal((await supertest(enabled).post(paths.confirm).set("Authorization", `Bearer ${next.plaintextCredential}`).send({ operationId })).status, 200);
    assert.equal((await supertest(enabled).post(paths.prepare).set("Authorization", `Bearer ${old.plaintextCredential}`).send(body)).status, 401);
    const bounded = makeApp({ CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true" }, { boundary: { parserOptions: { limitBytes: 128 } } });
    assert.equal((await supertest(bounded).post(paths.confirm).set("Authorization", `Bearer ${next.plaintextCredential}`).send({ operationId, padding: "x".repeat(300) })).status, 413);
    const limited = makeApp({ CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true" }, { boundary: { rateLimitOptions: { limit: 1 } } });
    const malformed = generateAgentCredential().plaintextCredential;
    assert.equal((await supertest(limited).post(paths.confirm).set("Authorization", `Bearer ${malformed}`).send({ operationId })).status, 401);
    assert.equal((await supertest(limited).post(paths.confirm).set("Authorization", `Bearer ${malformed}`).send({ operationId })).status, 429);
  });

  it("client retries confirmation with the candidate after a real committed response is lost", async () => {
    const email = `rotation-client-${randomUUID()}@example.test`;
    const user = (await db.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method) VALUES ($1,$2,'Rotation Client','x','local') RETURNING id", [email,email])).rows[0];
    const workspaceId = randomUUID(); await db.query("INSERT INTO workspaces (id,name,created_by,plan) VALUES ($1,'rotation client',$2,'oss')", [workspaceId,user.id]);
    const old = generateAgentCredential(), next = generateAgentCredential(), agentId = `agent-${randomUUID()}`;
    await db.query(`INSERT INTO certops_agents (workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
      VALUES ($1,$2,'0.18.2','1.0.0',$3,$4)`, [workspaceId,agentId,old.credentialPrefix,old.credentialHash]);
    const app = express(); app.use(createCertOpsMachineWritePreParserBoundary());
    app.use(createCertOpsAgentRouter({ dbPool: db, rotationEnv: { CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true" }, credentialAuthMiddleware: createAgentCredentialAuth({ client: db }), certOpsEnabledMiddleware: (_req,_res,nextMiddleware) => nextMiddleware() }));
    const listener = await new Promise(resolve => { const srv = app.listen(0,"127.0.0.1",() => resolve(srv)); });
    try {
      let dropConfirmResponse = true;
      const transport = async (url, options) => {
        const response = await fetch(url, options);
        if (url.endsWith("/credential-rotation/confirm") && dropConfirmResponse) { dropConfirmResponse = false; throw new Error("simulated lost response"); }
        return response;
      };
      const client = createProtocolClient({ serverUrl: `http://127.0.0.1:${listener.address().port}`, allowInsecureLocalHttp: true, agentId, protocolVersion: "1.0.0", getCredential: () => old.plaintextCredential, fetchImpl: transport });
      const operationId = randomUUID().replaceAll("-", "");
      assert.deepEqual(await client.prepareCredentialRotation({ operationId, candidatePrefix: next.credentialPrefix, candidateHash: next.credentialHash }), { state: "pending" });
      await assert.rejects(client.confirmCredentialRotation({ operationId, candidateCredential: next.plaintextCredential }), { code: "network_error" });
      assert.equal((await validateAgentCredential({ client: db, rawCredential: old.plaintextCredential })).valid, false);
      assert.deepEqual(await client.confirmCredentialRotation({ operationId, candidateCredential: next.plaintextCredential }), { state: "committed" });
      assert.equal((await validateAgentCredential({ client: db, rawCredential: next.plaintextCredential })).agent.agentId, agentId);
    } finally { await new Promise((resolve,reject) => listener.close(error => error ? reject(error) : resolve())); }
  });

});
