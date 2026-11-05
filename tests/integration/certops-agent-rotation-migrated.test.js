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
const { claimJobs } = require("../../apps/api/services/certops/agentDispatch");
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
    const paths = { prepare: "/api/v1/certops/agent/credential-rotation/prepare", confirm: "/api/v1/certops/agent/credential-rotation/confirm", ack: "/api/v1/certops/agent/credential-rotation/acknowledge" };
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
    assert.equal((await supertest(disabled).post(paths.ack).send({ operationId })).status, 404);
    const enabled = makeApp({ CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true" });
    assert.equal((await supertest(enabled).post(paths.prepare).send(body)).status, 401);
    assert.equal((await supertest(enabled).post(paths.prepare).set("Authorization", `Bearer ${old.plaintextCredential}`).send({ ...body, extra: 1 })).status, 400);
    assert.equal((await supertest(enabled).post(paths.prepare).set("Authorization", `Bearer ${old.plaintextCredential}`).send(body)).status, 200);
    const before = (await validateAgentCredential({ client: db, rawCredential: old.plaintextCredential })).agent;
    let sequences = 0;
    const claimOptions = { dbPool: db, agent: before, body: { supportedActions: ["renew"] }, env: { CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true" }, deps: { enforceAgentSequence: async () => { sequences++; }, computeAgentCompatibility: () => { throw new Error("CLAIM_SELECTION_REACHED"); }, lockWorkspaceForCertOpsSideEffect: async () => {} } };
    assert.deepEqual(await claimJobs(claimOptions), { jobs: [], logStreams: [] });
    assert.equal(sequences, 1);
    claimOptions.env = {};
    assert.deepEqual(await claimJobs(claimOptions), { jobs: [], logStreams: [] });
    assert.equal(sequences, 2);
    claimOptions.env = { CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true" };
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
    assert.equal((await supertest(enabled).post(paths.ack).set("Authorization", `Bearer ${next.plaintextCredential}`).send({ operationId })).status, 404);
    const current = (await validateAgentCredential({ client: db, rawCredential: next.plaintextCredential })).agent;
    claimOptions.agent = current;
    assert.deepEqual(await claimJobs(claimOptions), { jobs: [], logStreams: [] });
    assert.equal(sequences, 3);
    const ackEnabled = makeApp({ CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true", CERTOPS_AGENT_ROTATION_ACK_ENABLED: "true" });
    assert.equal((await supertest(ackEnabled).post(paths.ack).set("Authorization", `Bearer ${old.plaintextCredential}`).send({ operationId })).status, 401);
    assert.equal((await supertest(ackEnabled).post(paths.ack).set("Authorization", `Bearer ${next.plaintextCredential}`).send({ operationId, extra: 1 })).status, 400);
    const uncertainJob = (await db.query(`INSERT INTO certificate_jobs (workspace_id, operation, status, needs_operator_reconciliation)
      VALUES ($1, 'renew', 'orphaned_unknown_effect', TRUE) RETURNING id`, [workspaceId])).rows[0];
    assert.equal((await supertest(ackEnabled).post(paths.ack).set("Authorization", `Bearer ${next.plaintextCredential}`).send({ operationId })).status, 409);
    assert.equal((await db.query("SELECT state FROM certops_agent_credential_rotations WHERE operation_id = $1", [operationId])).rows[0].state, "committed");
    // Fixture-only state change; the product has no supported closure flow yet.
    await db.query("UPDATE certificate_jobs SET status = 'succeeded', needs_operator_reconciliation = FALSE WHERE id = $1", [uncertainJob.id]);
    assert.equal((await supertest(ackEnabled).post(paths.ack).set("Authorization", `Bearer ${next.plaintextCredential}`).send({ operationId })).status, 200);
    assert.equal((await supertest(ackEnabled).post(paths.ack).set("Authorization", `Bearer ${next.plaintextCredential}`).send({ operationId })).status, 200);
    await assert.rejects(claimJobs(claimOptions), /CLAIM_SELECTION_REACHED/);
    assert.equal(sequences, 4);
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
    app.use(createCertOpsAgentRouter({ dbPool: db, rotationEnv: { CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true", CERTOPS_AGENT_ROTATION_ACK_ENABLED: "true" }, credentialAuthMiddleware: createAgentCredentialAuth({ client: db }), certOpsEnabledMiddleware: (_req,_res,nextMiddleware) => nextMiddleware() }));
    const listener = await new Promise(resolve => { const srv = app.listen(0,"127.0.0.1",() => resolve(srv)); });
    try {
      let dropConfirmResponse = true, dropAckResponse = true;
      const transport = async (url, options) => {
        const response = await fetch(url, options);
        if (url.endsWith("/credential-rotation/confirm") && dropConfirmResponse) { dropConfirmResponse = false; throw new Error("simulated lost response"); }
        if (url.endsWith("/credential-rotation/acknowledge") && dropAckResponse) { dropAckResponse = false; throw new Error("simulated lost ACK response"); }
        return response;
      };
      const client = createProtocolClient({ serverUrl: `http://127.0.0.1:${listener.address().port}`, allowInsecureLocalHttp: true, agentId, protocolVersion: "1.0.0", getCredential: () => old.plaintextCredential, fetchImpl: transport });
      const operationId = randomUUID().replaceAll("-", "");
      assert.deepEqual(await client.prepareCredentialRotation({ operationId, candidatePrefix: next.credentialPrefix, candidateHash: next.credentialHash }), { state: "pending" });
      await assert.rejects(client.confirmCredentialRotation({ operationId, candidateCredential: next.plaintextCredential }), { code: "network_error" });
      assert.equal((await validateAgentCredential({ client: db, rawCredential: old.plaintextCredential })).valid, false);
      assert.deepEqual(await client.confirmCredentialRotation({ operationId, candidateCredential: next.plaintextCredential }), { state: "committed" });
      await assert.rejects(client.acknowledgeCredentialRotation({ operationId, candidateCredential: next.plaintextCredential }), { code: "network_error" });
      assert.deepEqual(await client.acknowledgeCredentialRotation({ operationId, candidateCredential: next.plaintextCredential }), { state: "acknowledged" });
      const ackAudits = await db.query("SELECT count(*) FROM audit_events WHERE workspace_id = $1 AND action = 'CERTOPS_AGENT_CREDENTIAL_ROTATION_ACKNOWLEDGED'", [workspaceId]);
      assert.equal(Number(ackAudits.rows[0].count), 1);
      assert.equal((await validateAgentCredential({ client: db, rawCredential: next.plaintextCredential })).agent.agentId, agentId);
    } finally { await new Promise((resolve,reject) => listener.close(error => error ? reject(error) : resolve())); }
  });

  it("serializes preparation against a claim and fences later claims until ACK", async () => {
    const email = `rotation-race-${randomUUID()}@example.test`;
    const user = (await db.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method) VALUES ($1,$2,'Rotation Race','x','local') RETURNING id", [email,email])).rows[0];
    const workspaceId = randomUUID(); await db.query("INSERT INTO workspaces (id,name,created_by,plan) VALUES ($1,'rotation race',$2,'oss')", [workspaceId,user.id]);
    const old = generateAgentCredential(), next = generateAgentCredential(), agentId = `agent-${randomUUID()}`;
    const row = (await db.query(`INSERT INTO certops_agents (workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
      VALUES ($1,$2,'0.18.2','1.0.0',$3,$4) RETURNING id`, [workspaceId,agentId,old.credentialPrefix,old.credentialHash])).rows[0];
    const agent = (await validateAgentCredential({ client: db, rawCredential: old.plaintextCredential })).agent;
    const job = (await db.query(`INSERT INTO certificate_jobs (workspace_id,operation,status,requested_by_user_id,executor_kind,mode)
      VALUES ($1,'renew','pending',$2,'agent','real') RETURNING id`, [workspaceId,user.id])).rows[0];
    const rotation = { dbPool: db, agent, operationId: randomUUID().replaceAll("-", ""), candidatePrefix: next.credentialPrefix, candidateHash: next.credentialHash, env: { CERTOPS_AGENT_ROTATION_ALL_API_FENCED: "true" } };
    const claimant = await db.connect();
    try {
      await claimant.query("BEGIN");
      await claimant.query("SELECT id FROM certops_agents WHERE id = $1 FOR UPDATE", [row.id]);
      await claimant.query("UPDATE certificate_jobs SET status = 'claimed', claimed_by_agent_id = $2 WHERE id = $1", [job.id, row.id]);
      const pending = prepareCredentialRotation(rotation).then(() => null, error => error);
      let blocked = false;
      for (let i = 0; i < 100 && !blocked; i++) {
        const waiting = await db.query(`SELECT count(*) AS count FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%SELECT credential_hash, status%'`);
        blocked = Number(waiting.rows[0].count) > 0;
        if (!blocked) await new Promise(resolve => setTimeout(resolve, 20));
      }
      assert.equal(blocked, true);
      await claimant.query("COMMIT");
      assert.equal((await pending)?.code, "CERTOPS_AGENT_ROTATION_CONFLICT");
    } finally { try { await claimant.query("ROLLBACK"); } catch (_) {} claimant.release(); }
    await db.query("UPDATE certificate_jobs SET status = 'succeeded' WHERE id = $1", [job.id]);
    await prepareCredentialRotation(rotation);
    let sequenceCalls = 0;
    const response = await claimJobs({ dbPool: db, agent, env: rotation.env, body: { supportedActions: [] },
      deps: { enforceAgentSequence: async () => { sequenceCalls++; }, lockWorkspaceForCertOpsSideEffect: async () => {} } });
    assert.deepEqual(response, { jobs: [], logStreams: [] }); assert.equal(sequenceCalls, 1);
    await db.query("UPDATE certops_agents SET last_sequence = 5 WHERE id = $1", [agent.id]);
    await assert.rejects(claimJobs({ dbPool: db, agent, env: rotation.env, envelope: { sequence: 5 }, body: { supportedActions: [] } }), { code: "CERTOPS_AGENT_SEQUENCE_REGRESSION" });
    assert.deepEqual(await claimJobs({ dbPool: db, agent, env: rotation.env, envelope: { sequence: 6 }, body: { supportedActions: [] } }), { jobs: [], logStreams: [] });
    assert.equal(Number((await db.query("SELECT last_sequence FROM certops_agents WHERE id = $1", [agent.id])).rows[0].last_sequence), 6);
    await db.query("UPDATE certops_agent_credential_rotations SET expires_at = NOW() - interval '1 second' WHERE agent_id = $1", [agent.id]);
    await assert.rejects(claimJobs({ dbPool: db, agent, env: {}, envelope: { sequence: 7 }, body: { supportedActions: ["renew"] },
      deps: { computeAgentCompatibility: () => { throw new Error("EXPIRED_CLAIM_SELECTION_REACHED"); } } }), /EXPIRED_CLAIM_SELECTION_REACHED/);
  });

});
