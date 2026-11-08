"use strict";

const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { Client, Pool } = require("pg");
const express = require("express");
const request = require("supertest");
const { migrations } = require("../../../apps/api/migrations/migrate");
let generateAgentCredential, validateAgentCredential, claimJobs;


const connection = { host: process.env.DB_HOST || "localhost", port: Number(process.env.DB_PORT || 5432), user: process.env.DB_USER || "tokentimer", password: process.env.DB_PASSWORD || "password" };
const database = `agent_retirement_http_${process.pid}_${Date.now()}`;
const adminDatabase = process.env.DB_NAME || "tokentimer";

describe("HTTP retirement concurrent with claim on PostgreSQL", function () {
  this.timeout(120000);
  let db, apiPool, app, workspaceId, userId;
  before(async () => {
    const admin = new Client({ ...connection, database: adminDatabase });
    await admin.connect(); try { await admin.query(`CREATE DATABASE ${database}`); } finally { await admin.end(); }
    db = new Pool({ ...connection, database });
    for (const migration of migrations) await db.query(migration.sql);
    for (const migration of migrations) if (migration.postCommitSql) await db.query(migration.postCommitSql);
    process.env.DB_NAME = database;
    process.env.DB_PASSWORD = connection.password;
    process.env.CERTOPS_ENABLED = "true";
    ({ generateAgentCredential, validateAgentCredential } = require("../../../apps/api/services/certops/agentCredentials"));
    ({ claimJobs } = require("../../../apps/api/services/certops/agentDispatch"));
    const router = require("../../../apps/api/routes/certops");
    apiPool = require("../../../apps/api/db/database").pool;
    const email = `http-retire-${randomUUID()}@example.test`;
    userId = (await db.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method) VALUES ($1,$2,'Retire HTTP','x','local') RETURNING id", [email, email])).rows[0].id;
    workspaceId = randomUUID();
    await db.query("INSERT INTO workspaces (id,name,created_by,plan) VALUES ($1,'HTTP race',$2,'oss')", [workspaceId, userId]);
    app = express(); app.use(express.json());
    app.use((req, _res, next) => { req.workspace = { id: workspaceId }; req.user = { id: userId }; req.authz = { workspaceRole: "workspace_manager" }; next(); });
    app.use(router);
  });
  after(async () => {
    if (apiPool) await apiPool.end();
    if (db) await db.end();
    const admin = new Client({ ...connection, database: adminDatabase });
    await admin.connect(); try { await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`); } finally { await admin.end(); }
  });
  it("authenticates real agent claim requests before and after HTTP retirement", async () => {
    const { createCertOpsAgentRouter } = require("../../../apps/api/routes/certops-agent");
    const { createAgentCredentialAuth } = require("../../../apps/api/middleware/agent-auth");
    const credential = generateAgentCredential();
    const name = `agent-${randomUUID()}`;
    const agentId = (await db.query(`INSERT INTO certops_agents (workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
      VALUES ($1,$2,'0.18.2','1.0.0',$3,$4) RETURNING id`, [workspaceId, name, credential.credentialPrefix, credential.credentialHash])).rows[0].id;
    const machine = express();
    machine.use(express.json());
    machine.use(createCertOpsAgentRouter({ dbPool: db, credentialAuthMiddleware: createAgentCredentialAuth({ client: db }) }));
    const route = "/api/v1/certops/agent/jobs/claim";
    const payload = sequence => ({ schemaVersion: 1, protocolVersion: "1.0.0", messageType: "claim", agentId: name, workspaceId: null, sentAt: new Date().toISOString(), clockOffsetMs: null, sequence, body: { maxJobs: 1, supportedActions: [] } });
    assert.equal((await request(machine).post(route).set("Authorization", "Bearer invalid").send(payload(1))).status, 401);
    const active = await request(machine).post(route).set("Authorization", `Bearer ${credential.plaintextCredential}`).send(payload(1));
    assert.equal(active.status, 200, JSON.stringify(active.body));
    assert.deepEqual(active.body.jobs, []);
    const retirement = await request(app).post(`/api/v1/workspaces/${workspaceId}/certops/agents/${agentId}/retire`).send({});
    assert.equal(retirement.status, 200, JSON.stringify(retirement.body));
    const retired = await request(machine).post(route).set("Authorization", `Bearer ${credential.plaintextCredential}`).send(payload(2));
    assert.equal(retired.status, 410, JSON.stringify(retired.body));
    assert.equal(retired.body.code, "CERTOPS_AGENT_RETIRED");
  });
  it("requires a real operator session and workspace access to retire an agent", async () => {
    const bcrypt = require("bcryptjs");
    const session = require("express-session");
    const passport = require("passport");
    const { requireAuth } = require("../../../apps/api/middleware/auth");
    const { loadWorkspace, requireWorkspaceMembership } = require("../../../apps/api/services/rbac");
    process.env.SESSION_SECRET = "test-session-secret-for-isolated-postgres-only";
    const authRouter = require("../../../apps/api/routes/auth");
    const realApp = express();
    realApp.use(express.json());
    realApp.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));
    realApp.use(passport.initialize());
    realApp.use(passport.session());
    realApp.use(authRouter);
    realApp.use("/api/v1/workspaces/:id", requireAuth, loadWorkspace, requireWorkspaceMembership);
    realApp.use(require("../../../apps/api/routes/certops"));
    const password = "FixturePassword123!";
    const hash = await bcrypt.hash(password, 10);
    const email = `session-retire-${randomUUID()}@example.test`;
    const owner = (await db.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES ($1,$2,'Session Owner',$3,'local',TRUE) RETURNING id", [email, email, hash])).rows[0].id;
    const realWorkspace = randomUUID();
    await db.query("INSERT INTO workspaces (id,name,created_by,plan) VALUES ($1,'Real session',$2,'oss')", [realWorkspace, owner]);
    const credential = generateAgentCredential();
    const agentId = (await db.query(`INSERT INTO certops_agents (workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
      VALUES ($1,$2,'0.18.2','1.0.0',$3,$4) RETURNING id`, [realWorkspace, `session-agent-${randomUUID()}`, credential.credentialPrefix, credential.credentialHash])).rows[0].id;
    const route = `/api/v1/workspaces/${realWorkspace}/certops/agents/${agentId}/retire`;
    assert.equal((await request(realApp).post(route).send({})).status, 401);
    const outsiderEmail = `session-outsider-${randomUUID()}@example.test`;
    await db.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES ($1,$2,'Session Outsider',$3,'local',TRUE)", [outsiderEmail, outsiderEmail, hash]);
    const outsider = request.agent(realApp);
    assert.equal((await outsider.post("/auth/login").send({ email: outsiderEmail, password })).status, 200);
    assert.equal((await outsider.post(route).send({})).status, 403);
    const operator = request.agent(realApp);
    const login = await operator.post("/auth/login").send({ email, password });
    assert.equal(login.status, 200, JSON.stringify(login.body));
    const retirement = await operator.post(route).send({});
    assert.equal(retirement.status, 200, JSON.stringify(retirement.body));
    assert.equal((await db.query("SELECT status FROM certops_agents WHERE id=$1", [agentId])).rows[0].status, "retired");
  });
  it("serializes a waiting HTTP retirement before a real claim", async () => {
    const credential = generateAgentCredential();
    const agentId = (await db.query(`INSERT INTO certops_agents (workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
      VALUES ($1,$2,'0.18.2','1.0.0',$3,$4) RETURNING id`, [workspaceId, `agent-${randomUUID()}`, credential.credentialPrefix, credential.credentialHash])).rows[0].id;
    const jobId = (await db.query(`INSERT INTO certificate_jobs (workspace_id,operation,status,requested_by_user_id,executor_kind,mode)
      VALUES ($1,'issue','pending',$2,'agent','real') RETURNING id`, [workspaceId, userId])).rows[0].id;
    const agent = (await validateAgentCredential({ client: db, rawCredential: credential.plaintextCredential })).agent;
    const gate = await db.connect();
    let retirement, claim;
    try {
      await gate.query("BEGIN");
      await gate.query("SELECT id FROM certops_agents WHERE id=$1 FOR UPDATE", [agentId]);
      retirement = request(app).post(`/api/v1/workspaces/${workspaceId}/certops/agents/${agentId}/retire`).send({}).then(result => result);
      let httpWaiting = false;
      for (let i = 0; i < 100; i++) {
        const waiting = await db.query("SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND $2=ANY(pg_blocking_pids(pid))", [database, gate.processID]);
        if (waiting.rowCount) { httpWaiting = true; break; }
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      assert.equal(httpWaiting, true, "retirement route did not wait for the locked row");
      let resolveClaimClient;
      const claimClientReady = new Promise(resolve => { resolveClaimClient = resolve; });
      const claimPool = { connect: async () => { const client = await db.connect(); resolveClaimClient(client); return client; } };
      claim = claimJobs({ dbPool: claimPool, agent, body: { supportedActions: ["issue"] } }).then(value => ({ value }), error => ({ error }));
      const claimClient = await claimClientReady;
      let claimWaiting = false;
      for (let i = 0; i < 100; i++) {
        const waiting = await db.query("SELECT wait_event_type = 'Lock' AND cardinality(pg_blocking_pids(pid)) > 0 AS blocked FROM pg_stat_activity WHERE pid=$1", [claimClient.processID]);
        if (waiting.rows[0].blocked) { claimWaiting = true; break; }
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      assert.equal(claimWaiting, true, "claim did not wait for the locked row");
      await gate.query("COMMIT");
      const result = await retirement;
      assert.equal(result.status, 200, JSON.stringify(result.body));
      assert.equal((await claim).error?.code, "CERTOPS_AGENT_RETIRED");
      const state = await db.query("SELECT a.status AS agent_status,j.status AS job_status FROM certops_agents a JOIN certificate_jobs j ON j.id=$2 WHERE a.id=$1", [agentId, jobId]);
      assert.equal(state.rows[0].agent_status, "retired");
      assert.equal(state.rows[0].job_status, "pending");
    } finally {
      try { await gate.query("ROLLBACK"); } catch (_) {}
      gate.release();
      if (retirement) await retirement;
      if (claim) await claim;
    }
  });
  it("blocks HTTP retirement after a real claim acquires the agent lock", async () => {
    const credential = generateAgentCredential();
    const agentId = (await db.query(`INSERT INTO certops_agents (workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
      VALUES ($1,$2,'0.18.2','1.0.0',$3,$4) RETURNING id`, [workspaceId, `agent-${randomUUID()}`, credential.credentialPrefix, credential.credentialHash])).rows[0].id;
    const jobId = (await db.query(`INSERT INTO certificate_jobs (workspace_id,operation,status,requested_by_user_id,executor_kind,mode)
      VALUES ($1,'noop','pending',$2,'agent','real') RETURNING id`, [workspaceId, userId])).rows[0].id;
    const agent = (await validateAgentCredential({ client: db, rawCredential: credential.plaintextCredential })).agent;
    let resolveClaimClient, signalLocked, releaseClaim;
    const claimClientReady = new Promise(resolve => { resolveClaimClient = resolve; });
    const claimLocked = new Promise(resolve => { signalLocked = resolve; });
    const claimMayProceed = new Promise(resolve => { releaseClaim = resolve; });
    const claimPool = { connect: async () => { const client = await db.connect(); resolveClaimClient(client); return client; } };
    const claim = claimJobs({ dbPool: claimPool, agent, body: { supportedActions: ["noop"] }, deps: {
      enforceAgentSequence: async () => { signalLocked(); await claimMayProceed; },
      signJobForDispatch: async ({ job }) => job,
    } }).then(value => ({ value }), error => ({ error }));
    let retirement;
    try {
      const claimClient = await claimClientReady;
      await claimLocked;
      retirement = request(app).post(`/api/v1/workspaces/${workspaceId}/certops/agents/${agentId}/retire`).send({}).then(result => result);
      let httpWaiting = false;
      for (let i = 0; i < 100; i++) {
        const waiting = await db.query("SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND $2=ANY(pg_blocking_pids(pid))", [database, claimClient.processID]);
        if (waiting.rowCount) { httpWaiting = true; break; }
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      assert.equal(httpWaiting, true, "retirement route did not wait for the claim");
      releaseClaim();
      const claimResult = await claim;
      assert.equal(claimResult.error, undefined, String(claimResult.error));
      assert.equal(claimResult.value.jobs.length, 1);
      const result = await retirement;
      assert.equal(result.status, 409, JSON.stringify(result.body));
      assert.equal(result.body.code, "CERTOPS_AGENT_RETIRE_BLOCKED");
      const state = await db.query("SELECT a.status AS agent_status,j.status AS job_status FROM certops_agents a JOIN certificate_jobs j ON j.id=$2 WHERE a.id=$1", [agentId, jobId]);
      assert.equal(state.rows[0].agent_status, "active");
      assert.equal(state.rows[0].job_status, "claimed");
    } finally {
      releaseClaim();
      await claim;
      if (retirement) await retirement;
    }
  });
});
