"use strict";

const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { Client, Pool } = require("pg");
const { migrations } = require("../../apps/api/migrations/migrate");
const { getAgentById, countActivelyLeasedJobs, retireAgent } = require("../../apps/api/services/certops/agentRegistry");
const { generateAgentCredential, validateAgentCredential } = require("../../apps/api/services/certops/agentCredentials");
const { claimJobs } = require("../../apps/api/services/certops/agentDispatch");

const connection = { host: process.env.DB_HOST || "localhost", port: Number(process.env.DB_PORT || 5432), user: process.env.DB_USER || "tokentimer", password: process.env.DB_PASSWORD || "password" };
const database = `agent_retirement_lock_${process.pid}_${Date.now()}`;

describe("Agent retirement locking on PostgreSQL", function () {
  this.timeout(120000);
  let db;
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
  async function fixture() {
    const email = `retire-lock-${randomUUID()}@example.test`;
    const user = (await db.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method) VALUES ($1,$2,'Retire','x','local') RETURNING id", [email,email])).rows[0];
    const workspaceId = randomUUID();
    await db.query("INSERT INTO workspaces (id,name,created_by,plan) VALUES ($1,'retire lock',$2,'oss')", [workspaceId,user.id]);
    const credential = generateAgentCredential();
    const agent = (await db.query(`INSERT INTO certops_agents (workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
      VALUES ($1,$2,'0.18.2','1.0.0',$3,$4) RETURNING id`, [workspaceId, `agent-${randomUUID()}`,credential.credentialPrefix,credential.credentialHash])).rows[0];
    const job = (await db.query(`INSERT INTO certificate_jobs (workspace_id,operation,status,requested_by_user_id,executor_kind,mode)
      VALUES ($1,'issue','pending',$2,'agent','real') RETURNING id`, [workspaceId,user.id])).rows[0];
    return { workspaceId, agentId: agent.id, jobId: job.id, rawCredential: credential.plaintextCredential };
  }
  async function assertBlocked(waiter, blocker) {
    for (let i = 0; i < 100; i++) {
      const result = await db.query("SELECT $2 = ANY(pg_blocking_pids($1)) AS blocked", [waiter.processID, blocker.processID]);
      if (result.rows[0].blocked) return;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.fail("retirement did not wait for agent lock");
  }
  it("rejects a real claim already waiting when retirement commits", async () => {
    const f = await fixture(), retiring = await db.connect();
    const agent = (await validateAgentCredential({client:db, rawCredential:f.rawCredential})).agent;
    try {
      await retiring.query("BEGIN");
      await getAgentById({client:retiring, workspaceId:f.workspaceId, agentId:f.agentId, forUpdate:true});
      let resolveClaimClient;
      const claimClientReady = new Promise(resolve => { resolveClaimClient = resolve; });
      const claimPool = { connect: async () => { const client = await db.connect(); resolveClaimClient(client); return client; } };
      const claim = claimJobs({dbPool:claimPool, agent, body:{supportedActions:["issue"]}}).then(value => ({value}), error => ({error}));
      const claimClient = await claimClientReady;
      await assertBlocked(claimClient, retiring);
      assert.equal(await countActivelyLeasedJobs({client:retiring, agentId:f.agentId}), 0);
      assert.equal((await retireAgent({client:retiring, workspaceId:f.workspaceId, agentId:f.agentId})).retiredNow, true);
      await retiring.query("COMMIT");
      assert.equal((await claim).error?.code, "CERTOPS_AGENT_RETIRED");
      assert.equal((await db.query("SELECT status FROM certificate_jobs WHERE id=$1",[f.jobId])).rows[0].status,"pending");
    } finally { try { await retiring.query("ROLLBACK"); } catch (_) {} retiring.release(); }
  });
  for (const force of [false, true]) {
    it(`serializes ${force ? "forced" : "ordinary"} retirement after an in-flight claim`, async () => {
      const f = await fixture(), claim = await db.connect(), retiring = await db.connect();
      try {
        await claim.query("BEGIN");
        await claim.query("SELECT id FROM certops_agents WHERE id=$1 FOR UPDATE", [f.agentId]);
        await retiring.query("BEGIN");
        await retiring.query("SET LOCAL lock_timeout = '5s'");
        const locked = getAgentById({ client: retiring, workspaceId: f.workspaceId, agentId: f.agentId, forUpdate: true });
        await assertBlocked(retiring, claim);
        await claim.query(`UPDATE certificate_jobs SET status='claimed', claimed_by_agent_id=$2, lease_expires_at=NOW()+interval '5 minutes' WHERE id=$1`, [f.jobId,f.agentId]);
        await claim.query("COMMIT");
        assert.equal((await locked).id, f.agentId);
        const leased = await countActivelyLeasedJobs({client:retiring, agentId:f.agentId});
        assert.equal(leased, 1);
        if (force) {
          const result = await retireAgent({client:retiring, workspaceId:f.workspaceId, agentId:f.agentId, force:true, reason:"fixture"});
          assert.equal(result.retiredNow, true);
          assert.deepEqual(result.fenced.cancelledJobIds, [f.jobId]);
        }
        await retiring.query("COMMIT");
        const state = (await db.query("SELECT a.status AS agent_status,j.status AS job_status FROM certops_agents a JOIN certificate_jobs j ON j.id=$2 WHERE a.id=$1", [f.agentId,f.jobId])).rows[0];
        assert.equal(state.agent_status, force ? "retired" : "active");
        assert.equal(state.job_status, force ? "cancelled" : "claimed");
      } finally {
        try { await claim.query("ROLLBACK"); } catch (_) {}
        try { await retiring.query("ROLLBACK"); } catch (_) {}
        claim.release(); retiring.release();
      }
    });
  }
});
