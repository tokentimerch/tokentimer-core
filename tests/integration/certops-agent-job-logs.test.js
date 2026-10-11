const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();

const { claimJobs } = require("../../apps/api/services/certops/agentDispatch");
const {
  lockWorkspaceForCertOpsSideEffect,
} = require("../../apps/api/services/certops/workspaceKillSwitch");
const {
  JOB_LOG_STREAM_CAPABILITY,
  abandonExpiredStreams,
  closeClaimStream,
  decodeCursor,
  ingestAgentJobLogs,
  purgeExpiredAgentLogs,
  readAgentJobLog,
  scrubIncomingLines,
} = require("../../apps/api/services/certops/agentJobLogs");
const { pool } = require("../../apps/api/db/database");

const LOG_ENV = { ...process.env, CERTOPS_AGENT_LOG_RETENTION_DAYS: "30" };
const STORAGE_OFF_ENV = { ...process.env, CERTOPS_AGENT_LOG_RETENTION_DAYS: "0" };

/**
 * The log stream's guarantees live in row locks and SQL predicates: idempotent
 * retries, the shared daily quota, the per-job ingest counter, and the
 * job_state -> stream -> quota lock order. Stubbed-database unit tests cannot
 * observe any of that, so these run against real PostgreSQL.
 */
describe("CertOps agent job logs (real database)", function () {
  this.timeout(60000);

  let ownerId;
  const workspaceIds = [];

  before(async () => {
    await runMigrations();
    const email = `agent-logs-${Date.now()}-${crypto.randomUUID()}@example.com`;
    const owner = await TestUtils.execQuery(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ($1, $2, 'Agent Logs', 'unused', 'local', TRUE)
       RETURNING id`,
      [email.toLowerCase(), email],
    );
    ownerId = owner.rows[0].id;
  });

  after(async () => {
    for (const workspaceId of workspaceIds) {
      await TestUtils.execQuery(
        "DELETE FROM certops_agent_log_daily_quota WHERE workspace_id = $1",
        [workspaceId],
      );
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
    }
    if (ownerId) {
      await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
    }
  });

  async function createWorkspace() {
    const workspaceId = crypto.randomUUID();
    await TestUtils.execQuery(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES ($1, 'Agent Logs WS', $2, 'oss')`,
      [workspaceId, ownerId],
    );
    workspaceIds.push(workspaceId);
    return workspaceId;
  }

  async function createAgent(workspaceId, { capabilities = [] } = {}) {
    const agentId = `agent-${crypto.randomUUID()}`;
    const inserted = await TestUtils.execQuery(
      `INSERT INTO certops_agents (
         workspace_id, agent_id, name, agent_version, protocol_version,
         credential_prefix, credential_hash, status, declared_capabilities,
         capabilities_updated_at, last_seen_at
       )
       VALUES ($1, $2, 'log-agent', '0.11.1', '1.0.0', $3, $4, 'active',
               $5::jsonb, NOW(), NOW())
       RETURNING id`,
      [
        workspaceId,
        agentId,
        `ttagent_${crypto.randomBytes(8).toString("hex")}`,
        crypto.randomBytes(32).toString("hex"),
        JSON.stringify(capabilities),
      ],
    );
    return {
      id: inserted.rows[0].id,
      agentId,
      workspaceId,
      agentVersion: "0.11.1",
      protocolVersion: "1.0.0",
      status: "active",
    };
  }

  async function createJob(workspaceId) {
    const inserted = await TestUtils.execQuery(
      `INSERT INTO certificate_jobs
         (workspace_id, operation, status, executor_kind, mode,
          subject_type, subject_id, payload, requested_by_user_id)
       VALUES ($1, 'renew', 'pending', 'agent', 'real',
               'endpoint', $2, '{}'::jsonb, $3)
       RETURNING id`,
      [workspaceId, crypto.randomUUID(), ownerId],
    );
    return String(inserted.rows[0].id);
  }

  async function claim(agent, { env = LOG_ENV, maxJobs = 10 } = {}) {
    return claimJobs({
      dbPool: pool,
      agent,
      envelope: { agentId: agent.agentId, protocolVersion: "1.0.0" },
      body: { supportedActions: ["renew"], maxJobs },
      env,
      deps: {
        enforceAgentSequence: async () => ({ sequence: 1 }),
        // Signing has its own tests and needs provisioned keys.
        signJobForDispatch: async ({ job, envelopeVersion }) => ({ ...job, envelopeVersion }),
        // The real share lock on the workspace, with CertOps forced on.
        lockWorkspaceForCertOpsSideEffect: (args) =>
          lockWorkspaceForCertOpsSideEffect({
            ...args,
            env: { ...process.env, CERTOPS_ENABLED: "true" },
          }),
      },
    });
  }

  async function claimOne(agent, options) {
    const result = await claim(agent, { ...options, maxJobs: 1 });
    expect(result.jobs).to.have.length(1);
    return {
      jobId: String(result.jobs[0].jobId),
      claimId: String(result.jobs[0].claimId),
      offer: result.logStreams[0],
      result,
    };
  }

  function lines(from, to, prefix = "line") {
    const out = [];
    for (let seq = from; seq <= to; seq += 1) {
      out.push({
        seq,
        ts: new Date().toISOString(),
        level: "info",
        step: "deploy",
        message: `${prefix}-${String(seq).padStart(4, "0")}`,
        fields: null,
      });
    }
    return out;
  }

  function ingest(agent, jobId, body, { env = LOG_ENV, quotaLimitBytes } = {}) {
    return ingestAgentJobLogs({ dbPool: pool, agent, jobId, body, env, quotaLimitBytes });
  }

  async function streamRows(workspaceId, jobId) {
    const found = await TestUtils.execQuery(
      `SELECT * FROM certops_agent_log_stream
        WHERE workspace_id = $1 AND job_id = $2
        ORDER BY issued_at`,
      [workspaceId, jobId],
    );
    return found.rows;
  }

  async function quotaUsed(workspaceId) {
    const found = await TestUtils.execQuery(
      "SELECT COALESCE(SUM(used_bytes), 0)::bigint AS used FROM certops_agent_log_daily_quota WHERE workspace_id = $1",
      [workspaceId],
    );
    return Number(found.rows[0].used);
  }

  async function withClient(fn) {
    const client = await pool.connect();
    try {
      return await fn(client);
    } finally {
      client.release();
    }
  }

  function read(workspaceId, jobId, options = {}) {
    return readAgentJobLog({
      db: pool,
      workspaceId,
      jobId,
      includeText: true,
      env: LOG_ENV,
      ...options,
    });
  }

  it("opens the stream inside the claim and leaves the signed job untouched", async () => {
    const workspaceId = await createWorkspace();
    const capable = await createAgent(workspaceId, { capabilities: [JOB_LOG_STREAM_CAPABILITY] });
    await createJob(workspaceId);

    const claimed = await claimOne(capable);
    expect(claimed.offer).to.include({ enabled: true });
    expect(claimed.offer.maxBatchBytes).to.be.a("number");
    expect(JSON.stringify(claimed.result.jobs)).to.not.match(/logStream/i);

    const [stream] = await streamRows(workspaceId, claimed.jobId);
    expect(stream.claim_id).to.equal(claimed.claimId);
    expect(stream.status).to.equal("pending");
    expect(stream.streaming_enabled).to.equal(true);
    expect(stream.closed_at).to.equal(null);

    const legacy = await createAgent(workspaceId);
    await createJob(workspaceId);
    const legacyClaim = await claimOne(legacy);
    expect(legacyClaim.offer).to.include({ enabled: false });
    const [legacyStream] = await streamRows(workspaceId, legacyClaim.jobId);
    expect(legacyStream.status).to.equal("disabled");
  });

  it("answers a retried batch with the stored ack and never charges it twice", async () => {
    const workspaceId = await createWorkspace();
    const agent = await createAgent(workspaceId, { capabilities: [JOB_LOG_STREAM_CAPABILITY] });
    await createJob(workspaceId);
    const { jobId, claimId } = await claimOne(agent);
    const quotaLimitBytes = 1_000_000;

    const first = await ingest(agent, jobId, { claimId, lines: lines(1, 3) }, { quotaLimitBytes });
    expect(first.httpStatus).to.equal(200);
    expect(first.body).to.include({ ackThroughSeq: 3, newlyStored: 3 });
    const usedAfterFirst = await quotaUsed(workspaceId);
    expect(usedAfterFirst).to.be.greaterThan(0);

    const replay = await ingest(agent, jobId, { claimId, lines: lines(1, 3) }, { quotaLimitBytes });
    expect(replay.httpStatus).to.equal(200);
    expect(replay.body).to.deep.equal(first.body);
    expect(await quotaUsed(workspaceId)).to.equal(usedAfterFirst);

    const finalBody = { claimId, lines: lines(4, 5), final: true };
    const final = await ingest(agent, jobId, finalBody, { quotaLimitBytes });
    expect(final.httpStatus).to.equal(200);
    const [afterFinal] = await streamRows(workspaceId, jobId);
    expect(afterFinal.status).to.equal("final");
    expect(afterFinal.accepted_lines).to.equal(5);
    const usedAfterFinal = await quotaUsed(workspaceId);

    const finalRetry = await ingest(agent, jobId, finalBody, { quotaLimitBytes });
    expect(finalRetry.httpStatus).to.equal(200);
    expect(finalRetry.body).to.deep.equal(final.body);

    const emptyFinal = await ingest(agent, jobId, { claimId, lines: [], final: true }, { quotaLimitBytes });
    expect(emptyFinal.httpStatus).to.equal(200);
    expect(emptyFinal.body.ackThroughSeq).to.equal(5);

    const [afterRetries] = await streamRows(workspaceId, jobId);
    expect(afterRetries.accepted_lines).to.equal(5);
    expect(Number(afterRetries.accepted_bytes)).to.equal(Number(afterFinal.accepted_bytes));
    expect(await quotaUsed(workspaceId)).to.equal(usedAfterFinal);
    const stored = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS n FROM certops_agent_job_log WHERE job_id = $1",
      [jobId],
    );
    expect(stored.rows[0].n).to.equal(5);

    const late = await ingest(agent, jobId, { claimId, lines: lines(6, 6) }, { quotaLimitBytes });
    expect(late.httpStatus).to.equal(409);
    expect(late.body.code).to.equal("CERTOPS_AGENT_LOG_CLOSED");
  });

  it("never overspends the shared daily quota under concurrent ingest", async () => {
    const workspaceId = await createWorkspace();
    const agent = await createAgent(workspaceId, { capabilities: [JOB_LOG_STREAM_CAPABILITY] });
    await createJob(workspaceId);
    await createJob(workspaceId);
    const claimed = await claim(agent, { maxJobs: 2 });
    expect(claimed.jobs).to.have.length(2);

    const lineBytes = scrubIncomingLines(lines(1, 1), new Set()).lines[0].bytes;
    const quotaLimitBytes = 15 * lineBytes;
    const bodies = claimed.jobs.map((job) => ({
      jobId: String(job.jobId),
      body: { claimId: String(job.claimId), lines: lines(1, 10) },
    }));

    const acks = await Promise.all(bodies.map(({ jobId, body }) =>
      ingest(agent, jobId, body, { quotaLimitBytes })));
    for (const ack of acks) expect(ack.httpStatus).to.equal(200);
    const stored = acks.reduce((sum, ack) => sum + ack.body.newlyStored, 0);
    const dropped = acks.reduce((sum, ack) => sum + ack.body.serverDroppedCount, 0);
    expect(stored).to.equal(15);
    expect(dropped).to.equal(5);

    const used = await quotaUsed(workspaceId);
    expect(used).to.equal(15 * lineBytes);
    expect(used).to.be.at.most(quotaLimitBytes);
    const accepted = await TestUtils.execQuery(
      "SELECT COALESCE(SUM(accepted_bytes), 0)::bigint AS bytes FROM certops_agent_log_stream WHERE workspace_id = $1",
      [workspaceId],
    );
    expect(Number(accepted.rows[0].bytes)).to.equal(used);

    const replays = await Promise.all(bodies.map(({ jobId, body }) =>
      ingest(agent, jobId, body, { quotaLimitBytes })));
    replays.forEach((replay, index) => expect(replay.body).to.deep.equal(acks[index].body));
    expect(await quotaUsed(workspaceId)).to.equal(used);
  });

  it("runs claims, ingest, reaper closes and both sweeps concurrently without deadlocking", async function () {
    this.timeout(120000);
    const workspaceId = await createWorkspace();
    const agents = [
      await createAgent(workspaceId, { capabilities: [JOB_LOG_STREAM_CAPABILITY] }),
      await createAgent(workspaceId, { capabilities: [JOB_LOG_STREAM_CAPABILITY] }),
    ];
    const agentByRow = new Map(agents.map((agent) => [String(agent.id), agent]));
    for (let index = 0; index < 6; index += 1) await createJob(workspaceId);

    const errors = [];
    const collect = (promise) => promise.catch((error) => { errors.push(error); });
    // The claim's savepoint swallows a lost lock race, so a deadlock on that
    // side only shows up as a capable agent getting a disabled offer.
    const collectClaim = (promise) => collect(promise.then((result) => {
      if (result.logStreams.some((offer) => offer.enabled !== true)) {
        errors.push(new Error("capable claim got a disabled log offer"));
      }
    }));
    const purgeEnv = { CERTOPS_AGENT_LOG_RETENTION_DAYS: "1" };

    // Reaper shape: job row first, then job_state through closeClaimStream.
    const reaperClose = (stream) => withClient(async (client) => {
      await client.query("BEGIN");
      try {
        await client.query("SELECT id FROM certificate_jobs WHERE id = $1 FOR UPDATE", [stream.job_id]);
        await closeClaimStream(client, {
          workspaceId,
          jobId: String(stream.job_id),
          claimId: String(stream.claim_id),
        });
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      }
    });

    for (let round = 0; round < 8; round += 1) {
      // Requeueing orphans every open stream while the same jobs become
      // claimable again, so sweeps and claims lock the same job_state rows.
      await TestUtils.execQuery(
        `UPDATE certificate_jobs
            SET status = 'pending', claim_id = NULL, claimed_by_agent_id = NULL,
                lease_expires_at = NULL
          WHERE workspace_id = $1`,
        [workspaceId],
      );
      await TestUtils.execQuery(
        `UPDATE certops_agent_log_stream
            SET accept_until = NOW() - INTERVAL '1 second'
          WHERE workspace_id = $1 AND closed_at IS NOT NULL
            AND status IN ('pending', 'streaming')`,
        [workspaceId],
      );
      await TestUtils.execQuery(
        `UPDATE certops_agent_log_stream
            SET closed_at = NOW() - INTERVAL '40 days'
          WHERE workspace_id = $1 AND status IN ('final', 'abandoned', 'disabled')`,
        [workspaceId],
      );
      const open = (await TestUtils.execQuery(
        `SELECT job_id, claim_id, agent_id, resolved_through_seq
           FROM certops_agent_log_stream
          WHERE workspace_id = $1 AND status IN ('pending', 'streaming')`,
        [workspaceId],
      )).rows;

      await Promise.all([
        ...agents.map((agent) => collectClaim(claim(agent, { maxJobs: 6 }))),
        collect(withClient((client) => abandonExpiredStreams({ client }))),
        collect(withClient((client) => purgeExpiredAgentLogs({ client, env: purgeEnv }))),
        ...open.map((stream) => {
          const from = Number(stream.resolved_through_seq) + 1;
          return collect(ingest(agentByRow.get(String(stream.agent_id)), String(stream.job_id), {
            claimId: String(stream.claim_id),
            lines: lines(from, from + 4),
            final: round % 2 === 1,
          }));
        }),
        ...open.map((stream) => collect(reaperClose(stream))),
      ]);
    }

    expect(errors.filter((error) => error?.code === "40P01")).to.deep.equal([]);
    expect(errors.map((error) => error?.message)).to.deep.equal([]);

    await withClient((client) => abandonExpiredStreams({ client }));
    const orphaned = await TestUtils.execQuery(
      `SELECT COUNT(*)::int AS n
         FROM certops_agent_log_stream s
         JOIN certificate_jobs cj ON cj.workspace_id = s.workspace_id AND cj.id = s.job_id
        WHERE s.workspace_id = $1 AND s.closed_at IS NULL
          AND cj.claim_id IS DISTINCT FROM s.claim_id`,
      [workspaceId],
    );
    expect(orphaned.rows[0].n).to.equal(0);
  });

  it("closes, then abandons, streams whose claim ended without a result", async () => {
    const workspaceId = await createWorkspace();
    const agent = await createAgent(workspaceId, { capabilities: [JOB_LOG_STREAM_CAPABILITY] });
    await createJob(workspaceId);
    const cancelled = await claimOne(agent);
    await ingest(agent, cancelled.jobId, { claimId: cancelled.claimId, lines: lines(1, 2) });

    await TestUtils.execQuery(
      "UPDATE certificate_jobs SET status = 'cancelled', completed_at = NOW() WHERE id = $1",
      [cancelled.jobId],
    );
    const firstSweep = await withClient((client) => abandonExpiredStreams({ client }));
    expect(firstSweep.closed).to.be.at.least(1);
    let [stream] = await streamRows(workspaceId, cancelled.jobId);
    expect(stream.closed_at).to.not.equal(null);
    expect(stream.status).to.equal("streaming");
    expect(new Date(stream.accept_until).getTime()).to.be.greaterThan(Date.now());
    expect((await read(workspaceId, cancelled.jobId)).logsComplete).to.equal(false);

    // A late batch inside the grace window still lands.
    const late = await ingest(agent, cancelled.jobId, { claimId: cancelled.claimId, lines: lines(3, 3) });
    expect(late.httpStatus).to.equal(200);

    await TestUtils.execQuery(
      "UPDATE certops_agent_log_stream SET accept_until = NOW() - INTERVAL '1 second' WHERE job_id = $1",
      [cancelled.jobId],
    );
    const secondSweep = await withClient((client) => abandonExpiredStreams({ client }));
    expect(secondSweep.abandoned).to.be.at.least(1);
    [stream] = await streamRows(workspaceId, cancelled.jobId);
    expect(stream.status).to.equal("abandoned");
    const afterAbandon = await read(workspaceId, cancelled.jobId);
    expect(afterAbandon.logsComplete).to.equal(true);
    expect(afterAbandon.items.map((item) => item.seq)).to.deep.equal([1, 2, 3]);

    await createJob(workspaceId);
    const requeued = await claimOne(agent);
    await TestUtils.execQuery(
      "UPDATE certificate_jobs SET status = 'pending', claim_id = NULL WHERE id = $1",
      [requeued.jobId],
    );
    await withClient((client) => abandonExpiredStreams({ client }));
    const [requeuedStream] = await streamRows(workspaceId, requeued.jobId);
    expect(requeuedStream.closed_at).to.not.equal(null);
    await TestUtils.execQuery(
      "UPDATE certificate_jobs SET status = 'cancelled', completed_at = NOW() WHERE id = $1",
      [requeued.jobId],
    );

    const legacy = await createAgent(workspaceId);
    await createJob(workspaceId);
    const disabled = await claimOne(legacy);
    await TestUtils.execQuery(
      "UPDATE certificate_jobs SET status = 'cancelled', completed_at = NOW() WHERE id = $1",
      [disabled.jobId],
    );
    await withClient((client) => abandonExpiredStreams({ client }));
    const [disabledStream] = await streamRows(workspaceId, disabled.jobId);
    expect(disabledStream.status).to.equal("disabled");
    expect(disabledStream.closed_at).to.not.equal(null);
    expect(disabledStream.accept_until).to.equal(null);
    expect((await read(workspaceId, disabled.jobId)).logsComplete).to.equal(true);
  });

  it("keeps cursors monotonic across a retention purge", async () => {
    const workspaceId = await createWorkspace();
    const agent = await createAgent(workspaceId, { capabilities: [JOB_LOG_STREAM_CAPABILITY] });
    await createJob(workspaceId);
    const { jobId, claimId } = await claimOne(agent);
    await ingest(agent, jobId, { claimId, lines: lines(1, 5) });

    const page1 = await read(workspaceId, jobId, { limit: 2 });
    expect(page1.items.map((item) => item.seq)).to.deep.equal([1, 2]);
    expect(page1.hasMore).to.equal(true);
    const page2 = await read(workspaceId, jobId, { limit: 2, cursor: page1.nextCursor });
    expect(page2.items.map((item) => item.seq)).to.deep.equal([3, 4]);

    await TestUtils.execQuery(
      "UPDATE certops_agent_job_log SET received_at = NOW() - INTERVAL '3 days' WHERE job_id = $1",
      [jobId],
    );
    const purged = await withClient((client) =>
      purgeExpiredAgentLogs({ client, env: { CERTOPS_AGENT_LOG_RETENTION_DAYS: "1" } }));
    expect(purged.deletedLines).to.be.at.least(5);

    await ingest(agent, jobId, { claimId, lines: lines(6, 7) });
    const page3 = await read(workspaceId, jobId, { limit: 2, cursor: page2.nextCursor });
    expect(page3.items.map((item) => item.seq)).to.deep.equal([6, 7]);
    expect(decodeCursor(page3.nextCursor)).to.be.greaterThan(decodeCursor(page2.nextCursor));

    const fromStart = await read(workspaceId, jobId);
    expect(fromStart.items.map((item) => item.seq)).to.deep.equal([6, 7]);
    const empty = await read(workspaceId, jobId, { cursor: page3.nextCursor });
    expect(empty.items).to.deep.equal([]);
    expect(empty.nextCursor).to.equal(page3.nextCursor);
    expect(empty.hasMore).to.equal(false);

    const counter = await TestUtils.execQuery(
      "SELECT next_ingest_order FROM certops_agent_log_job_state WHERE job_id = $1",
      [jobId],
    );
    expect(Number(counter.rows[0].next_ingest_order)).to.equal(7);
  });

  it("stores nothing when retention is 0", async () => {
    const workspaceId = await createWorkspace();
    const agent = await createAgent(workspaceId, { capabilities: [JOB_LOG_STREAM_CAPABILITY] });
    await createJob(workspaceId);
    const off = await claimOne(agent, { env: STORAGE_OFF_ENV });
    expect(off.offer).to.include({ enabled: false });
    expect(await streamRows(workspaceId, off.jobId)).to.deep.equal([]);

    // Storage switched off while a claim is open.
    await createJob(workspaceId);
    const open = await claimOne(agent);
    const ack = await ingest(agent, open.jobId, { claimId: open.claimId, lines: lines(1, 2) }, {
      env: STORAGE_OFF_ENV,
    });
    expect(ack.httpStatus).to.equal(200);
    expect(ack.body.streamDisabled).to.equal(true);
    const stored = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS n FROM certops_agent_job_log WHERE job_id = $1",
      [open.jobId],
    );
    expect(stored.rows[0].n).to.equal(0);

    const view = await read(workspaceId, open.jobId, { env: STORAGE_OFF_ENV });
    expect(view.storageEnabled).to.equal(false);
    expect(view.items).to.deep.equal([]);

    // Lines stored while retention was on go once it is switched to 0.
    await ingest(agent, open.jobId, { claimId: open.claimId, lines: lines(1, 2) });
    const before = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS n FROM certops_agent_job_log WHERE job_id = $1",
      [open.jobId],
    );
    expect(before.rows[0].n).to.equal(2);
    await withClient((client) => purgeExpiredAgentLogs({ client, env: STORAGE_OFF_ENV }));
    const after = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS n FROM certops_agent_job_log WHERE job_id = $1",
      [open.jobId],
    );
    expect(after.rows[0].n).to.equal(0);
  });
});
