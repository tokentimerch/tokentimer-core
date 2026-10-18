const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const { pool } = require("../../apps/api/db/database");
const {
  abandonEnrollment,
  cancelEnrollment,
  confirmIssuerKey,
  createEnrollment,
  dispatchPreflight,
  recordPreflightResult,
  scheduleDueEnrollments,
} = require("../../apps/api/services/certops/certificateEnrollments");
const { freezeSnapshot } = require("../../apps/api/services/certops/enrollmentLifecycle");
const { executeAdcsPreflight } = require("../../packages/agent/src/issuers/adcs-preflight");

const CA = "ca01.corp.example.com\\Corp Issuing CA 01";
const TEMPLATE = "TokenTimerWebServer";
const KEY = "ab".repeat(32);

/**
 * Enrollment state, request ids, and preflight reservations depend on
 * PostgreSQL types, row locks, and transaction rollback. The in-memory
 * service double cannot show those.
 */
describe("CertOps AD CS enrollments (real database)", function () {
  this.timeout(60000);

  let ownerId;
  let workspaceId;
  let issuerId;
  let agentRowId;

  before(async () => {
    await runMigrations();
    const email = `adcs-enroll-${Date.now()}-${crypto.randomUUID()}@example.com`;
    const owner = await TestUtils.execQuery(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ($1, $2, 'AD CS Enrollment', 'unused', 'local', TRUE)
       RETURNING id`,
      [email.toLowerCase(), email],
    );
    ownerId = owner.rows[0].id;
    workspaceId = crypto.randomUUID();
    await TestUtils.execQuery(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES ($1, 'AD CS Enrollment WS', $2, 'oss')`,
      [workspaceId, ownerId],
    );
    const issuer = await TestUtils.execQuery(
      `INSERT INTO certificate_issuers (workspace_id, kind, name, current_version, revalidation_required)
       VALUES ($1, 'adcs', 'Issuing CA', 1, false)
       RETURNING id`,
      [workspaceId],
    );
    issuerId = issuer.rows[0].id;
    await TestUtils.execQuery(
      `INSERT INTO certificate_issuer_versions (
         workspace_id, issuer_id, version, ca_config, template, transport, ca_key_sha256, confirmed_at
       ) VALUES ($1, $2, 1, $3, $4, 'dcom', $5, NOW())`,
      [workspaceId, issuerId, CA, TEMPLATE, KEY],
    );
    const agent = await TestUtils.execQuery(
      `INSERT INTO certops_agents (
         workspace_id, agent_id, name, agent_version, protocol_version,
         credential_prefix, credential_hash, status
       ) VALUES ($1, $2, 'adcs-agent', '0.1.0', '1.0.0', $3, $4, 'active')
       RETURNING id`,
      [
        workspaceId,
        `agent-${crypto.randomUUID()}`,
        `ttagent_${crypto.randomBytes(8).toString("hex")}`,
        crypto.randomBytes(32).toString("hex"),
      ],
    );
    agentRowId = agent.rows[0].id;
  });

  after(async () => {
    if (workspaceId || ownerId) {
      await TestUtils.execQuery(
        `DELETE FROM audit_events
          WHERE workspace_id = $1
             OR subject_user_id = $2
             OR actor_user_id = $2`,
        [workspaceId, ownerId],
      );
    }
    if (workspaceId) {
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
    }
    if (ownerId) {
      await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
    }
  });

  it("survivor fixture uses the insert-trigger management period and creates eligible enrollment work", async () => {
    const assert = require("node:assert/strict");
    const { provisionSurvivorSource } = require("../e2e/helpers/certops-adcs-local-rules");
    const ownedCertificateIds = [];
    const certificateId = await provisionSurvivorSource({
      fixture: { workspaceId, pool, request: async () => { throw new Error("Unexpected readd of an open source"); } },
      agentRowId, domain: "app.example.com", site: "Survivor", port: 443, ownedCertificateIds,
    });
    assert.deepEqual(ownedCertificateIds, [certificateId]);
    const periods = await pool.query("SELECT id, ended_at, current_identity_id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2", [workspaceId, certificateId]);
    assert.equal(periods.rows.length, 1);
    assert.equal(periods.rows[0].ended_at, null);
    assert.equal(periods.rows[0].current_identity_id, null);
    const enrollment = await createEnrollment(enrollmentInput({ certificateId }));
    const job = await pool.query(`SELECT j.subject_id,
      certops_is_initial_provisioning(j.workspace_id,j.subject_id::uuid,j.operation,j.executor_kind,j.source) AS eligible
      FROM certificate_jobs j WHERE j.workspace_id=$1 AND j.id=$2`, [workspaceId, enrollment.jobId]);
    assert.equal(job.rows.length, 1);
    assert.equal(job.rows[0].subject_id, certificateId);
    assert.equal(job.rows[0].eligible, true);
  });

  function enrollmentInput(overrides = {}) {
    return {
      client: pool,
      workspaceId,
      issuerId,
      certificateId: crypto.randomUUID(),
      agentId: agentRowId,
      target: {
        type: "windows-iis",
        reference: "iis-01/webhosting",
        store: "WebHosting",
        binding: { site: "Shop", port: 443, sniHost: "app.example.com" },
      },
      authorizedDnsNames: ["app.example.com"],
      keyAlgorithm: "rsa",
      keySize: 2048,
      actorUserId: ownerId,
      ...overrides,
    };
  }

  async function assertNoForeignDueRows() {
    const foreign = await TestUtils.execQuery(
      `SELECT count(*)::int AS n
         FROM certificate_enrollments
        WHERE workspace_id <> $1
          AND next_poll_at IS NOT NULL
          AND next_poll_at <= NOW()`,
      [workspaceId],
    );
    if (foreign.rows[0].n > 0) {
      throw new Error("refusing to sweep due enrollments that belong to another workspace");
    }
  }

  async function insertEnrollment(state, extra = {}) {
    const frozen = freezeSnapshot({
      issuerId,
      issuerVersion: 1,
      caConfig: CA,
      caKeySha256: KEY,
      template: TEMPLATE,
      authorizedDnsNames: ["app.example.com"],
      keyAlgorithm: "rsa",
      keySize: 2048,
    });
    const id = crypto.randomUUID();
    await TestUtils.execQuery(
      `INSERT INTO certificate_enrollments (
         id, workspace_id, certificate_id, issuer_id, issuer_version, agent_id,
         state, attempt, snapshot_bytes, snapshot_sha256, deploy_target,
         operator_request_id, next_poll_at
       ) VALUES (
         $1, $2, $3, $4, 1, $5,
         $6, 1, $7, $8, $9::jsonb,
         $10, $11
       )`,
      [
        id,
        workspaceId,
        crypto.randomUUID(),
        issuerId,
        agentRowId,
        state,
        frozen.bytes,
        frozen.sha256,
        JSON.stringify(enrollmentInput().target),
        extra.operatorRequestId || null,
        extra.nextPollAt || null,
      ],
    );
    return id;
  }

  it("decodes a BIGINT RequestId and schedules reconciliation", async () => {
    await assertNoForeignDueRows();
    const id = await insertEnrollment("submission_uncertain", {
      operatorRequestId: 77,
      nextPollAt: new Date(Date.now() - 1000),
    });
    const stored = await TestUtils.execQuery(
      "SELECT operator_request_id FROM certificate_enrollments WHERE id = $1",
      [id],
    );
    expect(typeof stored.rows[0].operator_request_id).to.equal("string");
    expect(stored.rows[0].operator_request_id).to.equal("77");

    const client = await pool.connect();
    try {
      const created = await scheduleDueEnrollments({
        client,
        createJob: async ({ payload }) => {
          expect(payload.metadata[0].value).to.equal(77);
          expect(typeof payload.metadata[0].value).to.equal("number");
          return { id: crypto.randomUUID() };
        },
      });
      expect(created.map((row) => row.enrollmentId)).to.include(id);
    } finally {
      client.release();
    }
  });

  it("rolls back the enrollment when creating the first job fails", async () => {
    const certificateId = crypto.randomUUID();
    try {
      await createEnrollment(enrollmentInput({
        certificateId,
        createJob: async () => {
          throw new Error("job insert failed");
        },
      }));
      throw new Error("expected job creation to fail");
    } catch (error) {
      expect(error.message).to.match(/job insert failed/);
    }
    const left = await TestUtils.execQuery(
      "SELECT count(*)::int AS n FROM certificate_enrollments WHERE certificate_id = $1",
      [certificateId],
    );
    expect(left.rows[0].n).to.equal(0);
  });

  it("lets only one of two scheduler connections claim a due enrollment", async () => {
    await assertNoForeignDueRows();
    const id = await insertEnrollment("pending_issuance", {
      nextPollAt: new Date(Date.now() - 1000),
    });
    let calls = 0;
    async function run() {
      const client = await pool.connect();
      try {
        return await scheduleDueEnrollments({
          client,
          createJob: async () => {
            calls += 1;
            await new Promise((resolve) => setTimeout(resolve, 50));
            return { id: crypto.randomUUID() };
          },
        });
      } finally {
        client.release();
      }
    }
    const [first, second] = await Promise.all([run(), run()]);
    const created = [...first, ...second].filter((row) => row.enrollmentId === id);
    expect(created).to.have.length(1);
    expect(calls).to.equal(1);
  });

  it("leaves a due enrollment alone while another transaction holds its row lock", async () => {
    await assertNoForeignDueRows();
    const id = await insertEnrollment("pending_issuance", {
      nextPollAt: new Date(Date.now() - 1000),
    });
    const holder = await pool.connect();
    try {
      await holder.query("BEGIN");
      await holder.query(
        "SELECT id FROM certificate_enrollments WHERE workspace_id = $1 AND id = $2 FOR UPDATE",
        [workspaceId, id],
      );
      const created = await scheduleDueEnrollments({ client: pool, now: new Date() });
      expect(created.filter((c) => c.enrollmentId === id)).to.have.length(0);
      await holder.query("ROLLBACK");
    } finally {
      holder.release();
    }
    const after = await TestUtils.execQuery(
      "SELECT state, current_job_id FROM certificate_enrollments WHERE id = $1",
      [id],
    );
    expect(after.rows[0].state).to.equal("pending_issuance");
    expect(after.rows[0].current_job_id).to.equal(null);
    await TestUtils.execQuery("UPDATE certificate_enrollments SET next_poll_at = NULL WHERE id = $1", [id]);
  });

  it("cancels the continuation job the scheduler created for a cancelled enrollment", async () => {
    await assertNoForeignDueRows();
    const id = await insertEnrollment("pending_issuance", {
      nextPollAt: new Date(Date.now() - 1000),
    });
    const created = await scheduleDueEnrollments({ client: pool, now: new Date() });
    const dispatched = created.find((c) => c.enrollmentId === id);
    expect(dispatched).to.exist;

    await cancelEnrollment({ client: pool, workspaceId, enrollmentId: id, actorUserId: ownerId });

    const enrollment = await TestUtils.execQuery(
      "SELECT state FROM certificate_enrollments WHERE id = $1",
      [id],
    );
    const job = await TestUtils.execQuery(
      "SELECT status FROM certificate_jobs WHERE id = $1",
      [dispatched.jobId],
    );
    expect(enrollment.rows[0].state).to.equal("cancelled");
    expect(job.rows[0].status).to.equal("cancelled");
    await TestUtils.execQuery("UPDATE certificate_enrollments SET next_poll_at = NULL WHERE id = $1", [id]);
  });

  it("rolls back an issuer version when confirmation does not finish", async () => {
    await TestUtils.execQuery(
      `UPDATE certificate_issuers
          SET last_preflight = $2::jsonb
        WHERE id = $1`,
      [issuerId, JSON.stringify({
        caConfig: CA,
        template: TEMPLATE,
        templateCheck: { verdict: "safe", reasons: [] },
        caCheck: { verdict: "safe", reasons: [], operatorAttested: false },
        caCertificates: [{ keySha256: KEY }],
      })],
    );
    const before = await TestUtils.execQuery(
      "SELECT count(*)::int AS n FROM certificate_issuer_versions WHERE issuer_id = $1",
      [issuerId],
    );
    try {
      await confirmIssuerKey({
        workspaceId,
        issuerId,
        caKeySha256: KEY,
        actorUserId: ownerId,
        audit: async () => {
          throw new Error("audit failed");
        },
      });
      throw new Error("expected confirmation to fail");
    } catch (error) {
      expect(error.message).to.match(/audit failed/);
    }
    const after = await TestUtils.execQuery(
      "SELECT count(*)::int AS n FROM certificate_issuer_versions WHERE issuer_id = $1",
      [issuerId],
    );
    expect(after.rows[0].n).to.equal(before.rows[0].n);
  });

  it("dispatches abandonment cleanup and refuses a bad snapshot or a revalidation hold", async () => {
    await assertNoForeignDueRows();
    const id = await insertEnrollment("submission_uncertain");
    await abandonEnrollment({
      workspaceId,
      enrollmentId: id,
      actorUserId: ownerId,
    });
    const client = await pool.connect();
    try {
      const created = await scheduleDueEnrollments({
        client,
        now: new Date(Date.now() + 5 * 60 * 1000),
        createJob: async () => ({ id: crypto.randomUUID() }),
      });
      expect(created.map((row) => row.enrollmentId)).to.include(id);
    } finally {
      client.release();
    }

    const certificateId = crypto.randomUUID();
    try {
      await createEnrollment(enrollmentInput({ certificateId, keySize: 1024 }));
      throw new Error("expected a malformed snapshot to be refused");
    } catch (error) {
      expect(error.code).to.equal("CERTOPS_SNAPSHOT_INVALID");
    }
    const malformed = await TestUtils.execQuery(
      "SELECT count(*)::int AS n FROM certificate_enrollments WHERE certificate_id = $1",
      [certificateId],
    );
    expect(malformed.rows[0].n).to.equal(0);

    await TestUtils.execQuery(
      "UPDATE certificate_issuers SET revalidation_required = true WHERE id = $1",
      [issuerId],
    );
    try {
      await createEnrollment(enrollmentInput());
      throw new Error("expected revalidation to block enrollment");
    } catch (error) {
      expect(error.code).to.equal("CERTOPS_ISSUER_REVALIDATION_REQUIRED");
    } finally {
      await TestUtils.execQuery(
        "UPDATE certificate_issuers SET revalidation_required = false WHERE id = $1",
        [issuerId],
      );
    }
  });

  it("keeps concurrent preflights inside the hourly limit and stores the agent result", async () => {
    for (let i = 0; i < 19; i += 1) {
      await TestUtils.execQuery(
        `INSERT INTO certificate_jobs
           (workspace_id, operation, status, executor_kind, mode, subject_type, subject_id, payload, requested_by_user_id)
         VALUES ($1, 'adcs-preflight', 'succeeded', 'agent', 'real', 'external', $2, '{}'::jsonb, $3)`,
        [workspaceId, issuerId, ownerId],
      );
    }
    const attempts = await Promise.allSettled([
      dispatchPreflight({
        workspaceId,
        issuerId,
        agentId: agentRowId,
        caConfig: CA,
        template: TEMPLATE,
        actorUserId: ownerId,
      }),
      dispatchPreflight({
        workspaceId,
        issuerId,
        agentId: agentRowId,
        caConfig: CA,
        template: TEMPLATE,
        actorUserId: ownerId,
      }),
    ]);
    const rejected = attempts.filter((item) => item.status === "rejected");
    const fulfilled = attempts.filter((item) => item.status === "fulfilled");
    expect(fulfilled).to.have.length(1);
    expect(rejected).to.have.length(1);
    expect(rejected[0].reason.code).to.equal("CERTOPS_PREFLIGHT_RATE_LIMITED");

    const job = fulfilled[0].value;
    const preflightResult = {
      caConfig: CA,
      template: TEMPLATE,
      templateCheck: {
        verdict: "safe",
        reasons: [],
        schemaVersion: 2,
        templateOid: "1.3.6.1.4.1.311.21.8.1.2.3.4.5.6",
        minimalKeySize: 2048,
        asymmetricAlgorithm: null,
        enrolleeSuppliesSubject: true,
      },
      caCheck: { verdict: "safe", reasons: [], operatorAttested: false },
      caCertificates: [{
        certificateB64: "MIIB",
        keySha256: KEY,
        thumbprintSha1: "AABBCCDDEEFF00112233445566778899AABBCCDD",
        notBefore: "2026-01-01T00:00:00.000Z",
        notAfter: "2031-01-01T00:00:00.000Z",
      }],
    };
    const outcome = await executeAdcsPreflight({
      job: { action: "adcs-preflight", mode: "real", transport: "dcom", caConfig: CA, template: TEMPLATE },
      rules: [{ caConfig: CA, template: TEMPLATE }],
      probe: async () => ({ preflightResult }),
    });
    expect(outcome.status).to.equal("succeeded");
    await recordPreflightResult(pool, {
      workspaceId,
      job: {
        subject_id: issuerId,
        operation: "adcs-preflight",
        id: job.id,
        payload: { caConfig: CA, template: TEMPLATE },
      },
      preflightResult: outcome.preflightResult,
      resultStatus: "succeeded",
    });
    const stored = await TestUtils.execQuery(
      "SELECT last_preflight->>'template' AS template FROM certificate_issuers WHERE id = $1",
      [issuerId],
    );
    expect(stored.rows[0].template).to.equal(TEMPLATE);
  });

  it("keeps the latest dispatched preflight when an older job finishes later", async () => {
    function resultFor(template) {
      return {
        caConfig: CA,
        template,
        templateCheck: {
          verdict: "safe",
          reasons: [],
          schemaVersion: 2,
          templateOid: "1.3.6.1.4.1.311.21.8.1.2.3.4.5.6",
          minimalKeySize: 2048,
          asymmetricAlgorithm: null,
          enrolleeSuppliesSubject: true,
        },
        caCheck: { verdict: "safe", reasons: [], operatorAttested: false },
        caCertificates: [{
          certificateB64: "MIIB",
          keySha256: KEY,
          thumbprintSha1: "AABBCCDDEEFF00112233445566778899AABBCCDD",
          notBefore: "2026-01-01T00:00:00.000Z",
          notAfter: "2031-01-01T00:00:00.000Z",
        }],
      };
    }
    async function insertJob(template, createdAt, preflightSeq) {
      const inserted = await TestUtils.execQuery(
        `INSERT INTO certificate_jobs
           (workspace_id, operation, status, executor_kind, mode,
            subject_type, subject_id, payload, requested_by_user_id,
            created_at, preflight_seq)
         VALUES ($1, 'adcs-preflight', 'succeeded', 'agent', 'real',
                 'external', $2, $3::jsonb, $4, $5, $6)
         RETURNING id`,
        [
          workspaceId,
          issuerId,
          JSON.stringify({ caConfig: CA, template }),
          ownerId,
          createdAt,
          preflightSeq,
        ],
      );
      return inserted.rows[0].id;
    }
    await TestUtils.execQuery(
      `UPDATE certificate_issuers
          SET last_preflight = NULL, last_preflight_job_id = NULL
        WHERE id = $1`,
      [issuerId],
    );
    const olderTemplate = "OlderTemplate";
    const newerTemplate = "NewerTemplate";
    const olderId = await insertJob(olderTemplate, new Date(Date.now() - 120000), 1);
    const newerId = await insertJob(newerTemplate, new Date(Date.now() - 60000), 2);
    async function report(jobId, template) {
      await recordPreflightResult(pool, {
        workspaceId,
        job: {
          id: jobId,
          subject_id: issuerId,
          operation: "adcs-preflight",
          payload: { caConfig: CA, template },
        },
        preflightResult: resultFor(template),
        resultStatus: "succeeded",
      });
    }
    await report(olderId, olderTemplate);
    await report(newerId, newerTemplate);
    await report(olderId, olderTemplate);
    const stored = await TestUtils.execQuery(
      `SELECT last_preflight->>'template' AS template, last_preflight_job_id
         FROM certificate_issuers WHERE id = $1`,
      [issuerId],
    );
    expect(stored.rows[0].template).to.equal(newerTemplate);
    expect(stored.rows[0].last_preflight_job_id).to.equal(newerId);
  });

  it("orders preflight results by the locked sequence when transaction time is reversed", async () => {
    await TestUtils.execQuery(
      `UPDATE certificate_jobs
          SET created_at = NOW() - INTERVAL '2 hours'
        WHERE workspace_id = $1 AND operation = 'adcs-preflight'`,
      [workspaceId],
    );
    await TestUtils.execQuery(
      `UPDATE certificate_issuers
          SET last_preflight = NULL, last_preflight_job_id = NULL, preflight_seq = 0
        WHERE id = $1`,
      [issuerId],
    );
    let releaseEarly;
    const earlyWaiting = new Promise((resolve) => {
      releaseEarly = resolve;
    });
    let markEarlyStarted;
    const earlyStarted = new Promise((resolve) => {
      markEarlyStarted = resolve;
    });
    const earlyTemplate = "EarlyTxnLateInsert";
    const lateTemplate = "LateTxnEarlyInsert";
    const early = dispatchPreflight({
      workspaceId,
      issuerId,
      agentId: agentRowId,
      caConfig: CA,
      template: earlyTemplate,
      actorUserId: ownerId,
      beforeLock: async () => {
        markEarlyStarted();
        await earlyWaiting;
      },
    });
    await earlyStarted;
    await new Promise((resolve) => setTimeout(resolve, 30));
    const lateJob = await dispatchPreflight({
      workspaceId,
      issuerId,
      agentId: agentRowId,
      caConfig: CA,
      template: lateTemplate,
      actorUserId: ownerId,
    });
    releaseEarly();
    const earlyJob = await early;
    const rows = await TestUtils.execQuery(
      `SELECT id, payload->>'template' AS template, created_at, preflight_seq
         FROM certificate_jobs
        WHERE id IN ($1, $2)`,
      [earlyJob.id, lateJob.id],
    );
    const earlyRow = rows.rows.find((row) => row.id === earlyJob.id);
    const lateRow = rows.rows.find((row) => row.id === lateJob.id);
    expect(new Date(earlyRow.created_at).getTime()).to.be.below(new Date(lateRow.created_at).getTime());
    expect(Number(earlyRow.preflight_seq)).to.be.greaterThan(Number(lateRow.preflight_seq));
    function resultFor(template) {
      return {
        caConfig: CA,
        template,
        templateCheck: {
          verdict: "safe",
          reasons: [],
          schemaVersion: 2,
          templateOid: "1.3.6.1.4.1.311.21.8.1.2.3.4.5.6",
          minimalKeySize: 2048,
          asymmetricAlgorithm: null,
          enrolleeSuppliesSubject: true,
        },
        caCheck: { verdict: "safe", reasons: [], operatorAttested: false },
        caCertificates: [{
          certificateB64: "MIIB",
          keySha256: KEY,
          thumbprintSha1: "AABBCCDDEEFF00112233445566778899AABBCCDD",
          notBefore: "2026-01-01T00:00:00.000Z",
          notAfter: "2031-01-01T00:00:00.000Z",
        }],
      };
    }
    async function report(job, template) {
      await recordPreflightResult(pool, {
        workspaceId,
        job: {
          id: job.id,
          subject_id: issuerId,
          operation: "adcs-preflight",
          payload: { caConfig: CA, template },
        },
        preflightResult: resultFor(template),
        resultStatus: "succeeded",
      });
    }
    await report(lateJob, lateTemplate);
    await report(earlyJob, earlyTemplate);
    await report(lateJob, lateTemplate);
    const stored = await TestUtils.execQuery(
      `SELECT last_preflight->>'template' AS template, last_preflight_job_id
         FROM certificate_issuers WHERE id = $1`,
      [issuerId],
    );
    expect(stored.rows[0].template).to.equal(earlyTemplate);
    expect(stored.rows[0].last_preflight_job_id).to.equal(earlyJob.id);
  });
});
