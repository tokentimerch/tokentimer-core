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
  recoverOrphanedEnrollment,
  scheduleDueEnrollments,
  retryEnrollmentInstallation,
} = require("../../apps/api/services/certops/certificateEnrollments");
const { createCertificateJob } = require("../../apps/api/services/certops/jobs");
const { retireCertificateIdentity } = require("../../apps/api/services/certops/certificateIdentity");
const { freezeSnapshot, storedAdcsPayload } = require("../../apps/api/services/certops/enrollmentLifecycle");
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

  it("WebHosting fixture opens exactly one trigger-created period and its real enrollment job is claimable",async()=>{
    const assert=require("node:assert/strict");
    const {provisionWebHostingSource}=require("../e2e/helpers/certops-adcs-webhosting-renewal");
    const certificateId=crypto.randomUUID(),domain="certops-adcs-0123456789-webhosting.example.test",site="TTAdcsWebHosting0123456789",port=8443;
    await provisionWebHostingSource({fixture:{workspaceId,pool},agentRowId,isolated:{certificateId,domain,site,port}});
    const periods=await pool.query("SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",[workspaceId,certificateId]);
    assert.equal(periods.rows.length,1);
    await assert.rejects(()=>pool.query("INSERT INTO certops_management_periods(workspace_id,managed_certificate_id) VALUES($1,$2)",[workspaceId,certificateId]),error=>error.code==="23505"&&error.constraint==="uq_certops_open_management_period");
    const source=(await pool.query("SELECT key_reference,public_metadata FROM managed_certificates WHERE workspace_id=$1 AND id=$2",[workspaceId,certificateId])).rows[0];
    assert.equal(source.key_reference,`winstore://WebHosting/${site}:${port}`);assert.equal(source.public_metadata.issuance.target.store,"WebHosting");
    const enrollment=await createEnrollment(enrollmentInput({certificateId,authorizedDnsNames:[domain],target:{type:"windows-iis",reference:domain,store:"WebHosting",binding:{site,port,sniHost:domain}}}));
    const {claimJobs,_test:dispatchCaps}=require("../../apps/api/services/certops/agentDispatch");
    await pool.query("UPDATE certops_agents SET agent_version='0.18.0',declared_capabilities=$2::jsonb,capabilities_updated_at=NOW(),declared_target_selectors=$3::jsonb WHERE id=$1",[agentRowId,JSON.stringify(["adcs-enroll-v1",dispatchCaps.EVIDENCE_CLAIM_BINDING_CAPABILITY,dispatchCaps.SIGNED_PAYLOAD_B64_CAPABILITY]),JSON.stringify([domain])]);
    const agent=(await pool.query("SELECT agent_id FROM certops_agents WHERE id=$1",[agentRowId])).rows[0];
    const claimed=await claimJobs({dbPool:pool,agent:{id:agentRowId,workspaceId,agentId:agent.agent_id,agentVersion:"0.18.0",protocolVersion:"1.0.0",status:"active"},envelope:{agentId:agent.agent_id,protocolVersion:"1.0.0"},body:{supportedActions:["renew"],maxJobs:16},deps:{enforceAgentSequence:async()=>({sequence:1}),signJobForDispatch:async({job,envelopeVersion})=>({...job,envelopeVersion})}});
    assert.ok(claimed.jobs.some(job=>String(job.id??job.jobId)===enrollment.jobId));
    const job=(await pool.query("SELECT status,claim_id,subject_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",[workspaceId,enrollment.jobId])).rows[0];
    assert.equal(job.status,"claimed");assert.ok(job.claim_id);assert.equal(job.subject_id,certificateId);
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
        extra.certificateId || crypto.randomUUID(),
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

  it("stops uncertain retrieval at the frozen deadline without a cleanup job", async () => {
    await assertNoForeignDueRows();
    const id = await insertEnrollment("pending_issuance", {nextPollAt: new Date(Date.now()-1000)});
    await TestUtils.execQuery(`UPDATE certificate_enrollments SET request_id=4242,
      pending_since=NOW()-INTERVAL '15 days', last_error_code='ADCS_DISPOSITION_UNKNOWN' WHERE id=$1`,[id]);
    const created = await scheduleDueEnrollments({client:pool,createJob:async()=>{throw new Error("Must preserve uncertain key");}});
    expect(created.filter(row=>row.enrollmentId===id)).to.have.length(0);
    const row=(await TestUtils.execQuery("SELECT state,request_id,next_poll_at,last_error_code,operator_request_id FROM certificate_enrollments WHERE id=$1",[id])).rows[0];
    expect(row.state).to.equal("submission_uncertain");expect(String(row.request_id)).to.equal("4242");
    expect(row.last_error_code).to.equal("ADCS_RETRIEVAL_RECONCILIATION_REQUIRED");
    expect(row.next_poll_at).to.equal(null);expect(row.operator_request_id).to.equal(null);
    const audit=await TestUtils.execQuery("SELECT metadata FROM audit_events WHERE workspace_id=$1 AND metadata->>'enrollmentId'=$2",[workspaceId,id]);
    expect(audit.rows.some(value=>value.metadata.reason==='pending_timeout_after_uncertain_retrieve' && String(value.metadata.requestId)==='4242')).to.equal(true);
    // Real public-service reconciliation remains possible after polling stops.
    await require("../../apps/api/services/certops/certificateEnrollments").proposeReconcileRequestId({client:pool,workspaceId,enrollmentId:id,requestId:4242,actorUserId:ownerId});
    const proposed=(await TestUtils.execQuery("SELECT operator_request_id,next_poll_at FROM certificate_enrollments WHERE id=$1",[id])).rows[0];
    expect(String(proposed.operator_request_id)).to.equal("4242");expect(proposed.next_poll_at).to.be.instanceOf(Date);
    await TestUtils.execQuery("DELETE FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",[workspaceId,id]);
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

  it("blocks install continuation and deploy-from-store after retirement while cleanup still claims", async () => {
    await assertNoForeignDueRows();
    const fingerprint = crypto.randomBytes(32).toString("hex");
    const certificateId = (await TestUtils.execQuery(
      `INSERT INTO managed_certificates(
         workspace_id, source, source_ref, fingerprint_sha256, name, common_name, status, key_mode
       ) VALUES($1,'agent_filesystem',$2,$3,'retired install','retired.example','discovered','os-store-managed')
       RETURNING id`,
      [workspaceId, crypto.randomUUID(), fingerprint],
    )).rows[0].id;
    const identityId = (await TestUtils.execQuery(
      `SELECT id FROM certops_certificate_identities
        WHERE workspace_id=$1 AND fingerprint_sha256=$2`,
      [workspaceId, fingerprint],
    )).rows[0].id;
    const due = new Date(Date.now() - 1000);
    const installing = await insertEnrollment("installing", { certificateId, nextPollAt: due });
    const installJob = (await scheduleDueEnrollments({ client: pool, now: new Date() }))
      .find((row) => row.enrollmentId === installing);
    expect(installJob).to.exist;

    await TestUtils.execQuery(
      `UPDATE certops_certificate_identities
          SET lifecycle_status='revoked', retired_at=NOW()
        WHERE workspace_id=$1 AND id=$2`,
      [workspaceId, identityId],
    );
    try {
      await TestUtils.execQuery("UPDATE certificate_jobs SET status='claimed' WHERE id=$1", [installJob.jobId]);
      throw new Error("installing continuation claim should fail");
    } catch (error) {
      expect(error.code).to.equal("55000");
    }
    const stillPending = await TestUtils.execQuery(
      "SELECT status FROM certificate_jobs WHERE id=$1",
      [installJob.jobId],
    );
    expect(stillPending.rows[0].status).to.equal("pending");

    const failed = await insertEnrollment("install_failed", { certificateId });
    try {
      await retryEnrollmentInstallation({
        client: pool,
        workspaceId,
        enrollmentId: failed,
        actorUserId: ownerId,
        env: { CERTOPS_ENABLED: "true" },
      });
      throw new Error("installation retry should fail");
    } catch (error) {
      expect(error.code).to.equal("CERTOPS_CERTIFICATE_RETIRED");
    }

    const cleanup = await insertEnrollment("cancelled", { certificateId, nextPollAt: due });
    const cleanupJob = (await scheduleDueEnrollments({ client: pool, now: new Date() }))
      .find((row) => row.enrollmentId === cleanup);
    expect(cleanupJob).to.exist;
    await TestUtils.execQuery("UPDATE certificate_jobs SET status='claimed' WHERE id=$1", [cleanupJob.jobId]);

    const reconcile = await insertEnrollment("submission_uncertain", {
      certificateId,
      operatorRequestId: 88,
      nextPollAt: due,
    });
    // Reconcile can retrieve and install an issued leaf, so it is fenced like an install.
    const reconcileJob = (await scheduleDueEnrollments({ client: pool, now: new Date() }))
      .find((row) => row.enrollmentId === reconcile);
    expect(reconcileJob).to.equal(undefined);
    const reconcileRow = await TestUtils.execQuery(
      "SELECT state, current_job_id FROM certificate_enrollments WHERE id=$1",
      [reconcile],
    );
    expect(reconcileRow.rows[0].state).to.equal("submission_uncertain");
    expect(reconcileRow.rows[0].current_job_id).to.equal(null);

    const otherFingerprint = crypto.randomBytes(32).toString("hex");
    const otherCertificateId = (await TestUtils.execQuery(
      `INSERT INTO managed_certificates(
         workspace_id, source, source_ref, fingerprint_sha256, name, common_name, status, key_mode
       ) VALUES($1,'agent_filesystem',$2,$3,'decommissioned store','store.example','discovered','os-store-managed')
       RETURNING id`,
      [workspaceId, crypto.randomUUID(), otherFingerprint],
    )).rows[0].id;
    const otherIdentityId = (await TestUtils.execQuery(
      `SELECT id FROM certops_certificate_identities
        WHERE workspace_id=$1 AND fingerprint_sha256=$2`,
      [workspaceId, otherFingerprint],
    )).rows[0].id;
    await TestUtils.execQuery(
      `UPDATE certops_certificate_identities
          SET lifecycle_status='decommissioned', retired_at=NOW()
        WHERE workspace_id=$1 AND id=$2`,
      [workspaceId, otherIdentityId],
    );
    const deployment = {
      keyMode: "vault-managed",
      materialDeployment: {
        groupId: crypto.randomUUID(),
        bindingId: crypto.randomUUID(),
        rolloutId: crypto.randomUUID(),
        materialVersionId: crypto.randomUUID(),
        materialStoreRef: "store",
        providerVersion: 1,
        fingerprintSha256: otherFingerprint,
        generation: 1,
        deploymentProfileRef: "profile",
        profileRevision: 1,
        authorizationRevision: 1,
        verificationPolicy: "served",
      },
    };
    try {
      await createCertificateJob({
        client: pool,
        workspaceId,
        operation: "deploy-from-store",
        subjectType: "managed_certificate",
        subjectId: otherCertificateId,
        payload: deployment,
      });
      throw new Error("deploy-from-store creation should fail");
    } catch (error) {
      expect(error.code).to.equal("CERTOPS_CERTIFICATE_RETIRED");
    }
    const stored = (await TestUtils.execQuery(
      `INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status)
       VALUES($1,'managed_certificate',$2,'renew','pending') RETURNING id`,
      [workspaceId, certificateId],
    )).rows[0];
    await TestUtils.execQuery(
      "UPDATE certificate_jobs SET operation='deploy-from-store' WHERE id=$1",
      [stored.id],
    );
    try {
      await TestUtils.execQuery("UPDATE certificate_jobs SET status='claimed' WHERE id=$1", [stored.id]);
      throw new Error("deploy-from-store claim should fail");
    } catch (error) {
      expect(error.code).to.equal("55000");
    }
    await TestUtils.execQuery(
      "UPDATE certificate_enrollments SET next_poll_at=NULL WHERE workspace_id=$1 AND certificate_id=$2",
      [workspaceId, certificateId],
    );
  });

  it("fences recovery and claims of every non-terminal continuation after retirement", async () => {
    const { claimJobs, _test: dispatchCaps } = require("../../apps/api/services/certops/agentDispatch");
    await assertNoForeignDueRows();
    await pool.query(
      `UPDATE certops_agents SET agent_version='0.18.0', declared_capabilities=$2::jsonb,
              capabilities_updated_at=NOW(), declared_target_selectors=$3::jsonb WHERE id=$1`,
      [agentRowId, JSON.stringify(["adcs-enroll-v1", dispatchCaps.EVIDENCE_CLAIM_BINDING_CAPABILITY,
        dispatchCaps.SIGNED_PAYLOAD_B64_CAPABILITY]), JSON.stringify(["app.example.com", "iis-01/webhosting"])],
    );
    const agentId = (await pool.query("SELECT agent_id FROM certops_agents WHERE id=$1", [agentRowId])).rows[0].agent_id;
    const claim = () => claimJobs({
      dbPool: pool,
      agent: { id: agentRowId, workspaceId, agentId, agentVersion: "0.18.0", protocolVersion: "1.0.0", status: "active" },
      envelope: { agentId, protocolVersion: "1.0.0" },
      body: { supportedActions: ["continue-enrollment"], maxJobs: 16 },
      deps: { enforceAgentSequence: async () => ({ sequence: 1 }), signJobForDispatch: async ({ job, envelopeVersion }) => ({ ...job, envelopeVersion }) },
    }).then((result) => result.jobs.map((job) => String(job.id ?? job.jobId)));
    const retiredCertificate = async (name) => {
      const fingerprint = crypto.randomBytes(32).toString("hex");
      const certificateId = (await pool.query(
        `INSERT INTO managed_certificates(workspace_id, source, source_ref, fingerprint_sha256, name,
                                          common_name, status, key_mode)
         VALUES($1,'agent_filesystem',$2,$3,$4,'retired.example','discovered','os-store-managed') RETURNING id`,
        [workspaceId, crypto.randomUUID(), fingerprint, name],
      )).rows[0].id;
      const identityId = (await pool.query(
        "SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2",
        [workspaceId, fingerprint],
      )).rows[0].id;
      return { certificateId, identityId };
    };
    const continuation = async (enrollmentId, certificateId) => {
      const job = await createCertificateJob({
        client: pool, workspaceId, operation: "continue-enrollment", allowEnrollmentContinuation: true,
        subjectType: "managed_certificate", subjectId: certificateId, assignedAgentId: agentRowId, enrollmentId,
        payload: storedAdcsPayload({ certificateId, target: enrollmentInput().target }),
      });
      await pool.query("UPDATE certificate_enrollments SET current_job_id=$3 WHERE workspace_id=$1 AND id=$2",
        [workspaceId, enrollmentId, job.id]);
      return job.id;
    };

    // A cancelled enrollment keeps its key-cleanup job claimable, and proves the harness can claim.
    const cleanupCert = await retiredCertificate("cleanup after retirement");
    const cleanupEnrollment = await insertEnrollment("cancelled", { certificateId: cleanupCert.certificateId });
    const cleanupJobId = await continuation(cleanupEnrollment, cleanupCert.certificateId);
    await pool.query("UPDATE certops_certificate_identities SET lifecycle_status='revoked', retired_at=NOW() WHERE id=$1", [cleanupCert.identityId]);
    expect(await claim()).to.include(cleanupJobId);

    // First issuance has no identity yet, and a missing identity is not retirement.
    const firstCertificateId = (await pool.query(
      `INSERT INTO managed_certificates(workspace_id, status, source, source_ref, name, common_name,
                                        subject_alt_names, key_mode, key_reference, public_metadata)
       VALUES($1,'provisioning','agent_issuance',$2,'first issuance','first.example',ARRAY['first.example'],
              'os-store-managed','winstore://My/first:443','{}'::jsonb) RETURNING id`,
      [workspaceId, crypto.randomUUID()],
    )).rows[0].id;
    const firstEnrollment = await insertEnrollment("pending_issuance", { certificateId: firstCertificateId });
    const firstJobId = await continuation(firstEnrollment, firstCertificateId);
    expect(await claim(), "continuation of a certificate with no identity").to.include(firstJobId);

    for (const state of ["requested", "prepared", "issued", "validated"]) {
      // Orphaned by a crash: the operator-recovery route must not mint a new install-capable job.
      const orphanCert = await retiredCertificate(`orphan ${state}`);
      const orphanEnrollment = await insertEnrollment(state, { certificateId: orphanCert.certificateId });
      const orphanJobId = await continuation(orphanEnrollment, orphanCert.certificateId);
      await pool.query(
        `UPDATE certificate_jobs SET status='orphaned_unknown_effect', needs_operator_reconciliation=TRUE,
                reconciliation_reason='lease_expired' WHERE id=$1`, [orphanJobId]);
      // Already queued before retirement: the claim must refuse it.
      const queuedCert = await retiredCertificate(`queued ${state}`);
      const queuedEnrollment = await insertEnrollment(state, { certificateId: queuedCert.certificateId });
      const queuedJobId = await continuation(queuedEnrollment, queuedCert.certificateId);
      await pool.query("UPDATE certops_certificate_identities SET lifecycle_status='revoked', retired_at=NOW() WHERE id = ANY($1::uuid[])",
        [[orphanCert.identityId, queuedCert.identityId]]);

      let recoveryError;
      try {
        await recoverOrphanedEnrollment({
          client: pool, workspaceId, enrollmentId: orphanEnrollment, orphanedJobId: orphanJobId,
          acknowledgeUnknownEffect: true, reason: "operator inspected the host", actorUserId: ownerId,
          env: { CERTOPS_ENABLED: "true" },
        });
      } catch (error) {
        recoveryError = error;
      }
      expect(recoveryError?.code, `recovery from ${state}`).to.equal("CERTOPS_CERTIFICATE_RETIRED");
      const jobs = await pool.query("SELECT count(*)::int AS n FROM certificate_jobs WHERE workspace_id=$1 AND enrollment_id=$2", [workspaceId, orphanEnrollment]);
      expect(jobs.rows[0].n, `jobs after refused recovery from ${state}`).to.equal(1);

      expect(await claim(), `claim in ${state}`).to.not.include(queuedJobId);
      const queued = await pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [queuedJobId]);
      expect(queued.rows[0].status).to.equal("pending");
      try {
        await pool.query("UPDATE certificate_jobs SET status='claimed' WHERE id=$1", [queuedJobId]);
        throw new Error(`continuation claim in ${state} should fail`);
      } catch (error) {
        expect(error.code).to.equal("55000");
      }
    }
  });

  it("retirement covers running and queued install-capable work and spares key cleanup", async () => {
    await assertNoForeignDueRows();
    const managed = async () => {
      const fingerprint = crypto.randomBytes(32).toString("hex");
      const certificateId = (await pool.query(
        `INSERT INTO managed_certificates(workspace_id, source, source_ref, fingerprint_sha256, name,
                                          common_name, status, key_mode)
         VALUES($1,'agent_filesystem',$2,$3,'retire coverage','retire.example','discovered','os-store-managed') RETURNING id`,
        [workspaceId, crypto.randomUUID(), fingerprint],
      )).rows[0].id;
      const identityId = (await pool.query(
        "SELECT id FROM certops_certificate_identities WHERE workspace_id=$1 AND fingerprint_sha256=$2",
        [workspaceId, fingerprint],
      )).rows[0].id;
      return { fingerprint, certificateId, identityId };
    };
    const continuation = async (state, { certificateId }) => {
      const enrollmentId = await insertEnrollment(state, { certificateId });
      const job = await createCertificateJob({
        client: pool, workspaceId, operation: "continue-enrollment", allowEnrollmentContinuation: true,
        subjectType: "managed_certificate", subjectId: certificateId, assignedAgentId: agentRowId, enrollmentId,
        payload: storedAdcsPayload({ certificateId, target: enrollmentInput().target }),
      });
      await pool.query("UPDATE certificate_enrollments SET current_job_id=$3 WHERE workspace_id=$1 AND id=$2",
        [workspaceId, enrollmentId, job.id]);
      return job.id;
    };
    const deployFromStore = async ({ certificateId }) => {
      const id = (await pool.query(
        `INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status)
         VALUES($1,'managed_certificate',$2,'renew','pending') RETURNING id`,
        [workspaceId, certificateId],
      )).rows[0].id;
      await pool.query("UPDATE certificate_jobs SET operation='deploy-from-store' WHERE id=$1", [id]);
      return id;
    };
    const run = async (jobId) => {
      await pool.query("UPDATE certificate_jobs SET status='claimed', claimed_by_agent_id=$2 WHERE id=$1", [jobId, agentRowId]);
      await pool.query("UPDATE certificate_jobs SET status='running' WHERE id=$1", [jobId]);
    };
    const retire = (cert, status) => retireCertificateIdentity({
      workspaceId, identityId: cert.identityId, expectedFingerprintSha256: cert.fingerprint, status,
      reason: "retirement coverage", acknowledgeUncertainty: true, actorUserId: ownerId,
    });
    const job = async (id) => (await pool.query(
      "SELECT status, needs_operator_reconciliation AS reconcile FROM certificate_jobs WHERE id=$1", [id])).rows[0];

    // A running install-capable job blocks decommission; a running key cleanup does not.
    for (const [name, make] of [
      ["installing continuation", (cert) => continuation("installing", cert)],
      ["polling continuation", (cert) => continuation("pending_issuance", cert)],
      ["deploy-from-store", deployFromStore],
    ]) {
      const cert = await managed();
      await run(await make(cert));
      try {
        await retire(cert, "decommissioned");
        throw new Error(`${name} should block decommission`);
      } catch (error) {
        expect(error.code, name).to.equal("CERTOPS_MUTATION_RUNNING");
      }
    }
    const cleanupCert = await managed();
    const cleanupId = await continuation("abandoned", cleanupCert);
    await run(cleanupId);
    await retire(cleanupCert, "decommissioned");
    expect((await job(cleanupId)).reconcile).to.equal(false);

    // Revocation flags running install-capable work for reconciliation, never key cleanup.
    for (const [name, make] of [
      ["installing continuation", (cert) => continuation("installing", cert)],
      ["deploy-from-store", deployFromStore],
    ]) {
      const cert = await managed();
      const id = await make(cert);
      await run(id);
      await retire(cert, "revoked");
      expect((await job(id)).reconcile, name).to.equal(true);
    }
    const revokedCleanup = await managed();
    const revokedCleanupId = await continuation("cancelled", revokedCleanup);
    await run(revokedCleanupId);
    await retire(revokedCleanup, "revoked");
    expect((await job(revokedCleanupId)).reconcile).to.equal(false);

    // A queued deploy-from-store is cancelled with the other mutations. A queued
    // continuation is not cancelled: the claim fence refuses it, and abandoning the
    // enrollment turns it into the key-cleanup job.
    const queuedCert = await managed();
    const queuedDeploy = await deployFromStore(queuedCert);
    const queuedContinuation = await continuation("installing", queuedCert);
    await retire(queuedCert, "revoked");
    expect((await job(queuedDeploy)).status).to.equal("cancelled");
    expect((await job(queuedContinuation)).status).to.equal("pending");
  });
});