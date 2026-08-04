const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();

const {
  claimJobs,
  recordHeartbeat,
  _test: dispatchInternals,
} = require("../../apps/api/services/certops/agentDispatch");
const {
  ENVELOPE_VERSION_1,
  ENVELOPE_VERSION_2,
} = require("../../apps/api/services/certops/jobSigning");
const { pool } = require("../../apps/api/db/database");
const {
  DEFAULT_CERTOPS_CAPABILITY_FRESHNESS_MS,
} = require("../../apps/api/services/certops/agentRegistry");

const EVIDENCE_CLAIM_BINDING_CAPABILITY =
  dispatchInternals.EVIDENCE_CLAIM_BINDING_CAPABILITY;
const SIGNED_PAYLOAD_B64_CAPABILITY =
  dispatchInternals.SIGNED_PAYLOAD_B64_CAPABILITY;

/**
 * The issuance claim gate lives entirely in SQL: a NOT EXISTS against
 * managed_certificates.status combined with a boolean capability parameter.
 * Service-level unit tests stub the database, so they can only assert that a
 * query was issued, not that the predicate selects the right rows. Every bug
 * found here was of exactly that shape, so these run against real
 * PostgreSQL.
 */
describe("CertOps issuance claim gating (real database)", function () {
  this.timeout(60000);

  let ownerId;
  let workspaceId;

  before(async () => {
    await runMigrations();

    const email = `claim-gate-${Date.now()}-${crypto.randomUUID()}@example.com`;
    const owner = await TestUtils.execQuery(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ($1, $2, 'Claim Gate', 'unused', 'local', TRUE)
       RETURNING id`,
      [email.toLowerCase(), email],
    );
    ownerId = owner.rows[0].id;

    workspaceId = crypto.randomUUID();
    await TestUtils.execQuery(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES ($1, 'Claim Gate WS', $2, 'oss')`,
      [workspaceId, ownerId],
    );
  });

  after(async () => {
    if (workspaceId) {
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [
        workspaceId,
      ]);
    }
    if (ownerId) {
      await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
    }
  });

  async function createAgent({
    capabilities = [],
    // ADR-0012 decision 17: gated selection also requires a fresh
    // capabilities_updated_at. Defaulting this to "now" keeps every
    // pre-existing test in this file (which seeds capabilities by direct
    // INSERT and expects them to gate exactly as before) passing unchanged;
    // tests that care about freshness pass an explicit Date (or null, to
    // simulate a migrated pre-existing row that was never backfilled).
    capabilitiesUpdatedAt = new Date(),
  } = {}) {
    const agentId = `agent-${crypto.randomUUID()}`;
    const inserted = await TestUtils.execQuery(
      `INSERT INTO certops_agents (
         workspace_id, agent_id, name, agent_version, protocol_version,
         credential_prefix, credential_hash, status, declared_capabilities,
         capabilities_updated_at, last_seen_at
       )
       VALUES ($1, $2, 'gate-agent', '0.11.1', '1.0.0', $3, $4, 'active',
               $5::jsonb, $6, NOW())
       RETURNING id`,
      [
        workspaceId,
        agentId,
        `ttagent_${crypto.randomBytes(8).toString("hex")}`,
        crypto.randomBytes(32).toString("hex"),
        JSON.stringify(capabilities),
        capabilitiesUpdatedAt,
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

  async function createManagedCertificate(status) {
    const inserted = await TestUtils.execQuery(
      `INSERT INTO managed_certificates
         (workspace_id, status, source, source_ref, name, common_name)
       VALUES ($1, $2, 'agent_issuance', $3, 'gate-cert', 'gate.example.com')
       RETURNING id`,
      [workspaceId, status, crypto.randomUUID()],
    );
    return inserted.rows[0].id;
  }

  async function createJob({ operation, subjectId }) {
    const inserted = await TestUtils.execQuery(
      `INSERT INTO certificate_jobs
         (workspace_id, operation, status, executor_kind, mode,
          subject_type, subject_id, payload, requested_by_user_id)
       VALUES ($1, $2, 'pending', 'agent', 'real',
               'managed_certificate', $3, '{}'::jsonb, $4)
       RETURNING id`,
      [workspaceId, operation, subjectId, ownerId],
    );
    return inserted.rows[0].id;
  }

  async function claimJobsFull(agent) {
    const result = await claimJobs({
      dbPool: pool,
      agent,
      envelope: { agentId: agent.agentId, protocolVersion: "1.0.0" },
      body: { supportedActions: ["renew", "deploy"], maxJobs: 10 },
      deps: {
        enforceAgentSequence: async () => ({ sequence: 1 }),
        // Dispatch signing is a separate concern with its own tests and needs
        // provisioned Ed25519 keys. What is under test here is which rows the
        // claim predicate selects (and, for the envelope-version tests below,
        // which envelopeVersion claimJobs decided on), so signing is reduced
        // to identity plus passing envelopeVersion through untouched.
        signJobForDispatch: async ({ job, envelopeVersion }) => ({
          ...job,
          envelopeVersion,
        }),
      },
    });
    return result.jobs || [];
  }

  async function claimFor(agent) {
    const jobs = await claimJobsFull(agent);
    return jobs.map((job) => String(job.jobId ?? job.id));
  }

  // Real recordHeartbeat call (no stubbed enforceAgentSequence/writeAudit):
  // exercises the actual heartbeat write path, including the
  // capabilities_updated_at stamp and the CERTOPS_AGENT_CAPABILITIES_CHANGED
  // audit write, against the real database.
  async function heartbeatFor(agent, body) {
    return recordHeartbeat({
      dbPool: pool,
      agent,
      envelope: {},
      body,
    });
  }

  it("offers an issue job only to an agent that can bind evidence to a claim", async () => {
    const capable = await createAgent({
      capabilities: [EVIDENCE_CLAIM_BINDING_CAPABILITY],
    });
    const legacy = await createAgent({ capabilities: [] });
    const certificateId = await createManagedCertificate("provisioning");
    const jobId = await createJob({
      operation: "issue",
      subjectId: certificateId,
    });

    // An agent that cannot report claim-bound verify evidence would run the
    // issuance and leave the certificate stuck in 'provisioning' forever, so it
    // must never be offered the job in the first place.
    expect(await claimFor(legacy)).to.not.include(String(jobId));

    expect(await claimFor(capable)).to.include(String(jobId));
  });

  it("gates a retrying renew against a still-provisioning certificate", async () => {
    const legacy = await createAgent({ capabilities: [] });
    const capable = await createAgent({
      capabilities: [EVIDENCE_CLAIM_BINDING_CAPABILITY],
    });
    const certificateId = await createManagedCertificate("provisioning");
    // ADR-0008: a failed issuance is retried as an ordinary renew against the
    // still-provisioning certificate, so gating operation = 'issue' alone would
    // leave this path open to an agent that cannot reconcile it.
    const jobId = await createJob({
      operation: "renew",
      subjectId: certificateId,
    });

    expect(await claimFor(legacy)).to.not.include(String(jobId));
    expect(await claimFor(capable)).to.include(String(jobId));
  });

  it("still offers an ordinary renewal of an active certificate to an older agent", async () => {
    const legacy = await createAgent({ capabilities: [] });
    const certificateId = await createManagedCertificate("active");
    const jobId = await createJob({
      operation: "renew",
      subjectId: certificateId,
    });

    // The gate must not regress the existing fleet: capability-less agents keep
    // doing every kind of work they did before.
    expect(await claimFor(legacy)).to.include(String(jobId));
  });

  // --- ADR-0012 decision 17: capability freshness epoch --------------------

  it("replaces rather than unions the declared capability set on a real heartbeat write", async () => {
    const agent = await createAgent({
      capabilities: [
        EVIDENCE_CLAIM_BINDING_CAPABILITY,
        SIGNED_PAYLOAD_B64_CAPABILITY,
      ],
    });

    await heartbeatFor(agent, {
      agentVersion: "0.11.1",
      declaredCapabilities: [SIGNED_PAYLOAD_B64_CAPABILITY],
    });

    const row = await TestUtils.execQuery(
      `SELECT declared_capabilities FROM certops_agents WHERE id = $1`,
      [agent.id],
    );
    expect(row.rows[0].declared_capabilities).to.deep.equal([
      SIGNED_PAYLOAD_B64_CAPABILITY,
    ]);
  });

  it("a downgraded agent that stops advertising signed-payload-b64-v1 never receives a v2 envelope", async () => {
    const agent = await createAgent({
      capabilities: [SIGNED_PAYLOAD_B64_CAPABILITY],
    });
    const certificateId = await createManagedCertificate("active");
    const jobId = await createJob({ operation: "renew", subjectId: certificateId });

    // Before the downgrade: capability is fresh, so the agent gets v2.
    const beforeJobs = await claimJobsFull(agent);
    expect(beforeJobs.map((j) => String(j.jobId))).to.include(String(jobId));
    expect(
      beforeJobs.find((j) => String(j.jobId) === String(jobId)).envelopeVersion,
    ).to.equal(ENVELOPE_VERSION_2);

    // The agent downgrades: heartbeat no longer declares the capability.
    await heartbeatFor(agent, {
      agentVersion: "0.10.0",
      declaredCapabilities: [],
    });

    const certificateId2 = await createManagedCertificate("active");
    const jobId2 = await createJob({ operation: "renew", subjectId: certificateId2 });
    const afterJobs = await claimJobsFull(agent);
    const claimed2 = afterJobs.find((j) => String(j.jobId) === String(jobId2));
    expect(claimed2, "the downgraded agent must still be offered ordinary renew jobs").to.exist;
    expect(claimed2.envelopeVersion).to.equal(ENVELOPE_VERSION_1);
  });

  it("a downgraded agent that stops advertising evidence-claim-binding-v1 is never offered an issue job", async () => {
    const agent = await createAgent({
      capabilities: [EVIDENCE_CLAIM_BINDING_CAPABILITY],
    });

    const certificateId = await createManagedCertificate("provisioning");
    const jobId = await createJob({ operation: "issue", subjectId: certificateId });
    // Before the downgrade: capability is fresh, so the agent is offered the
    // issue job.
    expect(await claimFor(agent)).to.include(String(jobId));

    // Requeue so the same job can be offered again post-downgrade (claiming
    // above transitioned it to 'claimed').
    await TestUtils.execQuery(
      `UPDATE certificate_jobs SET status = 'pending', claimed_by_agent_id = NULL, claim_id = NULL WHERE id = $1`,
      [jobId],
    );

    await heartbeatFor(agent, {
      agentVersion: "0.10.0",
      declaredCapabilities: [],
    });

    expect(await claimFor(agent)).to.not.include(String(jobId));
  });

  it("does not offer a capability-gated job when the assertion is older than the freshness bound, with a test on both sides of the bound", async () => {
    const justUnder = await createAgent({
      capabilities: [EVIDENCE_CLAIM_BINDING_CAPABILITY],
      capabilitiesUpdatedAt: new Date(
        Date.now() - (DEFAULT_CERTOPS_CAPABILITY_FRESHNESS_MS - 5000),
      ),
    });
    const justOver = await createAgent({
      capabilities: [EVIDENCE_CLAIM_BINDING_CAPABILITY],
      capabilitiesUpdatedAt: new Date(
        Date.now() - (DEFAULT_CERTOPS_CAPABILITY_FRESHNESS_MS + 5000),
      ),
    });

    const certUnder = await createManagedCertificate("provisioning");
    const jobUnder = await createJob({ operation: "issue", subjectId: certUnder });
    const certOver = await createManagedCertificate("provisioning");
    const jobOver = await createJob({ operation: "issue", subjectId: certOver });

    expect(await claimFor(justUnder)).to.include(String(jobUnder));
    expect(await claimFor(justOver)).to.not.include(String(jobOver));
  });

  it("writes a CERTOPS_AGENT_CAPABILITIES_CHANGED audit event on a real heartbeat capability change", async () => {
    const agent = await createAgent({ capabilities: [] });

    await heartbeatFor(agent, {
      agentVersion: "0.11.1",
      declaredCapabilities: [EVIDENCE_CLAIM_BINDING_CAPABILITY],
    });

    const audits = await TestUtils.execQuery(
      `SELECT action, metadata
         FROM audit_events
        WHERE workspace_id = $1
          AND action = 'CERTOPS_AGENT_CAPABILITIES_CHANGED'
        ORDER BY id DESC
        LIMIT 1`,
      [workspaceId],
    );
    expect(audits.rows).to.have.length(1);
    expect(audits.rows[0].metadata.agentId).to.equal(agent.agentId);
    expect(audits.rows[0].metadata.declaredCapabilities).to.deep.equal([
      EVIDENCE_CLAIM_BINDING_CAPABILITY,
    ]);
  });

  it("a migrated pre-existing agent row (capabilities_updated_at IS NULL) is never offered a gated job, and becomes eligible once a heartbeat sets the column", async () => {
    // Simulates a row that existed before this migration and was never
    // backfilled: declared_capabilities lists the capability, but its
    // freshness epoch is NULL, which must fail closed.
    const migrated = await createAgent({
      capabilities: [EVIDENCE_CLAIM_BINDING_CAPABILITY],
      capabilitiesUpdatedAt: null,
    });

    const row = await TestUtils.execQuery(
      `SELECT capabilities_updated_at FROM certops_agents WHERE id = $1`,
      [migrated.id],
    );
    expect(row.rows[0].capabilities_updated_at).to.equal(null);

    const certificateId = await createManagedCertificate("provisioning");
    const jobId = await createJob({ operation: "issue", subjectId: certificateId });

    expect(await claimFor(migrated)).to.not.include(String(jobId));

    // A heartbeat that reports capabilities sets the column for the first
    // time, at which point the row becomes eligible normally.
    await heartbeatFor(migrated, {
      agentVersion: "0.11.1",
      declaredCapabilities: [EVIDENCE_CLAIM_BINDING_CAPABILITY],
    });

    const rowAfter = await TestUtils.execQuery(
      `SELECT capabilities_updated_at FROM certops_agents WHERE id = $1`,
      [migrated.id],
    );
    expect(rowAfter.rows[0].capabilities_updated_at).to.not.equal(null);

    expect(await claimFor(migrated)).to.include(String(jobId));
  });
});
