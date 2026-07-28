const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();

const {
  claimJobs,
  _test: dispatchInternals,
} = require("../../apps/api/services/certops/agentDispatch");
const { pool } = require("../../apps/api/db/database");

const EVIDENCE_CLAIM_BINDING_CAPABILITY =
  dispatchInternals.EVIDENCE_CLAIM_BINDING_CAPABILITY;

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

  async function createAgent({ capabilities = [] } = {}) {
    const agentId = `agent-${crypto.randomUUID()}`;
    const inserted = await TestUtils.execQuery(
      `INSERT INTO certops_agents (
         workspace_id, agent_id, name, agent_version, protocol_version,
         credential_prefix, credential_hash, status, declared_capabilities,
         last_seen_at
       )
       VALUES ($1, $2, 'gate-agent', '0.11.0', '1.0.0', $3, $4, 'active',
               $5::jsonb, NOW())
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
      agentVersion: "0.11.0",
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

  async function claimFor(agent) {
    const result = await claimJobs({
      dbPool: pool,
      agent,
      envelope: { agentId: agent.agentId, protocolVersion: "1.0.0" },
      body: { supportedActions: ["renew", "deploy"], maxJobs: 10 },
      deps: {
        enforceAgentSequence: async () => ({ sequence: 1 }),
        // Dispatch signing is a separate concern with its own tests and needs
        // provisioned Ed25519 keys. What is under test here is which rows the
        // claim predicate selects, so signing is reduced to identity.
        signJobForDispatch: async ({ job }) => job,
      },
    });
    return (result.jobs || []).map((job) => String(job.jobId ?? job.id));
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
});
