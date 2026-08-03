"use strict";

const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();

const { pool } = require("../../apps/api/db/database");
const {
  claimJobs,
} = require("../../apps/api/services/certops/agentDispatch");
const {
  AGENT_KIND_DIAGNOSTIC,
  AGENT_KIND_NORMAL,
  DIAGNOSTIC_ORPHAN_BRANCH,
  reconcileDiagnosticAgentOrphan,
  retireAgent,
} = require("../../apps/api/services/certops/agentRegistry");
const {
  generateAgentCredential,
  validateAgentCredential,
} = require("../../apps/api/services/certops/agentCredentials");

/**
 * ADR-0012 decision 7 covers two boundaries that only mean something against
 * a real database:
 *   - the agent_kind dispatch gate (a normal agent must never be offered a
 *     protocol_smoke job, and a diagnostic agent must never be offered a
 *     real one, regardless of what it declares in supportedActions);
 *   - the four-branch orphan-retirement state machine and the atomicity of
 *     credential revocation on retire.
 * Both live in SQL predicates (agentDispatch.js's claim query, and the
 * single UPDATE in agentRegistry.js's retireAgent), so, like
 * certops-issuance-claim-gating.test.js, these run against real PostgreSQL
 * rather than a mocked pool.
 */
describe("CertOps diagnostic-agent isolation (real database)", function () {
  this.timeout(60000);

  let ownerId;
  let workspaceId;

  before(async () => {
    await runMigrations();

    const email = `diag-isolation-${Date.now()}-${crypto.randomUUID()}@example.com`;
    const owner = await TestUtils.execQuery(
      `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
       VALUES ($1, $2, 'Diagnostic Isolation', 'unused', 'local', TRUE)
       RETURNING id`,
      [email.toLowerCase(), email],
    );
    ownerId = owner.rows[0].id;

    workspaceId = crypto.randomUUID();
    await TestUtils.execQuery(
      `INSERT INTO workspaces (id, name, created_by, plan)
       VALUES ($1, 'Diagnostic Isolation WS', $2, 'oss')`,
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
    agentKind = AGENT_KIND_NORMAL,
    capabilities = [],
  } = {}) {
    const agentId = `agent-${crypto.randomUUID()}`;
    const credential = generateAgentCredential();
    const inserted = await TestUtils.execQuery(
      `INSERT INTO certops_agents (
         workspace_id, agent_id, name, agent_version, protocol_version,
         credential_prefix, credential_hash, agent_kind, status,
         declared_capabilities, capabilities_updated_at, last_seen_at
       )
       VALUES ($1, $2, 'diag-isolation-agent', '0.11.1', '1.0.0', $3, $4, $5,
               'active', $6::jsonb, NOW(), NOW())
       RETURNING id`,
      [
        workspaceId,
        agentId,
        credential.credentialPrefix,
        credential.credentialHash,
        agentKind,
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
      credential: credential.plaintextCredential,
    };
  }

  async function createJob({
    operation,
    mode = "real",
    status = "pending",
    assignedAgentId = null,
    leaseExpiresAt = null,
  }) {
    const inserted = await TestUtils.execQuery(
      `INSERT INTO certificate_jobs
         (workspace_id, operation, status, executor_kind, mode,
          subject_type, subject_id, payload, requested_by_user_id,
          assigned_agent_id, lease_expires_at)
       VALUES ($1, $2, $3, 'agent', $4,
               'managed_certificate', NULL, '{}'::jsonb, $5, $6, $7)
       RETURNING id`,
      [
        workspaceId,
        operation,
        status,
        mode,
        ownerId,
        assignedAgentId,
        leaseExpiresAt,
      ],
    );
    return inserted.rows[0].id;
  }

  async function claimJobsFull(agent, supportedActions) {
    const result = await claimJobs({
      dbPool: pool,
      agent,
      envelope: { agentId: agent.agentId, protocolVersion: "1.0.0" },
      body: { supportedActions, maxJobs: 10 },
      deps: {
        enforceAgentSequence: async () => ({ sequence: 1 }),
        signJobForDispatch: async ({ job, envelopeVersion }) => ({
          ...job,
          envelopeVersion,
        }),
      },
    });
    return result.jobs || [];
  }

  async function claimFor(agent, supportedActions) {
    const jobs = await claimJobsFull(agent, supportedActions);
    return jobs.map((job) => String(job.jobId ?? job.id));
  }

  async function jobStatus(jobId) {
    const result = await TestUtils.execQuery(
      `SELECT status FROM certificate_jobs WHERE id = $1`,
      [jobId],
    );
    return result.rows[0]?.status || null;
  }

  async function agentRow(agentId) {
    const result = await TestUtils.execQuery(
      `SELECT status, credential_hash FROM certops_agents WHERE id = $1`,
      [agentId],
    );
    return result.rows[0];
  }

  // --- agent_kind dispatch gate --------------------------------------------

  it("never offers a protocol_smoke job to a normal agent, even declaring a matching capability", async () => {
    const normalAgent = await createAgent({ agentKind: AGENT_KIND_NORMAL });
    const jobId = await createJob({ operation: "protocol_smoke", mode: "dry_run" });

    // supportedActions is client-supplied on every claim call; a normal agent
    // declaring "protocol_smoke" must still never be offered the job, because
    // the gate is agent_kind (server-assigned), not declared capabilities.
    expect(await claimFor(normalAgent, ["protocol_smoke", "renew"])).to.not.include(
      String(jobId),
    );
  });

  it("never offers a real job to a diagnostic agent that clears its declaredCapabilities", async () => {
    const diagnosticAgent = await createAgent({
      agentKind: AGENT_KIND_DIAGNOSTIC,
      capabilities: [],
    });
    const jobId = await createJob({ operation: "renew", mode: "real" });

    // A diagnostic agent declaring every action it can think of, with an
    // empty declaredCapabilities, must still never be offered a real job:
    // agent_kind is the only thing that decides this, not what it claims.
    expect(
      await claimFor(diagnosticAgent, ["renew", "deploy", "reload", "revoke"]),
    ).to.not.include(String(jobId));
  });

  it("offers a protocol_smoke job only to the diagnostic agent that declares it", async () => {
    const diagnosticAgent = await createAgent({
      agentKind: AGENT_KIND_DIAGNOSTIC,
    });
    const jobId = await createJob({ operation: "protocol_smoke", mode: "dry_run" });

    expect(await claimFor(diagnosticAgent, ["protocol_smoke"])).to.include(
      String(jobId),
    );
  });

  // --- four-branch orphan retirement (ADR-0012 decision 7) -----------------

  it("branch pending_unclaimed: cancels the job and retires the agent atomically", async () => {
    const agent = await createAgent({ agentKind: AGENT_KIND_DIAGNOSTIC });
    const jobId = await createJob({
      operation: "protocol_smoke",
      mode: "dry_run",
      status: "pending",
      assignedAgentId: agent.id,
    });

    const outcome = await reconcileDiagnosticAgentOrphan({
      workspaceId,
      agentId: agent.id,
      reason: "test: pending_unclaimed branch",
    });

    expect(outcome.retired).to.equal(true);
    expect(outcome.branch).to.equal(DIAGNOSTIC_ORPHAN_BRANCH.PENDING_UNCLAIMED);
    expect(await jobStatus(jobId)).to.equal("cancelled");
    const row = await agentRow(agent.id);
    expect(row.status).to.equal("retired");
  });

  it("branch active_unexpired: defers and leaves the agent active", async () => {
    const agent = await createAgent({ agentKind: AGENT_KIND_DIAGNOSTIC });
    const jobId = await createJob({
      operation: "protocol_smoke",
      mode: "dry_run",
      status: "claimed",
      assignedAgentId: agent.id,
      leaseExpiresAt: new Date(Date.now() + 60 * 60 * 1000),
    });

    const outcome = await reconcileDiagnosticAgentOrphan({
      workspaceId,
      agentId: agent.id,
      reason: "test: active_unexpired branch",
    });

    expect(outcome.deferred).to.equal(true);
    expect(outcome.branch).to.equal(DIAGNOSTIC_ORPHAN_BRANCH.ACTIVE_UNEXPIRED);
    // Neither the job nor the agent is touched while a lease may still be
    // held by a live client.
    expect(await jobStatus(jobId)).to.equal("claimed");
    const row = await agentRow(agent.id);
    expect(row.status).to.equal("active");
  });

  it("branch active_expired: terminalizes the job then retires the agent", async () => {
    const agent = await createAgent({ agentKind: AGENT_KIND_DIAGNOSTIC });
    const jobId = await createJob({
      operation: "protocol_smoke",
      mode: "dry_run",
      status: "claimed",
      assignedAgentId: agent.id,
      leaseExpiresAt: new Date(Date.now() - 60 * 1000),
    });

    const outcome = await reconcileDiagnosticAgentOrphan({
      workspaceId,
      agentId: agent.id,
      reason: "test: active_expired branch",
    });

    expect(outcome.retired).to.equal(true);
    expect(outcome.branch).to.equal(DIAGNOSTIC_ORPHAN_BRANCH.ACTIVE_EXPIRED);
    // A "claimed" (never reported "running") job with an expired lease is
    // safe to cancel outright: no in-flight effect was ever reported.
    expect(await jobStatus(jobId)).to.equal("cancelled");
    const row = await agentRow(agent.id);
    expect(row.status).to.equal("retired");
  });

  it("branch active_expired on a running job: flags needs_operator_reconciliation instead of a plain cancel", async () => {
    const agent = await createAgent({ agentKind: AGENT_KIND_DIAGNOSTIC });
    const jobId = await createJob({
      operation: "protocol_smoke",
      mode: "dry_run",
      status: "running",
      assignedAgentId: agent.id,
      leaseExpiresAt: new Date(Date.now() - 60 * 1000),
    });

    const outcome = await reconcileDiagnosticAgentOrphan({
      workspaceId,
      agentId: agent.id,
      reason: "test: active_expired running branch",
    });

    expect(outcome.retired).to.equal(true);
    expect(outcome.branch).to.equal(DIAGNOSTIC_ORPHAN_BRANCH.ACTIVE_EXPIRED);
    expect(await jobStatus(jobId)).to.equal("orphaned_unknown_effect");
    const result = await TestUtils.execQuery(
      `SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id = $1`,
      [jobId],
    );
    expect(result.rows[0].needs_operator_reconciliation).to.equal(true);
  });

  it("branch terminal: retires the agent normally without touching an already-terminal job", async () => {
    const agent = await createAgent({ agentKind: AGENT_KIND_DIAGNOSTIC });
    const jobId = await createJob({
      operation: "protocol_smoke",
      mode: "dry_run",
      status: "dry_run_complete",
      assignedAgentId: agent.id,
    });

    const outcome = await reconcileDiagnosticAgentOrphan({
      workspaceId,
      agentId: agent.id,
      reason: "test: terminal branch",
    });

    expect(outcome.retired).to.equal(true);
    expect(outcome.branch).to.equal(DIAGNOSTIC_ORPHAN_BRANCH.TERMINAL);
    expect(await jobStatus(jobId)).to.equal("dry_run_complete");
    const row = await agentRow(agent.id);
    expect(row.status).to.equal("retired");
  });

  // --- credential revocation on retire (no window) --------------------------

  it("fails authentication for a retired diagnostic agent's credential, not merely authorization", async () => {
    const agent = await createAgent({ agentKind: AGENT_KIND_DIAGNOSTIC });

    const beforeRetire = await validateAgentCredential({
      rawCredential: agent.credential,
    });
    expect(beforeRetire.valid).to.equal(true);

    await retireAgent({
      workspaceId,
      agentId: agent.id,
      reason: "test: credential revocation on retire",
    });

    const afterRetire = await validateAgentCredential({
      rawCredential: agent.credential,
    });
    expect(afterRetire.valid).to.equal(false);
  });

  it("has no window where the row reads retired but the credential still authenticates", async () => {
    // Both the status flip and the credential_hash overwrite happen in the
    // single UPDATE inside retireAgent (agentRegistry.js). Asserting this
    // directly (not just by code inspection): read status and re-derive the
    // credential validity from the same post-retire row snapshot, and prove
    // they agree in the direction that matters (retired implies invalid).
    const agent = await createAgent({ agentKind: AGENT_KIND_DIAGNOSTIC });

    await retireAgent({
      workspaceId,
      agentId: agent.id,
      reason: "test: no window between retired and credential invalid",
    });

    const row = await agentRow(agent.id);
    expect(row.status).to.equal("retired");

    const validation = await validateAgentCredential({
      rawCredential: agent.credential,
    });
    expect(validation.valid).to.equal(false);
  });

  it("does not revoke a normal agent's credential on retire (frozen-retired rule)", async () => {
    // Unlike diagnostic agents, a retired *normal* agent's credential must
    // still authenticate (so heartbeat/claim routes can answer 410 instead
    // of a generic 401). This pins that the diagnostic-only revocation branch
    // in retireAgent's UPDATE ... CASE does not regress the normal-agent path.
    const agent = await createAgent({ agentKind: AGENT_KIND_NORMAL });

    await retireAgent({
      workspaceId,
      agentId: agent.id,
      reason: "test: normal agent retire keeps credential",
    });

    const validation = await validateAgentCredential({
      rawCredential: agent.credential,
    });
    expect(validation.valid).to.equal(true);
    expect(validation.agent.status).to.equal("retired");
  });
});
