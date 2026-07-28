const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const assert = require("node:assert/strict");
const crypto = require("crypto");
const { expect, request, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const {
  createApiToken,
} = require("../../apps/api/services/certops/apiTokens");
const {
  createCertificateJob,
} = require("../../apps/api/services/certops/jobs");
const {
  setWorkspaceCertOpsPauseState,
  createManualCertificateJob,
} = require("../../apps/api/services/certops/workspaceKillSwitch");
const { writeAudit } = require("../../apps/api/services/audit");
const { pool } = require("../../apps/api/db/database");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";
const CERTOPS_ENABLED = ["1", "true", "yes", "on", "enabled"].includes(
  String(process.env.CERTOPS_ENABLED || "").trim().toLowerCase(),
);
const INTERNAL_WORKER_KEY = process.env.WORKER_API_KEY || process.env.SESSION_SECRET;

function deferred() {
  let resolve;
  const promise = new Promise((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

function singleClientPool(client, onQuery = null) {
  let released = false;
  return {
    async connect() {
      return {
        async query(sql, params) {
          onQuery?.(String(sql).replace(/\s+/g, " ").trim());
          return client.query(sql, params);
        },
        release() {
          if (!released) {
            released = true;
            client.release();
          }
        },
      };
    },
  };
}

const LOCK_WAIT_TIMEOUT_MS = 5_000;
const LOCK_WAIT_POLL_INTERVAL_MS = 25;

async function backendPid(client) {
  const result = await client.query("SELECT pg_backend_pid() AS pid");
  return Number(result.rows[0].pid);
}

async function waitForBlockingBackend({
  observerClient,
  waiterPid,
  blockerPid,
  description,
}) {
  const deadline = Date.now() + LOCK_WAIT_TIMEOUT_MS;
  let blockingPids = [];

  while (Date.now() < deadline) {
    const result = await observerClient.query(
      "SELECT pg_blocking_pids($1) AS blocking_pids",
      [waiterPid],
    );
    blockingPids = result.rows[0]?.blocking_pids || [];
    if (blockingPids.map(Number).includes(blockerPid)) {
      console.info(
        `[certops workspace race] ${description}: waiter=${waiterPid}, blocker=${blockerPid}, pg_blocking_pids=[${blockingPids.join(", ")}]`,
      );
      return blockingPids.map(Number);
    }
    await new Promise((resolve) => setTimeout(resolve, LOCK_WAIT_POLL_INTERVAL_MS));
  }

  throw new Error(
    `${description}: expected PostgreSQL backend ${waiterPid} to be blocked by ${blockerPid} within ${LOCK_WAIT_TIMEOUT_MS}ms; last pg_blocking_pids=[${blockingPids.join(", ")}]`,
  );
}

async function primaryWorkspaceId(session) {
  const response = await request(BASE)
    .get("/api/v1/workspaces?limit=50&offset=0")
    .set("Cookie", session.cookie)
    .expect(200);
  return response.body.items[0].id;
}

async function createFixture() {
  const ownerUser = await TestUtils.createVerifiedTestUser();
  const ownerSession = await TestUtils.loginTestUser(
    ownerUser.email,
    "SecureTest123!@#",
  );
  const workspaceId = await primaryWorkspaceId(ownerSession);

  const managerUser = await TestUtils.createVerifiedTestUser();
  const managerSession = await TestUtils.loginTestUser(
    managerUser.email,
    "SecureTest123!@#",
  );
  const viewerUser = await TestUtils.createVerifiedTestUser();
  const viewerSession = await TestUtils.loginTestUser(
    viewerUser.email,
    "SecureTest123!@#",
  );
  await TestUtils.execQuery(
    `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
     VALUES ($1, $2, 'workspace_manager', $3), ($4, $2, 'viewer', $3)
     ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = EXCLUDED.role`,
    [managerUser.id, workspaceId, ownerUser.id, viewerUser.id],
  );

  const outsiderUser = await TestUtils.createVerifiedTestUser();
  const outsiderSession = await TestUtils.loginTestUser(
    outsiderUser.email,
    "SecureTest123!@#",
  );
  const outsiderWorkspaceId = await primaryWorkspaceId(outsiderSession);

  return {
    ownerUser,
    ownerSession,
    managerUser,
    managerSession,
    viewerUser,
    viewerSession,
    outsiderUser,
    outsiderSession,
    workspaceId,
    outsiderWorkspaceId,
  };
}

async function cleanupFixture(fixture) {
  if (!fixture) return;
  const workspaceIds = [fixture.workspaceId, fixture.outsiderWorkspaceId].filter(
    Boolean,
  );
  if (workspaceIds.length > 0) {
    await TestUtils.execQuery(
      "DELETE FROM audit_events WHERE workspace_id = ANY($1::uuid[])",
      [workspaceIds],
    );
    await TestUtils.execQuery(
      "DELETE FROM certificate_executor_events WHERE workspace_id = ANY($1::uuid[])",
      [workspaceIds],
    );
    await TestUtils.execQuery(
      "DELETE FROM certificate_evidence WHERE workspace_id = ANY($1::uuid[])",
      [workspaceIds],
    );
    await TestUtils.execQuery(
      "DELETE FROM certificate_job_log WHERE workspace_id = ANY($1::uuid[])",
      [workspaceIds],
    );
    await TestUtils.execQuery(
      "DELETE FROM certificate_jobs WHERE workspace_id = ANY($1::uuid[])",
      [workspaceIds],
    );
    await TestUtils.execQuery(
      "DELETE FROM api_tokens WHERE workspace_id = ANY($1::uuid[])",
      [workspaceIds],
    );
    await TestUtils.execQuery(
      "DELETE FROM workspaces WHERE id = ANY($1::uuid[])",
      [workspaceIds],
    );
  }

  for (const [user, session] of [
    [fixture.ownerUser, fixture.ownerSession],
    [fixture.managerUser, fixture.managerSession],
    [fixture.viewerUser, fixture.viewerSession],
    [fixture.outsiderUser, fixture.outsiderSession],
  ]) {
    if (user?.email && session?.cookie) {
      await TestUtils.cleanupTestUser(user.email, session.cookie);
    }
  }
}

async function pauseAudits(workspaceId) {
  const result = await TestUtils.execQuery(
    `SELECT action, actor_user_id, subject_user_id, metadata
       FROM audit_events
      WHERE workspace_id = $1
        AND action IN ('CERTOPS_WORKSPACE_PAUSED', 'CERTOPS_WORKSPACE_RESUMED')
      ORDER BY id ASC`,
    [workspaceId],
  );
  return result.rows;
}

async function jobsForSubject(workspaceId, subjectId) {
  const result = await TestUtils.execQuery(
    `SELECT id
       FROM certificate_jobs
      WHERE workspace_id = $1 AND subject_id = $2`,
    [workspaceId, subjectId],
  );
  return result.rows;
}

async function manualJobAudits(workspaceId, subjectId) {
  const result = await TestUtils.execQuery(
    `SELECT id
       FROM audit_events
      WHERE workspace_id = $1
        AND action = 'CERTOPS_JOB_CREATED_MANUAL'
        AND metadata->>'subjectId' = $2`,
    [workspaceId, subjectId],
  );
  return result.rows;
}

async function keyRejectionAudits(workspaceId) {
  const result = await TestUtils.execQuery(
    `SELECT action, metadata
       FROM audit_events
      WHERE workspace_id = $1
        AND action = 'CERTOPS_KEY_MATERIAL_REJECTED'
      ORDER BY id ASC`,
    [workspaceId],
  );
  return result.rows;
}

describe("CertOps workspace kill-switch API", function () {
  this.timeout(60000);

  let fixture;

  before(async () => {
    await runMigrations();
    fixture = await createFixture();
  });

  after(async () => {
    await cleanupFixture(fixture);
  });

  it("allows members to read but only admins to change the workspace-local state", async () => {
    for (const session of [fixture.ownerSession, fixture.managerSession, fixture.viewerSession]) {
      const response = await request(BASE)
        .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
        .set("Cookie", session.cookie)
        .expect(200);
      expect(response.body).to.include({
        workspaceId: fixture.workspaceId,
        certOpsPaused: false,
        certOpsEnabled: CERTOPS_ENABLED,
        certOpsActive: CERTOPS_ENABLED,
      });
    }

    const outsider = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
      .set("Cookie", fixture.outsiderSession.cookie);
    expect(outsider.status).to.equal(404);
    expect(outsider.body).to.deep.equal({ error: "Workspace not found" });
    const unknownWorkspace = await request(BASE)
      .get(`/api/v1/workspaces/${crypto.randomUUID()}/certops/settings`)
      .set("Cookie", fixture.outsiderSession.cookie);
    expect(unknownWorkspace.status).to.equal(404);
    expect(unknownWorkspace.body).to.deep.equal(outsider.body);

    const unrelatedRoute = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.outsiderSession.cookie);
    expect(unrelatedRoute.status).to.equal(403);

    for (const session of [fixture.managerSession, fixture.viewerSession]) {
      const denied = await request(BASE)
        .put(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
        .set("Cookie", session.cookie)
        .send({ certOpsPaused: true });
      expect(denied.status).to.equal(403);
    }

    const paused = await request(BASE)
      .put(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
      .set("Cookie", fixture.ownerSession.cookie)
      .send({ certOpsPaused: true, reason: "incident token=should-not-persist" })
      .expect(200);
    expect(paused.body).to.deep.include({
      workspaceId: fixture.workspaceId,
      certOpsPaused: true,
      certOpsEnabled: CERTOPS_ENABLED,
      certOpsActive: false,
      changed: true,
    });

    const persisted = await TestUtils.execQuery(
      "SELECT certops_paused FROM workspaces WHERE id = $1",
      [fixture.workspaceId],
    );
    expect(persisted.rows[0].certops_paused).to.equal(true);
    const audits = await pauseAudits(fixture.workspaceId);
    expect(audits).to.have.length(1);
    expect(audits[0]).to.include({
      action: "CERTOPS_WORKSPACE_PAUSED",
      actor_user_id: fixture.ownerUser.id,
      subject_user_id: fixture.ownerUser.id,
    });
    expect(audits[0].metadata).to.deep.include({
      workspaceId: fixture.workspaceId,
      previousCertOpsPaused: false,
      certOpsPaused: true,
      certOpsEnabled: CERTOPS_ENABLED,
      certOpsActive: false,
      reason: "incident token=[REDACTED]",
    });

    const sameValue = await request(BASE)
      .put(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
      .set("Cookie", fixture.ownerSession.cookie)
      .send({ certOpsPaused: true })
      .expect(200);
    expect(sameValue.body.changed).to.equal(false);
    expect(await pauseAudits(fixture.workspaceId)).to.have.length(1);

    const otherWorkspace = await TestUtils.execQuery(
      "SELECT certops_paused FROM workspaces WHERE id = $1",
      [fixture.outsiderWorkspaceId],
    );
    expect(otherWorkspace.rows[0].certops_paused).to.equal(false);
  });

  it("rejects internal worker credentials from reading or changing settings", async function () {
    if (!INTERNAL_WORKER_KEY) this.skip();
    const authorization = `Bearer ${INTERNAL_WORKER_KEY}`;
    const stateBefore = await TestUtils.execQuery(
      "SELECT certops_paused FROM workspaces WHERE id = $1",
      [fixture.workspaceId],
    );
    const auditsBefore = await pauseAudits(fixture.workspaceId);

    const getResponse = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
      .set("Authorization", authorization);
    expect(getResponse.status).to.equal(403);
    expect(getResponse.body).to.deep.equal({
      error: "Forbidden: session user required",
      code: "INSUFFICIENT_ROLE",
    });
    expect(getResponse.body).to.not.have.property("workspaceId");

    const putResponse = await request(BASE)
      .put(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
      .set("Authorization", authorization)
      .send({ certOpsPaused: !stateBefore.rows[0].certops_paused });
    expect(putResponse.status).to.equal(403);
    expect(putResponse.body).to.deep.equal(getResponse.body);

    const stateAfter = await TestUtils.execQuery(
      "SELECT certops_paused FROM workspaces WHERE id = $1",
      [fixture.workspaceId],
    );
    expect(stateAfter.rows[0].certops_paused).to.equal(
      stateBefore.rows[0].certops_paused,
    );
    expect(await pauseAudits(fixture.workspaceId)).to.have.length(
      auditsBefore.length,
    );
  });

  it("rejects worker settings key material before the session-user denial", async function () {
    if (!INTERNAL_WORKER_KEY) this.skip();
    const rejectionAuditsBefore = await keyRejectionAudits(fixture.workspaceId);
    const privateKey = "-----BEGIN PRIVATE KEY-----\nworker-secret\n-----END PRIVATE KEY-----";

    const response = await request(BASE)
      .put(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
      .set("Authorization", `Bearer ${INTERNAL_WORKER_KEY}`)
      .send({ certOpsPaused: true, reason: privateKey });
    expect(response.status).to.equal(422);
    expect(response.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
    expect(JSON.stringify(response.body)).to.not.include(privateKey);

    const rejectionAuditsAfter = await keyRejectionAudits(fixture.workspaceId);
    expect(rejectionAuditsAfter).to.have.length(rejectionAuditsBefore.length + 1);
    const rejectionAudit = rejectionAuditsAfter.at(-1);
    expect(JSON.stringify(rejectionAudit.metadata)).to.not.include(privateKey);
    expect(rejectionAudit.metadata).to.deep.include({
      code: "PRIVATE_KEY_MATERIAL_REJECTED",
      method: "PUT",
      path: "/api/v1/workspaces/:id/certops/settings",
    });
  });

  it("blocks only new manual jobs while paused, preserves reads, and resumes cleanly", async function () {
    if (!CERTOPS_ENABLED) {
      const blockedSubjectId = `rollout-disabled-job-${crypto.randomUUID()}`;
      const unavailable = await request(BASE)
        .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
        .set("Cookie", fixture.viewerSession.cookie);
      expect(unavailable.status).to.equal(404);
      const blocked = await request(BASE)
        .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
        .set("Cookie", fixture.managerSession.cookie)
        .send({
          operation: "deploy",
          subjectType: "managed_certificate",
          subjectId: blockedSubjectId,
        });
      expect(blocked.status).to.equal(404);
      expect(await jobsForSubject(fixture.workspaceId, blockedSubjectId)).to.have.length(0);
      expect(await manualJobAudits(fixture.workspaceId, blockedSubjectId)).to.have.length(0);
      await request(BASE)
        .put(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
        .set("Cookie", fixture.ownerSession.cookie)
        .send({ certOpsPaused: false, reason: "rollout-disabled verification complete" })
        .expect(200);
      return;
    }
    const blockedSubjectId = "paused-workspace-job";
    const privateKey = "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----";
    const rejectionAuditsBefore = await keyRejectionAudits(fixture.workspaceId);

    const blocked = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({ operation: "deploy", subjectType: "managed_certificate", subjectId: blockedSubjectId });
    expect(blocked.status).to.equal(409);
    expect(blocked.body.code).to.equal("CERTOPS_WORKSPACE_PAUSED");
    expect(await jobsForSubject(fixture.workspaceId, blockedSubjectId)).to.have.length(0);
    expect(await manualJobAudits(fixture.workspaceId, blockedSubjectId)).to.have.length(0);

    // The canonical key-material boundary still wins over the pause response.
    const keyRejected = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.viewerSession.cookie)
      .send({
        operation: "deploy",
        payload: { note: privateKey },
      });
    expect(keyRejected.status).to.equal(422);
    expect(keyRejected.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
    const rejectionAudits = await keyRejectionAudits(fixture.workspaceId);
    expect(rejectionAudits).to.have.length(rejectionAuditsBefore.length + 1);
    const keyRejectionAudit = rejectionAudits.at(-1);
    expect(keyRejectionAudit).to.include({
      action: "CERTOPS_KEY_MATERIAL_REJECTED",
    });
    expect(keyRejectionAudit.metadata).to.deep.include({
      code: "PRIVATE_KEY_MATERIAL_REJECTED",
      method: "POST",
      path: "/api/v1/workspaces/:id/certops/jobs",
      body_type: "object",
    });

    const passiveRead = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.viewerSession.cookie)
      .expect(200);
    expect(passiveRead.body).to.have.property("items");

    const resumed = await request(BASE)
      .put(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
      .set("Cookie", fixture.ownerSession.cookie)
      .send({ certOpsPaused: false, reason: "incident resolved" })
      .expect(200);
    expect(resumed.body).to.deep.include({
      certOpsPaused: false,
      certOpsActive: true,
      changed: true,
    });

    const created = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({ operation: "deploy", subjectType: "managed_certificate", subjectId: blockedSubjectId })
      .expect(201);
    expect(created.body.job.subjectId).to.equal(blockedSubjectId);
    expect(await jobsForSubject(fixture.workspaceId, blockedSubjectId)).to.have.length(1);
    expect(await manualJobAudits(fixture.workspaceId, blockedSubjectId)).to.have.length(1);

    const audits = await pauseAudits(fixture.workspaceId);
    expect(audits.map((audit) => audit.action)).to.deep.equal([
      "CERTOPS_WORKSPACE_PAUSED",
      "CERTOPS_WORKSPACE_RESUMED",
    ]);
    expect(audits[1].metadata).to.deep.include({
      previousCertOpsPaused: true,
      certOpsPaused: false,
      certOpsActive: true,
      reason: "incident resolved",
    });
  });

  it("rejects invalid update input without changing state", async () => {
    const invalidState = await request(BASE)
      .put(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
      .set("Cookie", fixture.ownerSession.cookie)
      .send({ certOpsPaused: "true" });
    expect(invalidState.status).to.equal(400);
    expect(invalidState.body.code).to.equal("CERTOPS_WORKSPACE_PAUSE_STATE_INVALID");

    const invalidReason = await request(BASE)
      .put(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
      .set("Cookie", fixture.ownerSession.cookie)
      .send({ certOpsPaused: false, reason: "x".repeat(501) });
    expect(invalidReason.status).to.equal(400);
    expect(invalidReason.body.code).to.equal("CERTOPS_WORKSPACE_PAUSE_REASON_INVALID");

    const state = await TestUtils.execQuery(
      "SELECT certops_paused FROM workspaces WHERE id = $1",
      [fixture.workspaceId],
    );
    expect(state.rows[0].certops_paused).to.equal(false);
  });

  it("keeps a same-request idempotent manual-job replay to one audit", async function () {
    if (!CERTOPS_ENABLED) this.skip();
    const subjectId = `manual-idempotency-${crypto.randomUUID()}`;
    const body = {
      operation: "deploy",
      subjectType: "managed_certificate",
      subjectId,
      idempotencyKey: `manual-job-${crypto.randomUUID()}`,
    };

    const first = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send(body)
      .expect(201);
    const replay = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send(body)
      .expect(201);

    expect(replay.body.job.id).to.equal(first.body.job.id);
    expect(await jobsForSubject(fixture.workspaceId, subjectId)).to.have.length(1);
    expect(await manualJobAudits(fixture.workspaceId, subjectId)).to.have.length(1);
  });

  it("exposes both workspace pause states independently of the global rollout", async () => {
    for (const certOpsPaused of [true, false]) {
      const response = await request(BASE)
        .put(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
        .set("Cookie", fixture.ownerSession.cookie)
        .send({ certOpsPaused })
        .expect(200);
      expect(response.body).to.deep.include({
        workspaceId: fixture.workspaceId,
        certOpsPaused,
        certOpsEnabled: CERTOPS_ENABLED,
        certOpsActive: CERTOPS_ENABLED && !certOpsPaused,
      });
    }
  });

  it("rejects private key material on settings before role checks even with rollout disabled", async () => {
    const before = await keyRejectionAudits(fixture.workspaceId);
    const privateKey = "-----BEGIN PRIVATE KEY-----\nnot-allowed\n-----END PRIVATE KEY-----";

    for (const session of [fixture.ownerSession, fixture.managerSession]) {
      const response = await request(BASE)
        .put(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
        .set("Cookie", session.cookie)
        .send({ certOpsPaused: false, reason: privateKey });
      expect(response.status).to.equal(422);
      expect(response.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
    }

    const after = await keyRejectionAudits(fixture.workspaceId);
    expect(after).to.have.length(before.length + 2);
  });

  it("keeps machine event and evidence ingestion available for pre-existing work while paused", async function () {
    if (!CERTOPS_ENABLED) this.skip();
    const paused = await request(BASE)
      .put(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
      .set("Cookie", fixture.ownerSession.cookie)
      .send({ certOpsPaused: true, reason: "verify in-flight reporting" })
      .expect(200);
    expect(paused.body.certOpsPaused).to.equal(true);

    const job = await createCertificateJob({
      workspaceId: fixture.workspaceId,
      operation: "deploy",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: `paused-http-job-${crypto.randomUUID()}`,
      payload: {
        deploymentTarget: "kubernetes/default/web-cert",
        fingerprintSha256:
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
      requestedByUserId: fixture.ownerUser.id,
    });
    const token = await createApiToken({
      workspaceId: fixture.workspaceId,
      name: "Paused workspace HTTP verifier",
      scopes: ["certops:events:write", "certops:evidence:write"],
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      createdBy: fixture.ownerUser.id,
    });
    const auth = `Bearer ${token.plaintextToken}`;

    const eventResponse = await request(BASE)
      .post(`/api/v1/certops/jobs/${job.id}/events`)
      .set("Authorization", auth)
      .send({
        schemaVersion: 1,
        eventId: `event-${crypto.randomUUID()}`,
        eventType: "job.completed",
        status: "succeeded",
        occurredAt: new Date().toISOString(),
        message: "Work already in flight completed safely",
      });
    expect(eventResponse.status).to.equal(202);

    const evidenceResponse = await request(BASE)
      .post(`/api/v1/certops/jobs/${job.id}/evidence`)
      .set("Authorization", auth)
      .send({
        schemaVersion: 1,
        eventId: `event-${crypto.randomUUID()}`,
        occurredAt: new Date().toISOString(),
        evidence: [
          {
            eventType: "certificate.observed",
            output: "paused workspace status reported honestly",
          },
        ],
      });
    expect(evidenceResponse.status).to.equal(202);
    expect(evidenceResponse.body.evidenceIds).to.have.length(1);

    await request(BASE)
      .put(`/api/v1/workspaces/${fixture.workspaceId}/certops/settings`)
      .set("Cookie", fixture.ownerSession.cookie)
      .send({ certOpsPaused: false, reason: "reporting verification complete" })
      .expect(200);
  });

  it("serializes concurrent opposite transitions with accurate prior state and audit history", async () => {
    const priorAudits = await pauseAudits(fixture.workspaceId);
    let releasePausedAudit;
    const pausedAuditEntered = new Promise((resolve) => {
      releasePausedAudit = resolve;
    });
    let continuePausedAudit;
    const pauseCommitGate = new Promise((resolve) => {
      continuePausedAudit = resolve;
    });

    const pause = setWorkspaceCertOpsPauseState({
      workspaceId: fixture.workspaceId,
      certOpsPaused: true,
      reason: "serialize transition test",
      actorUserId: fixture.ownerUser.id,
      auditWriter: async (event) => {
        await writeAudit(event);
        releasePausedAudit();
        await pauseCommitGate;
      },
    });

    await pausedAuditEntered;
    const resume = setWorkspaceCertOpsPauseState({
      workspaceId: fixture.workspaceId,
      certOpsPaused: false,
      reason: "serialize transition test",
      actorUserId: fixture.ownerUser.id,
    });
    continuePausedAudit();

    const [paused, resumed] = await Promise.all([pause, resume]);
    expect(paused).to.deep.include({
      certOpsPaused: true,
      changed: true,
    });
    expect(resumed).to.deep.include({
      certOpsPaused: false,
      changed: true,
    });

    const audits = await pauseAudits(fixture.workspaceId);
    const transitions = audits.slice(priorAudits.length);
    expect(transitions.map((audit) => audit.action)).to.deep.equal([
      "CERTOPS_WORKSPACE_PAUSED",
      "CERTOPS_WORKSPACE_RESUMED",
    ]);
    expect(transitions.map((audit) => audit.metadata.previousCertOpsPaused)).to.deep.equal([
      false,
      true,
    ]);
    const state = await TestUtils.execQuery(
      "SELECT certops_paused FROM workspaces WHERE id = $1",
      [fixture.workspaceId],
    );
    expect(state.rows[0].certops_paused).to.equal(false);
  });

  it("serializes real PostgreSQL pause and manual-job races in both commit orders", async function () {
    if (!CERTOPS_ENABLED) this.skip();
    const subjectAfterPause = `pause-first-${crypto.randomUUID()}`;
    const pauseAuditEntered = deferred();
    const releasePauseCommit = deferred();
    let pauseClient;
    let jobClient;
    let pauseFirstObserver;
    let pauseFirst;
    let pauseFirstJob;

    try {
      pauseClient = await pool.connect();
      jobClient = await pool.connect();
      pauseFirstObserver = await pool.connect();
      const pausePid = await backendPid(pauseClient);
      const jobPid = await backendPid(jobClient);

      pauseFirst = setWorkspaceCertOpsPauseState({
        workspaceId: fixture.workspaceId,
        certOpsPaused: true,
        reason: "pause wins race",
        actorUserId: fixture.ownerUser.id,
        dbPool: singleClientPool(pauseClient),
        auditWriter: async (event) => {
          await writeAudit(event);
          pauseAuditEntered.resolve();
          await releasePauseCommit.promise;
        },
      });
      await pauseAuditEntered.promise;

      const shareRequested = deferred();
      pauseFirstJob = createManualCertificateJob({
        workspaceId: fixture.workspaceId,
        operation: "deploy",
        subjectType: "managed_certificate",
        subjectId: subjectAfterPause,
        requestedByUserId: fixture.managerUser.id,
        actorUserId: fixture.managerUser.id,
        dbPool: singleClientPool(jobClient, (sql) => {
          if (sql.endsWith("FOR SHARE")) shareRequested.resolve();
        }),
      });
      await shareRequested.promise;
      const pauseFirstBlockingPids = await waitForBlockingBackend({
        observerClient: pauseFirstObserver,
        waiterPid: jobPid,
        blockerPid: pausePid,
        description: "pause-first FOR SHARE waits for FOR UPDATE",
      });
      expect(pauseFirstBlockingPids).to.include(pausePid);
      releasePauseCommit.resolve();
      await pauseFirst;
      await assert.rejects(
        () => pauseFirstJob,
        (error) => error?.code === "CERTOPS_WORKSPACE_PAUSED",
      );
      const pauseFirstState = await TestUtils.execQuery(
        "SELECT certops_paused FROM workspaces WHERE id = $1",
        [fixture.workspaceId],
      );
      expect(pauseFirstState.rows[0].certops_paused).to.equal(true);
      expect(await jobsForSubject(fixture.workspaceId, subjectAfterPause)).to.have.length(0);
      expect(await manualJobAudits(fixture.workspaceId, subjectAfterPause)).to.have.length(0);
    } finally {
      releasePauseCommit.resolve();
      await Promise.allSettled([pauseFirst, pauseFirstJob].filter(Boolean));
      try {
        pauseFirstObserver?.release();
      } catch (_) {}
      try {
        pauseClient?.release();
      } catch (_) {}
      try {
        jobClient?.release();
      } catch (_) {}
    }

    await TestUtils.execQuery(
      "UPDATE workspaces SET certops_paused = FALSE WHERE id = $1",
      [fixture.workspaceId],
    );

    const subjectBeforePause = `job-first-${crypto.randomUUID()}`;
    const jobAuditEntered = deferred();
    const releaseJobCommit = deferred();
    let firstJobClient;
    let secondPauseClient;
    let jobFirstObserver;
    let jobFirst;
    let jobFirstPause;

    try {
      firstJobClient = await pool.connect();
      secondPauseClient = await pool.connect();
      jobFirstObserver = await pool.connect();
      const jobPid = await backendPid(firstJobClient);
      const pausePid = await backendPid(secondPauseClient);

      jobFirst = createManualCertificateJob({
        workspaceId: fixture.workspaceId,
        operation: "deploy",
        subjectType: "managed_certificate",
        subjectId: subjectBeforePause,
        requestedByUserId: fixture.managerUser.id,
        actorUserId: fixture.managerUser.id,
        dbPool: singleClientPool(firstJobClient),
        auditWriter: async (event) => {
          await writeAudit(event);
          jobAuditEntered.resolve();
          await releaseJobCommit.promise;
        },
      });
      await jobAuditEntered.promise;

      const updateLockRequested = deferred();
      jobFirstPause = setWorkspaceCertOpsPauseState({
        workspaceId: fixture.workspaceId,
        certOpsPaused: true,
        reason: "job wins race",
        actorUserId: fixture.ownerUser.id,
        dbPool: singleClientPool(secondPauseClient, (sql) => {
          if (sql.endsWith("FOR UPDATE")) updateLockRequested.resolve();
        }),
      });
      await updateLockRequested.promise;
      const jobFirstBlockingPids = await waitForBlockingBackend({
        observerClient: jobFirstObserver,
        waiterPid: pausePid,
        blockerPid: jobPid,
        description: "job-first FOR UPDATE waits for FOR SHARE",
      });
      expect(jobFirstBlockingPids).to.include(jobPid);
      releaseJobCommit.resolve();

      const [created, paused] = await Promise.all([jobFirst, jobFirstPause]);
      expect(created.created).to.equal(true);
      expect(paused.certOpsPaused).to.equal(true);
      expect(await jobsForSubject(fixture.workspaceId, subjectBeforePause)).to.have.length(1);
      expect(await manualJobAudits(fixture.workspaceId, subjectBeforePause)).to.have.length(1);
      const jobFirstState = await TestUtils.execQuery(
        "SELECT certops_paused FROM workspaces WHERE id = $1",
        [fixture.workspaceId],
      );
      expect(jobFirstState.rows[0].certops_paused).to.equal(true);
    } finally {
      releaseJobCommit.resolve();
      await Promise.allSettled([jobFirst, jobFirstPause].filter(Boolean));
      try {
        jobFirstObserver?.release();
      } catch (_) {}
      try {
        firstJobClient?.release();
      } catch (_) {}
      try {
        secondPauseClient?.release();
      } catch (_) {}
    }

    await TestUtils.execQuery(
      "UPDATE workspaces SET certops_paused = FALSE WHERE id = $1",
      [fixture.workspaceId],
    );
  });
});
