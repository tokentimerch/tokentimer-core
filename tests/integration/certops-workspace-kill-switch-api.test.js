const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

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
} = require("../../apps/api/services/certops/workspaceKillSwitch");
const { writeAudit } = require("../../apps/api/services/audit");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

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
        certOpsEnabled: true,
        certOpsActive: true,
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
      certOpsEnabled: true,
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
      certOpsEnabled: true,
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

  it("blocks only new manual jobs while paused, preserves reads, and resumes cleanly", async () => {
    const blockedSubjectId = "paused-workspace-job";
    const privateKey = "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----";

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
    expect(rejectionAudits).to.have.length(1);
    expect(rejectionAudits[0]).to.include({
      action: "CERTOPS_KEY_MATERIAL_REJECTED",
    });
    expect(rejectionAudits[0].metadata).to.deep.include({
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

  it("keeps machine event and evidence ingestion available for pre-existing work while paused", async () => {
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
        eventType: "job.progress",
        status: "running",
        occurredAt: new Date().toISOString(),
        message: "Work already in flight",
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
});
