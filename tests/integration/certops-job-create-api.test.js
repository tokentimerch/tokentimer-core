const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const crypto = require("node:crypto");
const { expect, request, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const {
  updateCertificateJobStatus,
} = require("../../apps/api/services/certops/jobs");

const BASE = process.env.TEST_API_URL || "http://localhost:4000";

async function primaryWorkspaceId(session) {
  const response = await request(BASE)
    .get("/api/v1/workspaces?limit=50&offset=0")
    .set("Cookie", session.cookie)
    .expect(200);
  return response.body.items[0].id;
}

function walkKeys(value, visit) {
  if (Array.isArray(value)) {
    for (const item of value) walkKeys(item, visit);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    visit(key);
    walkKeys(item, visit);
  }
}

function expectNoPrivateKeyFields(value) {
  const forbiddenFragments = [
    "privatekey",
    "privatekeypem",
    "encryptedprivatekey",
    "keymaterial",
    "pfxblob",
    "jksblob",
    "tlskey",
    "caprivatekey",
    "keystorepassword",
    "privatekeypassword",
    "keypassword",
    "password",
    "secret",
    "credential",
    "tokensecret",
    "apisecret",
    "rawsecret",
    "rawprivatekey",
    "rawkey",
    "pemprivatekey",
  ];

  walkKeys(value, (key) => {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    for (const fragment of forbiddenFragments) {
      expect(
        normalized.includes(fragment),
        `${key} looks like private-key custody`,
      ).to.equal(false);
    }
  });
}

function expectNoSensitiveValues(value, extraForbidden = []) {
  const serialized = JSON.stringify(value);
  expect(serialized).to.not.include("Authorization");
  expect(serialized).to.not.include("token_hash");
  expect(serialized).to.not.include("ttx_");
  expect(serialized).to.not.include("PRIVATE KEY");
  expect(serialized).to.not.include("password=swordfish");
  for (const forbidden of extraForbidden) {
    expect(serialized).to.not.include(forbidden);
  }
  expectNoPrivateKeyFields(value);
}

async function createWorkspaceFixture() {
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
  await TestUtils.execQuery(
    `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
     VALUES ($1, $2, 'workspace_manager', $3)
     ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = EXCLUDED.role`,
    [managerUser.id, workspaceId, ownerUser.id],
  );

  const viewerUser = await TestUtils.createVerifiedTestUser();
  const viewerSession = await TestUtils.loginTestUser(
    viewerUser.email,
    "SecureTest123!@#",
  );
  await TestUtils.execQuery(
    `INSERT INTO workspace_memberships (user_id, workspace_id, role, invited_by)
     VALUES ($1, $2, 'viewer', $3)
     ON CONFLICT (user_id, workspace_id) DO UPDATE SET role = EXCLUDED.role`,
    [viewerUser.id, workspaceId, ownerUser.id],
  );

  const outsiderUser = await TestUtils.createVerifiedTestUser();
  const outsiderSession = await TestUtils.loginTestUser(
    outsiderUser.email,
    "SecureTest123!@#",
  );
  const outsiderWorkspaceId = await primaryWorkspaceId(outsiderSession);

  return {
    managerSession,
    managerUser,
    outsiderSession,
    outsiderUser,
    outsiderWorkspaceId,
    ownerSession,
    ownerUser,
    viewerSession,
    viewerUser,
    workspaceId,
  };
}

async function cleanupWorkspaceFixture(fixture) {
  if (!fixture) return;
  const workspaceIds = [
    fixture.workspaceId,
    fixture.outsiderWorkspaceId,
  ].filter(Boolean);
  if (workspaceIds.length > 0) {
    await TestUtils.execQuery(
      "DELETE FROM audit_events WHERE workspace_id = ANY($1::uuid[])",
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

async function jobCreatedAuditEvents(workspaceId, subjectId) {
  // audit_events.target_id is an INTEGER column; writeAudit stores NULL for
  // the certificate job's UUID id, so manual-create audits must be located
  // by the subjectId recorded in metadata instead of target_id.
  const result = await TestUtils.execQuery(
    `SELECT actor_user_id,
            subject_user_id,
            target_type,
            target_id,
            workspace_id,
            metadata
       FROM audit_events
      WHERE workspace_id = $1
        AND action = 'CERTOPS_JOB_CREATED_MANUAL'
        AND metadata->>'subjectId' = $2
      ORDER BY id ASC`,
    [workspaceId, subjectId],
  );
  return result.rows;
}

describe("CertOps manual job creation API", function () {
  this.timeout(60000);

  let fixture;

  before(async () => {
    await runMigrations();
    fixture = await createWorkspaceFixture();
  });

  after(async () => {
    await cleanupWorkspaceFixture(fixture);
  });

  it("requires authentication, workspace membership, and manager role", async () => {
    const unauthenticated = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .send({ operation: "deploy" });
    expect(unauthenticated.status).to.be.oneOf([401, 403]);
    expect(unauthenticated.status).to.not.equal(500);
    expectNoSensitiveValues(unauthenticated.body);

    const outsider = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.outsiderSession.cookie)
      .send({ operation: "deploy" });
    expect(outsider.status).to.equal(403);
    expectNoSensitiveValues(outsider.body);

    const viewerDenied = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.viewerSession.cookie)
      .send({ operation: "deploy" });
    expect(viewerDenied.status).to.equal(403);
    expect(viewerDenied.body.code).to.equal("INSUFFICIENT_ROLE");
    expectNoSensitiveValues(viewerDenied.body);

    const countAfterDenials = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS count FROM certificate_jobs WHERE workspace_id = $1",
      [fixture.workspaceId],
    );
    expect(countAfterDenials.rows[0].count).to.equal(0);
  });

  it("creates a job for managers, forces source to api, and writes an audit event", async () => {
    const response = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({
        operation: "deploy",
        subjectType: "managed_certificate",
        subjectId: "cert-manual-1",
        payload: { target: "kubernetes/default/manual-cert" },
        // A caller-supplied source must never override the server-forced value.
        source: "executor",
      })
      .expect(201);

    expect(response.body.job).to.include({
      workspaceId: fixture.workspaceId,
      operation: "deploy",
      status: "pending",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: "cert-manual-1",
      requestedByUserId: fixture.managerUser.id,
    });
    expect(response.body.job.payload).to.include({
      target: "kubernetes/default/manual-cert",
    });
    expectNoSensitiveValues(response.body);

    const persisted = await TestUtils.execQuery(
      "SELECT source, requested_by_user_id FROM certificate_jobs WHERE id = $1",
      [response.body.job.id],
    );
    expect(persisted.rows[0].source).to.equal("api");
    expect(persisted.rows[0].requested_by_user_id).to.equal(
      fixture.managerUser.id,
    );

    const audits = await jobCreatedAuditEvents(
      fixture.workspaceId,
      "cert-manual-1",
    );
    expect(audits).to.have.length(1);
    expect(audits[0]).to.include({
      actor_user_id: fixture.managerUser.id,
      subject_user_id: fixture.managerUser.id,
      target_type: "certificate_job",
      workspace_id: fixture.workspaceId,
    });
    expect(audits[0].metadata).to.deep.include({
      operation: "deploy",
      subjectType: "managed_certificate",
      subjectId: "cert-manual-1",
      source: "api",
    });
  });

  it("allows a bare operation with no subject", async () => {
    const response = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.ownerSession.cookie)
      .send({ operation: "noop" })
      .expect(201);

    expect(response.body.job).to.include({
      operation: "noop",
      source: "api",
      subjectType: null,
      subjectId: null,
    });
    expectNoSensitiveValues(response.body);
  });

  it("rejects invalid operations and subject combinations without creating a job", async () => {
    const countBefore = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS count FROM certificate_jobs WHERE workspace_id = $1",
      [fixture.workspaceId],
    );

    const missingOperation = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({});
    expect(missingOperation.status).to.equal(400);
    expect(missingOperation.body.code).to.equal("CERTOPS_JOB_OPERATION_INVALID");
    expectNoSensitiveValues(missingOperation.body);

    const invalidOperation = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({ operation: "delete-everything" });
    expect(invalidOperation.status).to.equal(400);
    expect(invalidOperation.body.code).to.equal("CERTOPS_JOB_OPERATION_INVALID");
    expectNoSensitiveValues(invalidOperation.body, ["delete-everything"]);

    const subjectIdWithoutType = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({ operation: "deploy", subjectId: "cert-orphan" });
    expect(subjectIdWithoutType.status).to.equal(400);
    expect(subjectIdWithoutType.body.code).to.equal("CERTOPS_JOB_INVALID");
    expectNoSensitiveValues(subjectIdWithoutType.body, ["cert-orphan"]);

    const invalidSubjectType = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({
        operation: "deploy",
        subjectType: "not-a-subject-type",
        subjectId: "cert-1",
      });
    expect(invalidSubjectType.status).to.equal(400);
    expect(invalidSubjectType.body.code).to.equal("CERTOPS_JOB_INVALID");
    expectNoSensitiveValues(invalidSubjectType.body, ["not-a-subject-type"]);

    const countAfter = await TestUtils.execQuery(
      "SELECT COUNT(*)::int AS count FROM certificate_jobs WHERE workspace_id = $1",
      [fixture.workspaceId],
    );
    expect(countAfter.rows[0].count).to.equal(countBefore.rows[0].count);
  });

  it("rejects private-key material before the rollout gate or manager check run", async () => {
    const rejected = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({
        operation: "deploy",
        payload: {
          note: "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----",
        },
      });
    expect(rejected.status).to.equal(422);
    expect(rejected.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
    expectNoSensitiveValues(rejected.body);

    // A viewer must also be blocked by key-material rejection before the
    // 403 role check ever runs, matching the token-route hardening pattern.
    const viewerRejected = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.viewerSession.cookie)
      .send({
        operation: "deploy",
        payload: {
          note: "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----",
        },
      });
    expect(viewerRejected.status).to.equal(422);
    expect(viewerRejected.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
    expectNoSensitiveValues(viewerRejected.body);
  });

  it("replays a lifecycle-advanced job without duplicating its creation audit", async () => {
    const idempotencyKey = `manual-job-${Date.now()}`;
    const subjectId = `idempotency-${crypto.randomUUID()}`;
    const requestBody = {
      operation: "renew",
      subjectType: "domain",
      subjectId,
      idempotencyKey,
      payload: { request: { source: "manual" } },
    };
    const first = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send(requestBody)
      .expect(201);
    expect(await jobCreatedAuditEvents(fixture.workspaceId, subjectId)).to.have.length(1);

    const running = await updateCertificateJobStatus({
      workspaceId: fixture.workspaceId,
      jobId: first.body.job.id,
      status: "running",
      resultMetadata: { phase: "validated" },
    });
    expect(running.status).to.equal("running");

    const replay = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send(requestBody)
      .expect(201);
    expect(replay.body.job.id).to.equal(first.body.job.id);
    expect(replay.body.job.status).to.equal("running");
    expect(replay.body.job.resultMetadata).to.deep.equal({ phase: "validated" });

    const jobs = await TestUtils.execQuery(
      `SELECT id
         FROM certificate_jobs
        WHERE workspace_id = $1
          AND idempotency_key = $2`,
      [fixture.workspaceId, idempotencyKey],
    );
    expect(jobs.rows).to.have.length(1);
    expect(await jobCreatedAuditEvents(fixture.workspaceId, subjectId)).to.have.length(1);

    const conflicting = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({
        operation: "revoke",
        subjectType: "domain",
        subjectId,
        idempotencyKey,
        payload: { request: { source: "manual" } },
      });
    expect(conflicting.status).to.equal(409);
    expect(conflicting.body.code).to.equal("CERTOPS_JOB_IDEMPOTENCY_CONFLICT");
    expectNoSensitiveValues(conflicting.body);

    const auditsForFirstJob = await jobCreatedAuditEvents(
      fixture.workspaceId,
      subjectId,
    );
    // The creation audit is written only for the newly inserted job. A replay
    // returns the current job, while a conflicting key reuse writes nothing.
    expect(auditsForFirstJob).to.have.length(1);
    expect(auditsForFirstJob.every((row) => row.target_id === null)).to.equal(
      true,
    );
  });

  it("scopes created jobs to the requesting workspace only", async () => {
    const response = await request(BASE)
      .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.managerSession.cookie)
      .send({ operation: "reload" })
      .expect(201);

    const crossWorkspaceFetch = await request(BASE)
      .get(
        `/api/v1/workspaces/${fixture.outsiderWorkspaceId}/certops/jobs/${response.body.job.id}`,
      )
      .set("Cookie", fixture.outsiderSession.cookie);
    expect(crossWorkspaceFetch.status).to.equal(404);
    expect(crossWorkspaceFetch.body.code).to.equal("CERTOPS_JOB_NOT_FOUND");

    const sameWorkspaceFetch = await request(BASE)
      .get(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/jobs/${response.body.job.id}`,
      )
      .set("Cookie", fixture.viewerSession.cookie)
      .expect(200);
    expect(sameWorkspaceFetch.body.job.id).to.equal(response.body.job.id);
  });
});
