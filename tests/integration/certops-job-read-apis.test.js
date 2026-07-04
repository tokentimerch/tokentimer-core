const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, request, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const {
  appendCertificateJobLog,
  createCertificateJob,
} = require("../../apps/api/services/certops/jobs");
const {
  createCertificateEvidence,
} = require("../../apps/api/services/certops/evidence");

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
    ownerUser,
    ownerSession,
    viewerUser,
    viewerSession,
    outsiderUser,
    outsiderSession,
    workspaceId,
    outsiderWorkspaceId,
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
    [fixture.viewerUser, fixture.viewerSession],
    [fixture.outsiderUser, fixture.outsiderSession],
  ]) {
    if (user?.email && session?.cookie) {
      await TestUtils.cleanupTestUser(user.email, session.cookie);
    }
  }
}

async function createJobFixture({ ownerUser, workspaceId, outsiderWorkspaceId }) {
  const deployJob = await createCertificateJob({
    workspaceId,
    operation: "deploy",
    status: "queued",
    source: "api",
    subjectType: "managed_certificate",
    subjectId: "cert-1",
    payload: {
      certificateId: "cert-1",
      target: "kubernetes/default/web-cert",
    },
    resultMetadata: {
      planner: "manual",
    },
    requestedByUserId: ownerUser.id,
  });

  const renewJob = await createCertificateJob({
    workspaceId,
    operation: "renew",
    status: "running",
    source: "executor",
    subjectType: "certificate_target",
    subjectId: "target-1",
    payload: {
      certificateId: "cert-2",
      target: "domain/example.com",
    },
    requestedByUserId: ownerUser.id,
  });

  const otherWorkspaceJob = await createCertificateJob({
    workspaceId: outsiderWorkspaceId,
    operation: "deploy",
    status: "queued",
    source: "api",
    subjectType: "managed_certificate",
    subjectId: "cert-other",
    payload: { certificateId: "cert-other" },
    requestedByUserId: ownerUser.id,
  });

  const deployLog = await appendCertificateJobLog({
    workspaceId,
    jobId: deployJob.id,
    eventType: "job.created",
    status: "queued",
    message: "Job queued for dashboard timeline",
    metadata: { stage: "queued", target: "web-cert" },
    createdByUserId: ownerUser.id,
  });
  await appendCertificateJobLog({
    workspaceId,
    jobId: renewJob.id,
    eventType: "job.progress",
    status: "running",
    message: "Renewal in progress",
    metadata: { stage: "renew" },
    createdByUserId: ownerUser.id,
  });

  const deployEvidence = await createCertificateEvidence({
    workspaceId,
    jobId: deployJob.id,
    evidenceType: "deployment.checked",
    subjectType: "managed_certificate",
    subjectId: "cert-1",
    metadata: {
      deploymentTarget: "kubernetes/default/web-cert",
      artifactRefs: [
        {
          type: "report",
          reference: "reports/certops/public-observation.json",
          sha256:
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
      ],
    },
    observedAt: "2026-07-01T12:00:00.000Z",
    createdByUserId: ownerUser.id,
  });
  await createCertificateEvidence({
    workspaceId,
    jobId: renewJob.id,
    evidenceType: "policy.checked",
    subjectType: "certificate_target",
    subjectId: "target-1",
    metadata: { policy: "public-metadata-only" },
    observedAt: "2026-07-01T12:05:00.000Z",
    createdByUserId: ownerUser.id,
  });

  return {
    deployEvidence,
    deployJob,
    deployLog,
    otherWorkspaceJob,
    renewJob,
  };
}

describe("CertOps job read APIs", function () {
  this.timeout(60000);

  let fixture;
  let jobs;

  before(async () => {
    await runMigrations();
    fixture = await createWorkspaceFixture();
    jobs = await createJobFixture(fixture);
  });

  after(async () => {
    await cleanupWorkspaceFixture(fixture);
  });

  it("requires authentication and workspace membership", async () => {
    const unauthenticated = await request(BASE).get(
      `/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`,
    );
    expect(unauthenticated.status).to.be.oneOf([401, 403]);
    expect(unauthenticated.status).to.not.equal(500);
    expectNoSensitiveValues(unauthenticated.body);

    const forbidden = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.outsiderSession.cookie);
    expect(forbidden.status).to.equal(403);
    expect(forbidden.status).to.not.equal(500);
    expectNoSensitiveValues(forbidden.body);

    const crossWorkspaceDetail = await request(BASE)
      .get(
        `/api/v1/workspaces/${fixture.outsiderWorkspaceId}/certops/jobs/${jobs.deployJob.id}`,
      )
      .set("Cookie", fixture.outsiderSession.cookie);
    expect(crossWorkspaceDetail.status).to.equal(404);
    expect(crossWorkspaceDetail.body.code).to.equal("CERTOPS_JOB_NOT_FOUND");
    expectNoSensitiveValues(crossWorkspaceDetail.body);
  });

  it("lists workspace jobs with pagination and safe filters", async () => {
    const list = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
      .set("Cookie", fixture.viewerSession.cookie)
      .expect(200);

    const ids = list.body.items.map((item) => item.id);
    expect(ids).to.include(jobs.deployJob.id);
    expect(ids).to.include(jobs.renewJob.id);
    expect(ids).to.not.include(jobs.otherWorkspaceJob.id);
    expect(list.body.items[0]).to.not.have.property("payload");
    expect(list.body.items[0]).to.not.have.property("resultMetadata");
    expectNoSensitiveValues(list.body);

    const firstPage = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs?limit=1&offset=0`)
      .set("Cookie", fixture.viewerSession.cookie)
      .expect(200);
    expect(firstPage.body.items).to.have.length(1);
    expect(firstPage.body.pagination).to.deep.equal({ limit: 1, offset: 0 });

    const statusFiltered = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs?status=queued`)
      .set("Cookie", fixture.viewerSession.cookie)
      .expect(200);
    expect(statusFiltered.body.items.map((item) => item.id)).to.include(
      jobs.deployJob.id,
    );
    expect(statusFiltered.body.items.map((item) => item.id)).to.not.include(
      jobs.renewJob.id,
    );

    const subjectFiltered = await request(BASE)
      .get(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/jobs?subjectType=certificate_target&subjectId=target-1`,
      )
      .set("Cookie", fixture.viewerSession.cookie)
      .expect(200);
    expect(subjectFiltered.body.items.map((item) => item.id)).to.deep.equal([
      jobs.renewJob.id,
    ]);

    const operationFiltered = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs?operation=deploy&source=api`)
      .set("Cookie", fixture.viewerSession.cookie)
      .send({ workspaceId: fixture.outsiderWorkspaceId })
      .expect(200);
    expect(operationFiltered.body.items.map((item) => item.id)).to.include(
      jobs.deployJob.id,
    );
    expect(operationFiltered.body.items.map((item) => item.id)).to.not.include(
      jobs.otherWorkspaceJob.id,
    );
    expectNoSensitiveValues(operationFiltered.body);
  });

  it("gets one sanitized job detail", async () => {
    const response = await request(BASE)
      .get(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/jobs/${jobs.deployJob.id}`,
      )
      .set("Cookie", fixture.ownerSession.cookie)
      .expect(200);

    expect(response.body.job).to.include({
      id: jobs.deployJob.id,
      workspaceId: fixture.workspaceId,
      operation: "deploy",
      status: "queued",
      source: "api",
      subjectType: "managed_certificate",
      subjectId: "cert-1",
    });
    expect(response.body.job.payload).to.include({
      certificateId: "cert-1",
      target: "kubernetes/default/web-cert",
    });
    expect(response.body.job.resultMetadata).to.include({ planner: "manual" });
    expectNoSensitiveValues(response.body);
  });

  it("returns job log and evidence scoped to the requested workspace job", async () => {
    const log = await request(BASE)
      .get(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/jobs/${jobs.deployJob.id}/log`,
      )
      .set("Cookie", fixture.viewerSession.cookie)
      .expect(200);
    expect(log.body.items.map((item) => item.id)).to.include(jobs.deployLog.id);
    expect(log.body.items.every((item) => item.jobId === jobs.deployJob.id)).to.equal(
      true,
    );
    expect(log.body.items.map((item) => item.eventType)).to.include(
      "job.created",
    );
    expectNoSensitiveValues(log.body);

    const evidence = await request(BASE)
      .get(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/jobs/${jobs.deployJob.id}/evidence`,
      )
      .set("Cookie", fixture.viewerSession.cookie)
      .expect(200);
    expect(evidence.body.items.map((item) => item.id)).to.include(
      jobs.deployEvidence.id,
    );
    expect(
      evidence.body.items.every((item) => item.jobId === jobs.deployJob.id),
    ).to.equal(true);
    expect(evidence.body.items[0].metadata.artifactRefs[0]).to.include({
      type: "report",
      reference: "reports/certops/public-observation.json",
    });
    expectNoSensitiveValues(evidence.body);

    for (const suffix of ["log", "evidence"]) {
      const crossWorkspace = await request(BASE)
        .get(
          `/api/v1/workspaces/${fixture.outsiderWorkspaceId}/certops/jobs/${jobs.deployJob.id}/${suffix}`,
        )
        .set("Cookie", fixture.outsiderSession.cookie);
      expect(crossWorkspace.status).to.equal(404);
      expect(crossWorkspace.body.code).to.equal("CERTOPS_JOB_NOT_FOUND");
      expectNoSensitiveValues(crossWorkspace.body);
    }
  });

  it("handles missing, malformed, and unsafe inputs without internal errors", async () => {
    const missingJobId = crypto.randomUUID();
    const missing = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs/${missingJobId}`)
      .set("Cookie", fixture.ownerSession.cookie);
    expect(missing.status).to.equal(404);
    expect(missing.body.code).to.equal("CERTOPS_JOB_NOT_FOUND");
    expectNoSensitiveValues(missing.body);

    for (const suffix of ["", "/log", "/evidence"]) {
      const malformed = await request(BASE)
        .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs/not-a-uuid${suffix}`)
        .set("Cookie", fixture.ownerSession.cookie);
      expect(malformed.status).to.equal(400);
      expect(malformed.status).to.not.equal(500);
      expect(malformed.body.code).to.equal("CERTOPS_JOB_INVALID");
      expectNoSensitiveValues(malformed.body, ["not-a-uuid"]);
    }

    const malformedWorkspace = await request(BASE)
      .get(`/api/v1/workspaces/not-a-uuid/certops/jobs`)
      .set("Cookie", fixture.ownerSession.cookie);
    expect(malformedWorkspace.status).to.equal(400);
    expect(malformedWorkspace.status).to.not.equal(500);
    expect(malformedWorkspace.body.code).to.equal("INVALID_WORKSPACE_ID");
    expectNoSensitiveValues(malformedWorkspace.body, ["not-a-uuid"]);

    const invalidStatus = await request(BASE)
      .get(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs?status=deleted`)
      .set("Cookie", fixture.ownerSession.cookie);
    expect(invalidStatus.status).to.equal(400);
    expect(invalidStatus.body.code).to.equal("CERTOPS_JOB_STATUS_INVALID");
    expectNoSensitiveValues(invalidStatus.body, ["deleted"]);

    const unsafeSubject = await request(BASE)
      .get(
        `/api/v1/workspaces/${fixture.workspaceId}/certops/jobs?subjectId=password%3Dswordfish`,
      )
      .set("Cookie", fixture.ownerSession.cookie);
    expect(unsafeSubject.status).to.equal(422);
    expect(unsafeSubject.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
    expectNoSensitiveValues(unsafeSubject.body, ["password=swordfish"]);
  });
});
