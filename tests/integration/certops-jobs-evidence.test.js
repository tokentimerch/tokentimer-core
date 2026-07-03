const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations, migrations } = requireMigrateModule();
const {
  PRIVATE_KEY_MATERIAL_REJECTED,
  appendCertificateJobLog,
  createCertificateJob,
  getCertificateJobById,
  listCertificateJobLog,
  listCertificateJobs,
  updateCertificateJobStatus,
} = require("../../apps/api/services/certops/jobs");
const {
  createCertificateEvidence,
  getCertificateEvidenceById,
  listCertificateEvidence,
} = require("../../apps/api/services/certops/evidence");

const JOBS_EVIDENCE_MIGRATION = migrations.find(
  (migration) => migration.name === "certops_jobs_evidence_schema",
);
const CERTOPS_JOB_TABLES = [
  "certificate_jobs",
  "certificate_job_log",
  "certificate_evidence",
];
const PRIVATE_KEY_PEM =
  "-----BEGIN RSA PRIVATE KEY-----\nRkFLRS1OT1QtQS1SRUFMLUtFWQ==\n-----END RSA PRIVATE KEY-----";

async function createWorkspacePair(label) {
  const ownerEmail = `${label}-${Date.now()}-${crypto.randomUUID()}@example.com`;
  const owner = await TestUtils.execQuery(
    `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
     VALUES ($1, $2, $3, $4, 'local', TRUE)
     RETURNING id`,
    [
      ownerEmail.toLowerCase(),
      ownerEmail,
      label,
      "not-used-in-certops-jobs-test",
    ],
  );
  const ownerId = owner.rows[0].id;
  const workspaceA = crypto.randomUUID();
  const workspaceB = crypto.randomUUID();

  await TestUtils.execQuery(
    `INSERT INTO workspaces (id, name, created_by, plan)
     VALUES ($1, $2, $3, 'oss'), ($4, $5, $3, 'oss')`,
    [
      workspaceA,
      `${label} A`,
      ownerId,
      workspaceB,
      `${label} B`,
    ],
  );

  return { ownerId, workspaceA, workspaceB };
}

async function cleanupWorkspacePair(ownerId, workspaceIds) {
  await TestUtils.execQuery("DELETE FROM workspaces WHERE id = ANY($1::uuid[])", [
    workspaceIds,
  ]);
  await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
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
  expect(JSON.stringify(value)).to.not.include("PRIVATE KEY");
}

describe("CertOps jobs and evidence persistence", function () {
  this.timeout(60000);

  before(async () => {
    expect(JOBS_EVIDENCE_MIGRATION).to.exist;
    await runMigrations();
    await TestUtils.execQuery(JOBS_EVIDENCE_MIGRATION.sql);
  });

  it("creates the job, log, and evidence tables with safe columns and indexes", async () => {
    const tables = await TestUtils.execQuery(
      `SELECT table_name
         FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = ANY($1::text[])
        ORDER BY table_name`,
      [CERTOPS_JOB_TABLES],
    );
    expect(tables.rows.map((row) => row.table_name).sort()).to.deep.equal(
      CERTOPS_JOB_TABLES.slice().sort(),
    );

    const columns = await TestUtils.execQuery(
      `SELECT table_name, column_name
         FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = ANY($1::text[])
        ORDER BY table_name, ordinal_position`,
      [CERTOPS_JOB_TABLES],
    );
    const byTable = columns.rows.reduce((acc, row) => {
      acc[row.table_name] ||= [];
      acc[row.table_name].push(row.column_name);
      return acc;
    }, {});

    expect(byTable.certificate_jobs).to.include.members([
      "id",
      "workspace_id",
      "operation",
      "status",
      "source",
      "requested_by_user_id",
      "requested_by_api_token_id",
      "idempotency_key",
      "payload",
      "result_metadata",
      "created_at",
      "updated_at",
    ]);
    expect(byTable.certificate_job_log).to.include.members([
      "id",
      "workspace_id",
      "job_id",
      "event_type",
      "status",
      "metadata",
      "created_at",
    ]);
    expect(byTable.certificate_evidence).to.include.members([
      "id",
      "workspace_id",
      "job_id",
      "evidence_type",
      "metadata",
      "observed_at",
      "created_at",
    ]);

    const forbiddenFragments = [
      "private",
      "key_material",
      "key_pem",
      "raw_key",
      "pfx",
      "jks",
      "password",
      "credential",
      "secret",
    ];
    for (const row of columns.rows) {
      const hit = forbiddenFragments.find((fragment) =>
        row.column_name.includes(fragment),
      );
      expect(
        hit,
        `${row.table_name}.${row.column_name} looks like custody`,
      ).to.equal(undefined);
    }

    const indexes = await TestUtils.execQuery(
      `SELECT tablename, indexname
         FROM pg_indexes
        WHERE schemaname = 'public'
          AND tablename = ANY($1::text[])`,
      [CERTOPS_JOB_TABLES],
    );
    const indexNames = indexes.rows.map((row) => row.indexname);
    expect(indexNames).to.include.members([
      "idx_certificate_jobs_workspace_created",
      "idx_certificate_jobs_workspace_status_created",
      "uq_certificate_jobs_workspace_idempotency_key",
      "idx_certificate_job_log_workspace_job_created",
      "idx_certificate_evidence_workspace_job_created",
      "idx_certificate_evidence_workspace_subject_created",
    ]);

    const constraints = await TestUtils.execQuery(
      `SELECT conname
         FROM pg_constraint
        WHERE conname = ANY($1::text[])
        ORDER BY conname`,
      [
        [
          "fk_certificate_job_log_job",
          "fk_certificate_evidence_job",
          "fk_certificate_jobs_api_token",
        ],
      ],
    );
    expect(constraints.rows.map((row) => row.conname)).to.include.members([
      "fk_certificate_job_log_job",
      "fk_certificate_evidence_job",
      "fk_certificate_jobs_api_token",
    ]);
  });

  it("roundtrips job, log, and evidence data with workspace isolation", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-jobs-roundtrip",
    );

    try {
      const job = await createCertificateJob({
        workspaceId: workspaceA,
        operation: "deploy",
        source: "api",
        idempotencyKey: "deploy-cert-1",
        subjectType: "managed_certificate",
        subjectId: "cert-1",
        payload: {
          target: "kubernetes/default/web-cert",
          fingerprintSha256:
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
        requestedByUserId: ownerId,
      });
      expect(job.workspaceId).to.equal(workspaceA);
      expect(job.status).to.equal("queued");
      expect(job.payload.target).to.equal("kubernetes/default/web-cert");

      const idempotent = await createCertificateJob({
        workspaceId: workspaceA,
        operation: "deploy",
        source: "api",
        idempotencyKey: "deploy-cert-1",
        subjectType: "managed_certificate",
        subjectId: "cert-1",
        payload: { target: "kubernetes/default/web-cert" },
        requestedByUserId: ownerId,
      });
      expect(idempotent.id).to.equal(job.id);

      const otherWorkspaceJob = await createCertificateJob({
        workspaceId: workspaceB,
        operation: "deploy",
        source: "api",
        idempotencyKey: "deploy-cert-1",
        payload: { target: "kubernetes/default/other-cert" },
        requestedByUserId: ownerId,
      });
      expect(otherWorkspaceJob.id).to.not.equal(job.id);

      const running = await updateCertificateJobStatus({
        workspaceId: workspaceA,
        jobId: job.id,
        status: "running",
        resultMetadata: { executor: "executor-a" },
      });
      expect(running.status).to.equal("running");
      expect(running.startedAt).to.be.a("string");

      const log = await appendCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
        eventType: "job.progress",
        status: "running",
        message: "Deployment started",
        metadata: { step: "deploy", target: "web-cert" },
        createdByUserId: ownerId,
      });
      expect(log.jobId).to.equal(job.id);
      expect(log.metadata.step).to.equal("deploy");

      const evidence = await createCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
        evidenceType: "deployment.checked",
        subjectType: "managed_certificate",
        subjectId: "cert-1",
        metadata: {
          deploymentTarget: "kubernetes/default/web-cert",
          issuerCn: "TokenTimer Test CA",
        },
        observedAt: "2026-06-30T02:00:00.000Z",
        createdByUserId: ownerId,
      });
      expect(evidence.jobId).to.equal(job.id);
      expect(evidence.metadata.deploymentTarget).to.equal(
        "kubernetes/default/web-cert",
      );

      expect(
        await getCertificateJobById({
          workspaceId: workspaceB,
          jobId: job.id,
        }),
      ).to.equal(null);
      expect(
        await getCertificateEvidenceById({
          workspaceId: workspaceB,
          evidenceId: evidence.id,
        }),
      ).to.equal(null);

      const jobsA = await listCertificateJobs({ workspaceId: workspaceA });
      const jobsB = await listCertificateJobs({ workspaceId: workspaceB });
      expect(jobsA.items.map((item) => item.id)).to.include(job.id);
      expect(jobsB.items.map((item) => item.id)).to.not.include(job.id);

      const logs = await listCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(logs.items.map((item) => item.id)).to.include(log.id);

      const evidenceList = await listCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
      });
      expect(evidenceList.items.map((item) => item.id)).to.include(evidence.id);

      expectNoPrivateKeyFields(job);
      expectNoPrivateKeyFields(logs);
      expectNoPrivateKeyFields(evidenceList);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("rejects dangerous payload and evidence metadata before persistence", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-jobs-dangerous",
    );

    try {
      const beforeJobs = await TestUtils.execQuery(
        "SELECT COUNT(*)::int AS count FROM certificate_jobs WHERE workspace_id = $1",
        [workspaceA],
      );
      let jobError;
      try {
        await createCertificateJob({
          workspaceId: workspaceA,
          operation: "renew",
          payload: { nested: { tokenSecret: "not-allowed" } },
          requestedByUserId: ownerId,
        });
      } catch (error) {
        jobError = error;
      }
      expect(jobError?.code).to.equal(PRIVATE_KEY_MATERIAL_REJECTED);
      const afterJobs = await TestUtils.execQuery(
        "SELECT COUNT(*)::int AS count FROM certificate_jobs WHERE workspace_id = $1",
        [workspaceA],
      );
      expect(afterJobs.rows[0].count).to.equal(beforeJobs.rows[0].count);

      const safeJob = await createCertificateJob({
        workspaceId: workspaceA,
        operation: "renew",
        payload: { certificateId: "cert-1" },
        requestedByUserId: ownerId,
      });

      const beforeEvidence = await TestUtils.execQuery(
        "SELECT COUNT(*)::int AS count FROM certificate_evidence WHERE workspace_id = $1",
        [workspaceA],
      );
      let evidenceError;
      try {
        await createCertificateEvidence({
          workspaceId: workspaceA,
          jobId: safeJob.id,
          evidenceType: "certificate.observed",
          metadata: { output: PRIVATE_KEY_PEM },
          createdByUserId: ownerId,
        });
      } catch (error) {
        evidenceError = error;
      }
      expect(evidenceError?.code).to.equal(PRIVATE_KEY_MATERIAL_REJECTED);
      const afterEvidence = await TestUtils.execQuery(
        "SELECT COUNT(*)::int AS count FROM certificate_evidence WHERE workspace_id = $1",
        [workspaceA],
      );
      expect(afterEvidence.rows[0].count).to.equal(
        beforeEvidence.rows[0].count,
      );

      let crossWorkspaceError;
      try {
        await createCertificateEvidence({
          workspaceId: workspaceB,
          jobId: safeJob.id,
          evidenceType: "certificate.observed",
          metadata: {},
        });
      } catch (error) {
        crossWorkspaceError = error;
      }
      expect(crossWorkspaceError?.code).to.equal("CERTOPS_JOB_NOT_FOUND");
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("cascades job logs and detaches evidence when a job is deleted", async () => {
    const { ownerId, workspaceA, workspaceB } = await createWorkspacePair(
      "certops-jobs-delete",
    );

    try {
      const job = await createCertificateJob({
        workspaceId: workspaceA,
        operation: "noop",
        payload: { reason: "deletion-behavior-test" },
        requestedByUserId: ownerId,
      });
      const log = await appendCertificateJobLog({
        workspaceId: workspaceA,
        jobId: job.id,
        eventType: "job.created",
        status: "queued",
        metadata: { reason: "created" },
        createdByUserId: ownerId,
      });
      const evidence = await createCertificateEvidence({
        workspaceId: workspaceA,
        jobId: job.id,
        evidenceType: "policy.checked",
        metadata: { policy: "no-private-key-custody" },
        createdByUserId: ownerId,
      });

      await TestUtils.execQuery(
        "DELETE FROM certificate_jobs WHERE workspace_id = $1 AND id = $2",
        [workspaceA, job.id],
      );

      const logRows = await TestUtils.execQuery(
        "SELECT 1 FROM certificate_job_log WHERE workspace_id = $1 AND id = $2",
        [workspaceA, log.id],
      );
      expect(logRows.rows).to.have.length(0);

      const evidenceRows = await TestUtils.execQuery(
        `SELECT workspace_id::text AS workspace_id, job_id
           FROM certificate_evidence
          WHERE workspace_id = $1
            AND id = $2`,
        [workspaceA, evidence.id],
      );
      expect(evidenceRows.rows).to.have.length(1);
      expect(evidenceRows.rows[0].workspace_id).to.equal(workspaceA);
      expect(evidenceRows.rows[0].job_id).to.equal(null);

      const otherWorkspaceEvidence = await TestUtils.execQuery(
        "SELECT 1 FROM certificate_evidence WHERE workspace_id = $1 AND id = $2",
        [workspaceB, evidence.id],
      );
      expect(otherWorkspaceEvidence.rows).to.have.length(0);
    } finally {
      await cleanupWorkspacePair(ownerId, [workspaceA, workspaceB]);
    }
  });

  it("does not add executor job or evidence route handlers yet", () => {
    const certOpsRoutesSource = fs.readFileSync(
      path.resolve(__dirname, "../../apps/api/routes/certops.js"),
      "utf8",
    );

    expect(certOpsRoutesSource).to.not.include("/api/v1/certops/executor");
    expect(certOpsRoutesSource).to.not.include("certificate_jobs");
    expect(certOpsRoutesSource).to.not.include("certificate_evidence");
  });
});
