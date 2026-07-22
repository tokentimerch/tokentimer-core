const crypto = require("crypto");
const { createRequire } = require("module");
const supertest = require("supertest");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations, migrations } = requireMigrateModule();
const { pool } = require("../../apps/api/db/database");
const {
  CERTOPS_API_TOKEN_CONTROLLER_CLUSTER_INVALID,
  createApiToken,
  getApiTokenById,
  revokeApiTokenWithResult,
} = require("../../apps/api/services/certops/apiTokens");
const certOpsExecutorRoutes = require("../../apps/api/routes/certops-executor");
const {
  createCertOpsExecutorRouter,
  _test: {
    executorEventIdempotencyPayload,
    normalizeExecutorEventBody,
  },
} = certOpsExecutorRoutes;
const certOpsRouter = require("../../apps/api/routes/certops");
const {
  createCertificateJob,
} = require("../../apps/api/services/certops/jobs");
const {
  _test: { requestHash },
} = require("../../apps/api/services/certops/executorEvents");
const {
  takeNextControllerProvisioningCommand,
} = require("../../apps/api/services/certops/controllerProvisioning");

const apiRequire = createRequire(require.resolve("../../apps/api/package.json"));
const express = apiRequire("express");

const PROVISION_ROUTE = "/api/v1/certops/executor/provisioning-commands/next";
const OBSERVATION_ROUTE = "/api/v1/certops/executor/observations";

function fixtureEmail(label) {
  return `${label}-${crypto.randomUUID()}@example.test`;
}

async function createWorkspace(label) {
  const email = fixtureEmail(label);
  const user = await TestUtils.execQuery(
    `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
     VALUES ($1, $2, $3, $4, 'local', TRUE)
     RETURNING id`,
    [email.toLowerCase(), email, label, "not-used"],
  );
  const workspaceId = crypto.randomUUID();
  await TestUtils.execQuery(
    "INSERT INTO workspaces (id, name, created_by, plan) VALUES ($1, $2, $3, 'oss')",
    [workspaceId, label, user.rows[0].id],
  );
  return { ownerId: user.rows[0].id, workspaceId };
}

async function cleanupWorkspace({ ownerId, workspaceId }) {
  if (workspaceId) {
    await TestUtils.execQuery("DELETE FROM audit_events WHERE workspace_id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM certificate_executor_events WHERE workspace_id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM certificate_evidence WHERE workspace_id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM certificate_job_log WHERE workspace_id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM certificate_controller_observations WHERE workspace_id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM certificate_controller_provision_deliveries WHERE workspace_id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM certificate_jobs WHERE workspace_id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM certificate_instances WHERE workspace_id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM certificate_targets WHERE workspace_id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM managed_certificates WHERE workspace_id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM api_tokens WHERE workspace_id = $1", [workspaceId]);
    await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
  }
  if (ownerId) {
    await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
  }
}

function provisionRequest(overrides = {}) {
  return {
    schemaVersion: 1,
    clusterId: "cluster-a",
    namespace: "certops",
    certificateName: "example-com",
    secretName: "example-com-tls",
    issuerRef: {
      group: "cert-manager.io",
      kind: "ClusterIssuer",
      name: "public-issuer",
    },
    dnsNames: ["example.com", "www.example.com"],
    ...overrides,
  };
}

function observationPayload(workspaceId, overrides = {}) {
  return {
    schemaVersion: 1,
    observationId: crypto.randomUUID(),
    idempotencyKey: crypto.randomBytes(32).toString("hex"),
    workspaceId,
    clusterId: "cluster-a",
    namespace: "certops",
    certificateName: "paused-observation",
    certificateUid: crypto.randomUUID(),
    certificateGeneration: 1,
    resourceVersion: "1",
    issuerRef: { name: "public-issuer" },
    secretName: "paused-observation-tls",
    certificateRequestRef: null,
    dnsNames: ["example.com"],
    conditions: [{ type: "Ready", status: "True" }],
    ready: true,
    publicCertificate: { fingerprintSha256: "a".repeat(64) },
    observationSource: "cert_manager",
    observedAt: "2026-07-21T10:00:00.000Z",
    ...overrides,
  };
}

function executorEventPayload(workspaceId, jobId, overrides = {}) {
  return {
    schemaVersion: 1,
    eventId: `event-${crypto.randomUUID()}`,
    workspaceId,
    jobId,
    eventType: "job.progress",
    status: "running",
    occurredAt: new Date().toISOString(),
    message: "The controller is still reporting public status",
    ...overrides,
  };
}

function createHumanProvisioningApp(ownerId, {
  userId = ownerId,
  workspaceRole = "workspace_manager",
  isWorkerCall = false,
} = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    const match = /^\/api\/v1\/workspaces\/([^/]+)\/certops(?:\/|$)/.exec(req.path);
    if (match) {
      req.workspace = { id: match[1] };
      if (userId) req.user = { id: userId };
      req.authz = { workspaceRole };
      if (isWorkerCall) req.isWorkerCall = true;
    }
    next();
  });
  app.use(certOpsRouter);
  return app;
}

function createControllerExecutorApp(options = {}) {
  const app = express();
  app.use(express.json());
  app.use(
    createCertOpsExecutorRouter({
      rateLimitOptions: { windowMs: 60_000, max: 10_000 },
      ...options,
    }),
  );
  return app;
}

function postProvisionIntent(app, workspaceId, idempotencyKey, body) {
  return supertest(app)
    .post(`/api/v1/workspaces/${workspaceId}/certops/provision-intents`)
    .set("Idempotency-Key", idempotencyKey)
    .send(body);
}

function commandRequest(app, token) {
  return supertest(app)
    .post(PROVISION_ROUTE)
    .set("Authorization", `Bearer ${token}`)
    .send({});
}

function mutationAuthorizationRequest(app, token, jobId) {
  return supertest(app)
    .post(`/api/v1/certops/executor/provisioning-commands/${jobId}/authorize-mutation`)
    .set("Authorization", `Bearer ${token}`)
    .send({});
}

async function provisioningCounts(workspaceId) {
  const result = await TestUtils.execQuery(
    `SELECT
       (SELECT COUNT(*)::int FROM managed_certificates
         WHERE workspace_id = $1 AND source = 'cert_manager') AS managed,
       (SELECT COUNT(*)::int FROM certificate_targets
         WHERE workspace_id = $1 AND source = 'cert_manager') AS targets,
       (SELECT COUNT(*)::int FROM certificate_jobs
         WHERE workspace_id = $1 AND payload->>'kind' = 'cert_manager_provision') AS jobs,
       (SELECT COUNT(*)::int FROM certificate_jobs
         WHERE workspace_id = $1 AND idempotency_key IS NOT NULL) AS idempotency,
       (SELECT COUNT(*)::int FROM audit_events
         WHERE workspace_id = $1
           AND action = 'CERTOPS_CONTROLLER_PROVISION_INTENT_CREATED') AS audits,
       (SELECT COUNT(*)::int FROM certificate_controller_provision_deliveries
         WHERE workspace_id = $1) AS deliveries`,
    [workspaceId],
  );
  return result.rows[0];
}

async function createControllerToken({ workspaceId, ownerId, clusterId = "cluster-a", scopes = ["certops:provision:execute"] }) {
  return createApiToken({
    workspaceId,
    name: `Controller ${clusterId}`,
    scopes,
    controllerClusterId: clusterId,
    createdBy: ownerId,
  });
}

describe("CertOps controller provisioning", function () {
  this.timeout(60_000);

  let previousCertOpsEnabled;

  before(async () => {
    previousCertOpsEnabled = process.env.CERTOPS_ENABLED;
    process.env.CERTOPS_ENABLED = "true";
    await runMigrations();
  });

  after(() => {
    if (previousCertOpsEnabled === undefined) delete process.env.CERTOPS_ENABLED;
    else process.env.CERTOPS_ENABLED = previousCertOpsEnabled;
  });

  it("upgrades the migration-21 token shape to migration 22 and accepts the provision scope", async () => {
    const migration = migrations.find((item) => item.version === 22);
    expect(migration?.name).to.equal("certops_controller_provisioning");

    const schema = `provisioning_upgrade_${crypto.randomUUID().replaceAll("-", "")}`;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`CREATE SCHEMA ${schema}`);
      await client.query(`SET LOCAL search_path TO ${schema}, public`);
      await client.query(`
        CREATE TABLE workspaces (id UUID PRIMARY KEY);
        CREATE TABLE certificate_jobs (id UUID PRIMARY KEY);
        CREATE TABLE api_tokens (
          id UUID PRIMARY KEY,
          scopes TEXT[] NOT NULL,
          controller_cluster_id TEXT NULL,
          CONSTRAINT api_tokens_scopes_check CHECK (
            COALESCE(array_length(scopes, 1), 0) BETWEEN 1 AND 8 AND
            scopes <@ ARRAY[
              'certops:read',
              'certops:events:write',
              'certops:jobs:read',
              'certops:evidence:write',
              'certops:observations:write'
            ]::text[] AND
            ((scopes @> ARRAY['certops:observations:write']::text[]) =
              (controller_cluster_id IS NOT NULL))
          )
        );
      `);

      await client.query(migration.sql);
      await client.query(
        "INSERT INTO api_tokens (id, scopes, controller_cluster_id) VALUES ($1, $2, $3)",
        [crypto.randomUUID(), ["certops:provision:execute"], "cluster-a"],
      );

      let missingBinding;
      await client.query("SAVEPOINT missing_provision_binding");
      try {
        await client.query(
          "INSERT INTO api_tokens (id, scopes, controller_cluster_id) VALUES ($1, $2, NULL)",
          [crypto.randomUUID(), ["certops:provision:execute"]],
        );
      } catch (error) {
        missingBinding = error;
      }
      expect(missingBinding?.code).to.equal("23514");
      await client.query("ROLLBACK TO SAVEPOINT missing_provision_binding");

      let unexpectedBinding;
      await client.query("SAVEPOINT unexpected_provision_binding");
      try {
        await client.query(
          "INSERT INTO api_tokens (id, scopes, controller_cluster_id) VALUES ($1, $2, $3)",
          [crypto.randomUUID(), ["certops:events:write"], "cluster-a"],
        );
      } catch (error) {
        unexpectedBinding = error;
      }
      expect(unexpectedBinding?.code).to.equal("23514");
      await client.query("ROLLBACK TO SAVEPOINT unexpected_provision_binding");
    } finally {
      await client.query("ROLLBACK");
      client.release();
    }
  });

  it("upgrades the earlier controller delivery shape from migration 22 to 23", async () => {
    const migration = migrations.find((item) => item.version === 23);
    expect(migration?.name).to.equal("certops_controller_provisioning_event_timestamps");
    const schema = `provisioning_delivery_${crypto.randomUUID().replaceAll("-", "")}`;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`CREATE SCHEMA ${schema}`);
      await client.query(`SET LOCAL search_path TO ${schema}, public`);
      await client.query(`
        CREATE TABLE certificate_jobs (
          id UUID PRIMARY KEY,
          source TEXT NOT NULL CHECK (source IN ('api', 'executor', 'system', 'automation', 'domain-monitor', 'endpoint-monitor', 'control-plane', 'external'))
        );
        CREATE TABLE certificate_controller_provision_deliveries (
          job_id UUID PRIMARY KEY,
          workspace_id UUID NOT NULL,
          controller_cluster_id TEXT NOT NULL,
          delivered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);
      await client.query(migration.sql);
      await client.query(
        "INSERT INTO certificate_jobs (id, source) VALUES ($1, 'controller_provisioning')",
        [crypto.randomUUID()],
      );
      const columns = await client.query(
        `SELECT column_name FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = 'certificate_controller_provision_deliveries'
          ORDER BY column_name`,
        [schema],
      );
      expect(columns.rows.map((row) => row.column_name)).to.include.members([
        "started_at", "completed_at", "failed_at",
      ]);
    } finally {
      await client.query("ROLLBACK");
      client.release();
    }
  });

  it("requires and preserves the immutable controller cluster binding for provisioning tokens", async () => {
    const fixture = await createWorkspace("controller-provisioning-token");
    try {
      let missingBinding;
      try {
        await createApiToken({
          workspaceId: fixture.workspaceId,
          name: "Missing provision cluster",
          scopes: ["certops:provision:execute"],
          createdBy: fixture.ownerId,
        });
      } catch (error) {
        missingBinding = error;
      }
      expect(missingBinding?.code).to.equal(CERTOPS_API_TOKEN_CONTROLLER_CLUSTER_INVALID);

      const token = await createControllerToken(fixture);
      expect(token.token.scopes).to.deep.equal(["certops:provision:execute"]);
      expect(token.token.controllerClusterId).to.equal("cluster-a");
      const revoked = await revokeApiTokenWithResult({
        workspaceId: fixture.workspaceId,
        tokenId: token.token.id,
        revokedBy: fixture.ownerId,
      });
      expect(revoked.token.controllerClusterId).to.equal("cluster-a");
      const persisted = await getApiTokenById({
        workspaceId: fixture.workspaceId,
        tokenId: token.token.id,
      });
      expect(persisted.controllerClusterId).to.equal("cluster-a");
    } finally {
      await cleanupWorkspace(fixture);
    }
  });

  it("creates one source-stable intent atomically, replays it, and rejects a conflicting idempotency key", async () => {
    const fixture = await createWorkspace("controller-provisioning-intent");
    const app = createHumanProvisioningApp(fixture.ownerId);
    try {
      const idempotencyKey = `intent-${crypto.randomUUID()}`;
      const first = await postProvisionIntent(
        app,
        fixture.workspaceId,
        idempotencyKey,
        provisionRequest(),
      ).expect(201);
      expect(first.body).to.include({ duplicate: false });
      expect(first.body.job).to.include({ operation: "deploy", status: "pending" });
      expect(first.body.managedCertificateId).to.be.a("string");
      expect(first.body.targetId).to.be.a("string");

      const replay = await postProvisionIntent(
        app,
        fixture.workspaceId,
        idempotencyKey,
        provisionRequest(),
      ).expect(200);
      expect(replay.body).to.deep.equal({ ...first.body, duplicate: true });

      const conflict = await postProvisionIntent(
        app,
        fixture.workspaceId,
        idempotencyKey,
        provisionRequest({ secretName: "different-tls" }),
      ).expect(409);
      expect(conflict.body.code).to.equal("CERTOPS_JOB_IDEMPOTENCY_CONFLICT");
      expect(await provisioningCounts(fixture.workspaceId)).to.deep.equal({
        managed: 1,
        targets: 1,
        jobs: 1,
        idempotency: 1,
        audits: 1,
        deliveries: 0,
      });
    } finally {
      await cleanupWorkspace(fixture);
    }
  });

  it("requires a human manager session and preserves private-material precedence", async () => {
    const fixture = await createWorkspace("controller-provisioning-session");
    try {
      const manager = createHumanProvisioningApp(fixture.ownerId);
      await postProvisionIntent(manager, fixture.workspaceId, `manager-${crypto.randomUUID()}`, provisionRequest()).expect(201);

      const viewer = createHumanProvisioningApp(fixture.ownerId, { workspaceRole: "viewer" });
      await postProvisionIntent(viewer, fixture.workspaceId, `viewer-${crypto.randomUUID()}`, provisionRequest({ certificateName: "viewer-cert", secretName: "viewer-tls" })).expect(403);
      const worker = createHumanProvisioningApp(fixture.ownerId, { isWorkerCall: true });
      await postProvisionIntent(worker, fixture.workspaceId, `worker-${crypto.randomUUID()}`, provisionRequest({ certificateName: "worker-cert", secretName: "worker-tls" })).expect(403);
      const anonymous = createHumanProvisioningApp(fixture.ownerId, { userId: null });
      await postProvisionIntent(anonymous, fixture.workspaceId, `anonymous-${crypto.randomUUID()}`, provisionRequest({ certificateName: "anonymous-cert", secretName: "anonymous-tls" })).expect(403);

      const previous = process.env.CERTOPS_ENABLED;
      process.env.CERTOPS_ENABLED = "false";
      try {
        const privateBeforeGate = await postProvisionIntent(
          viewer,
          fixture.workspaceId,
          `private-${crypto.randomUUID()}`,
          { ...provisionRequest({ certificateName: "private-cert", secretName: "private-tls" }), privateKey: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----" },
        ).expect(422);
        expect(privateBeforeGate.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");
      } finally {
        if (previous === undefined) delete process.env.CERTOPS_ENABLED;
        else process.env.CERTOPS_ENABLED = previous;
      }
    } finally {
      await cleanupWorkspace(fixture);
    }
  });

  it("preserves observed public certificate state across intent creation and replays", async () => {
    const fixture = await createWorkspace("controller-provisioning-observed-state");
    const app = createHumanProvisioningApp(fixture.ownerId);
    try {
      const firstKey = `observed-first-${crypto.randomUUID()}`;
      const first = await postProvisionIntent(app, fixture.workspaceId, firstKey, provisionRequest()).expect(201);
      const observed = {
        fingerprint: "f".repeat(64),
        spki: "e".repeat(64),
        pem: "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----",
        issuer: "CN=issuer",
        subject: "CN=example.com",
        serial: "01ab",
        algorithm: "RSA",
        signature: "sha256WithRSAEncryption",
        metadata: { controllerObservation: { resourceVersion: "77", certificateUid: crypto.randomUUID() }, retained: true },
      };
      await TestUtils.execQuery(
        `UPDATE managed_certificates
            SET fingerprint_sha256 = $2, spki_fingerprint_sha256 = $3,
                certificate_pem = $4, issuer = $5, subject = $6,
                serial_number = $7, not_before = $8, not_after = $9,
                public_key_algorithm = $10, public_key_size = 2048,
                signature_algorithm = $11, public_metadata = $12::jsonb
          WHERE id = $1`,
        [
          first.body.managedCertificateId, observed.fingerprint, observed.spki,
          observed.pem, observed.issuer, observed.subject, observed.serial,
          "2025-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z",
          observed.algorithm, observed.signature, JSON.stringify(observed.metadata),
        ],
      );
      await postProvisionIntent(app, fixture.workspaceId, firstKey, provisionRequest()).expect(200);
      // Exact replay must never run the planning update differently.
      await postProvisionIntent(app, fixture.workspaceId, `observed-replay-${crypto.randomUUID()}`, provisionRequest()).expect(201);
      const persisted = await TestUtils.execQuery(
        `SELECT fingerprint_sha256, spki_fingerprint_sha256, certificate_pem,
                issuer, subject, serial_number, not_before, not_after,
                public_key_algorithm, public_key_size, signature_algorithm,
                public_metadata
           FROM managed_certificates WHERE id = $1`,
        [first.body.managedCertificateId],
      );
      expect(persisted.rows[0]).to.include({
        fingerprint_sha256: observed.fingerprint,
        spki_fingerprint_sha256: observed.spki,
        certificate_pem: observed.pem,
        issuer: observed.issuer,
        subject: observed.subject,
        serial_number: observed.serial,
        public_key_algorithm: observed.algorithm,
        public_key_size: 2048,
        signature_algorithm: observed.signature,
      });
      expect(persisted.rows[0].public_metadata).to.include({ retained: true });
      expect(persisted.rows[0].public_metadata.controllerObservation).to.deep.include({ resourceVersion: "77" });
    } finally {
      await cleanupWorkspace(fixture);
    }
  });

  it("never turns generic or forged jobs into provisioning commands", async () => {
    const fixture = await createWorkspace("controller-provisioning-provenance");
    const humanApp = createHumanProvisioningApp(fixture.ownerId);
    const executorApp = createControllerExecutorApp();
    try {
      const manual = await supertest(humanApp)
        .post(`/api/v1/workspaces/${fixture.workspaceId}/certops/jobs`)
        .send({
          operation: "deploy",
          subjectType: "managed_certificate",
          subjectId: crypto.randomUUID(),
          payload: { kind: "cert_manager_provision" },
          idempotencyKey: `manual-${crypto.randomUUID()}`,
        })
        .expect(201);
      expect(manual.body.job.source).to.equal("api");
      const token = await createControllerToken(fixture);
      await commandRequest(executorApp, token.plaintextToken).expect(204);

      const valid = await postProvisionIntent(humanApp, fixture.workspaceId, `valid-${crypto.randomUUID()}`, provisionRequest()).expect(201);
      const forgedJobId = crypto.randomUUID();
      const forgedDesired = {
        ...valid.body.job.payload.desiredCertificate,
        jobId: forgedJobId,
        managedCertificateId: crypto.randomUUID(),
      };
      await TestUtils.execQuery(
        `INSERT INTO certificate_jobs (
           id, workspace_id, operation, status, source, subject_type, subject_id,
           payload, created_at, updated_at
         ) VALUES ($1, $2, 'deploy', 'pending', 'controller_provisioning',
           'managed_certificate', $3, $4::jsonb, NOW() - INTERVAL '1 minute', NOW() - INTERVAL '1 minute')`,
        [
          forgedJobId, fixture.workspaceId, forgedDesired.managedCertificateId,
          JSON.stringify({ kind: "cert_manager_provision", desiredCertificate: forgedDesired }),
        ],
      );
      await commandRequest(executorApp, token.plaintextToken).expect(204);
      const blocked = await TestUtils.execQuery("SELECT status, error_code FROM certificate_jobs WHERE id = $1", [forgedJobId]);
      expect(blocked.rows[0]).to.deep.equal({ status: "blocked", error_code: "CERTOPS_CONTROLLER_PROVISIONING_INVALID_COMMAND" });
      const delivered = await commandRequest(executorApp, token.plaintextToken).expect(200);
      expect(delivered.body.command.jobId).to.equal(valid.body.job.id);
    } finally {
      await cleanupWorkspace(fixture);
    }
  });

  it("blocks delivery when the authoritative inventory identity is missing or terminal", async () => {
    const fixture = await createWorkspace("controller-provisioning-invalid-inventory");
    const humanApp = createHumanProvisioningApp(fixture.ownerId);
    const executorApp = createControllerExecutorApp();
    try {
      const token = await createControllerToken(fixture);
      const missingTarget = await postProvisionIntent(
        humanApp,
        fixture.workspaceId,
        `missing-target-${crypto.randomUUID()}`,
        provisionRequest(),
      ).expect(201);
      await TestUtils.execQuery(
        "DELETE FROM certificate_targets WHERE id = $1",
        [missingTarget.body.targetId],
      );
      await commandRequest(executorApp, token.plaintextToken).expect(204);

      const terminal = await postProvisionIntent(
        humanApp,
        fixture.workspaceId,
        `terminal-delivery-${crypto.randomUUID()}`,
        provisionRequest({ certificateName: "terminal-delivery", secretName: "terminal-delivery-tls" }),
      ).expect(201);
      await TestUtils.execQuery(
        "UPDATE managed_certificates SET status = 'revoked' WHERE id = $1",
        [terminal.body.managedCertificateId],
      );
      await commandRequest(executorApp, token.plaintextToken).expect(204);

      const jobs = await TestUtils.execQuery(
        "SELECT id, status, error_code FROM certificate_jobs WHERE id = ANY($1::uuid[]) ORDER BY id",
        [[missingTarget.body.job.id, terminal.body.job.id].sort()],
      );
      expect(jobs.rows).to.have.length(2);
      for (const job of jobs.rows) {
        expect(job).to.include({
          error_code: "CERTOPS_CONTROLLER_PROVISIONING_INVALID_COMMAND",
          status: "blocked",
        });
      }
      expect(await provisioningCounts(fixture.workspaceId)).to.deep.include({ deliveries: 0 });
    } finally {
      await cleanupWorkspace(fixture);
    }
  });

  it("rolls back transient identity-query failures without blocking or duplicating delivery", async () => {
    const fixture = await createWorkspace("controller-provisioning-query-failure");
    const humanApp = createHumanProvisioningApp(fixture.ownerId);
    let failIdentityQuery = true;
    let identityQueryFailures = 0;
    const faultInjectingPool = {
      async connect() {
        const client = await pool.connect();
        return new Proxy(client, {
          get(target, property) {
            if (property === "query") {
              return async (...args) => {
                const [query] = args;
                if (
                  failIdentityQuery &&
                  typeof query === "string" &&
                  query.includes("FROM managed_certificates mc")
                ) {
                  identityQueryFailures += 1;
                  const error = new Error("simulated identity query failure");
                  error.code = "ECONNRESET";
                  throw error;
                }
                return target.query(...args);
              };
            }
            const value = target[property];
            return typeof value === "function" ? value.bind(target) : value;
          },
        });
      },
    };
    const executorApp = createControllerExecutorApp({
      takeNextControllerProvisioningCommand: ({ apiToken }) => takeNextControllerProvisioningCommand({
        apiToken,
        dbPool: faultInjectingPool,
      }),
    });
    try {
      const token = await createControllerToken(fixture);
      const intent = await postProvisionIntent(
        humanApp,
        fixture.workspaceId,
        `query-failure-${crypto.randomUUID()}`,
        provisionRequest(),
      ).expect(201);

      const failed = await commandRequest(executorApp, token.plaintextToken).expect(500);
      expect(failed.body.code).to.equal("CERTOPS_CONTROLLER_PROVISIONING_COMMAND_FAILED");
      expect(identityQueryFailures).to.equal(1);
      expect(await provisioningCounts(fixture.workspaceId)).to.deep.include({ deliveries: 0, jobs: 1 });
      const afterFailure = await TestUtils.execQuery(
        "SELECT status, error_code FROM certificate_jobs WHERE id = $1",
        [intent.body.job.id],
      );
      expect(afterFailure.rows[0]).to.deep.equal({ status: "pending", error_code: null });

      failIdentityQuery = false;
      const delivered = await commandRequest(executorApp, token.plaintextToken).expect(200);
      expect(delivered.body.command.jobId).to.equal(intent.body.job.id);
      expect(await provisioningCounts(fixture.workspaceId)).to.deep.include({ deliveries: 1, jobs: 1 });
      expect(identityQueryFailures).to.equal(1);
    } finally {
      await cleanupWorkspace(fixture);
    }
  });

  it("rolls back inventory, job, idempotency, and audit state when the required audit write fails", async () => {
    const fixture = await createWorkspace("controller-provisioning-rollback");
    const app = createHumanProvisioningApp(fixture.ownerId);
    const triggerName = `provisioning_audit_${crypto.randomUUID().replaceAll("-", "")}`;
    const functionName = `${triggerName}_fn`;
    const key = `rollback-${crypto.randomUUID()}`;
    try {
      await TestUtils.execQuery(`
        CREATE OR REPLACE FUNCTION ${functionName}() RETURNS trigger AS $$
        BEGIN
          IF NEW.workspace_id = '${fixture.workspaceId}'::uuid
             AND NEW.action = 'CERTOPS_CONTROLLER_PROVISION_INTENT_CREATED' THEN
            RAISE EXCEPTION 'controller provisioning audit test failure';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        CREATE TRIGGER ${triggerName}
          BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION ${functionName}();
      `);

      const failed = await postProvisionIntent(
        app,
        fixture.workspaceId,
        key,
        provisionRequest(),
      ).expect(500);
      expect(failed.body.code).to.equal("CERTOPS_CONTROLLER_PROVISIONING_CREATE_FAILED");
      expect(await provisioningCounts(fixture.workspaceId)).to.deep.equal({
        managed: 0,
        targets: 0,
        jobs: 0,
        idempotency: 0,
        audits: 0,
        deliveries: 0,
      });

      await TestUtils.execQuery(`DROP TRIGGER ${triggerName} ON audit_events; DROP FUNCTION ${functionName}();`);
      const acceptedAfterRollback = await postProvisionIntent(
        app,
        fixture.workspaceId,
        key,
        provisionRequest(),
      ).expect(201);
      expect(acceptedAfterRollback.body.duplicate).to.equal(false);
    } finally {
      await TestUtils.execQuery(`DROP TRIGGER IF EXISTS ${triggerName} ON audit_events`);
      await TestUtils.execQuery(`DROP FUNCTION IF EXISTS ${functionName}()`);
      await cleanupWorkspace(fixture);
    }
  });

  it("rejects revoked and decommissioned cert-manager identities without reactivating them", async () => {
    const fixture = await createWorkspace("controller-provisioning-terminal");
    const app = createHumanProvisioningApp(fixture.ownerId);
    try {
      for (const status of ["revoked", "decommissioned"]) {
        const certificateName = `terminal-${status}`;
        const initial = await postProvisionIntent(
          app,
          fixture.workspaceId,
          `initial-${status}-${crypto.randomUUID()}`,
          provisionRequest({
            certificateName,
            secretName: `${certificateName}-tls`,
          }),
        ).expect(201);
        await TestUtils.execQuery(
          "UPDATE managed_certificates SET status = $2 WHERE id = $1",
          [initial.body.managedCertificateId, status],
        );

        const rejected = await postProvisionIntent(
          app,
          fixture.workspaceId,
          `terminal-${status}-${crypto.randomUUID()}`,
          provisionRequest({
            certificateName,
            secretName: `${certificateName}-tls`,
          }),
        ).expect(409);
        expect(rejected.body.code).to.equal("CERTOPS_CONTROLLER_PROVISIONING_TERMINAL_IDENTITY");
        const persisted = await TestUtils.execQuery(
          "SELECT status FROM managed_certificates WHERE id = $1",
          [initial.body.managedCertificateId],
        );
        expect(persisted.rows[0].status).to.equal(status);
      }
    } finally {
      await cleanupWorkspace(fixture);
    }
  });

  it("blocks human intent creation and command delivery while paused but keeps observations and executor events available", async () => {
    const fixture = await createWorkspace("controller-provisioning-paused");
    const humanApp = createHumanProvisioningApp(fixture.ownerId);
    const executorApp = createControllerExecutorApp();
    try {
      const initial = await postProvisionIntent(
        humanApp,
        fixture.workspaceId,
        `paused-initial-${crypto.randomUUID()}`,
        provisionRequest(),
      ).expect(201);
      const provisionToken = await createControllerToken(fixture);
      const observationToken = await createControllerToken({
        ...fixture,
        scopes: ["certops:observations:write"],
      });
      const eventsToken = await createApiToken({
        workspaceId: fixture.workspaceId,
        name: "Paused events",
        scopes: ["certops:events:write"],
        createdBy: fixture.ownerId,
      });
      const delivered = await commandRequest(
        executorApp,
        provisionToken.plaintextToken,
      ).expect(200);
      expect(delivered.body.command.jobId).to.equal(initial.body.job.id);
      await TestUtils.execQuery(
        "UPDATE workspaces SET certops_paused = TRUE WHERE id = $1",
        [fixture.workspaceId],
      );

      await postProvisionIntent(
        humanApp,
        fixture.workspaceId,
        `paused-new-${crypto.randomUUID()}`,
        provisionRequest({ certificateName: "blocked-cert", secretName: "blocked-cert-tls" }),
      ).expect(409);
      await commandRequest(executorApp, provisionToken.plaintextToken).expect(409);
      const blockedMutation = await mutationAuthorizationRequest(
        executorApp,
        provisionToken.plaintextToken,
        initial.body.job.id,
      ).expect(409);
      expect(blockedMutation.body.code).to.equal("CERTOPS_WORKSPACE_PAUSED");

      const observation = observationPayload(fixture.workspaceId);
      await supertest(executorApp)
        .post(OBSERVATION_ROUTE)
        .set("Authorization", `Bearer ${observationToken.plaintextToken}`)
        .set("Idempotency-Key", observation.idempotencyKey)
        .send(observation)
        .expect(201);
      await supertest(executorApp)
        .post(`/api/v1/certops/jobs/${initial.body.job.id}/events`)
        .set("Authorization", `Bearer ${eventsToken.plaintextToken}`)
        .send(executorEventPayload(fixture.workspaceId, initial.body.job.id))
        .expect(202);
    } finally {
      await cleanupWorkspace(fixture);
    }
  });

  it("keeps command delivery isolated by scope, workspace, and immutable cluster binding", async () => {
    const first = await createWorkspace("controller-provisioning-delivery-a");
    const second = await createWorkspace("controller-provisioning-delivery-b");
    const humanApp = createHumanProvisioningApp(first.ownerId);
    const executorApp = createControllerExecutorApp();
    try {
      await postProvisionIntent(
        humanApp,
        first.workspaceId,
        `delivery-a-${crypto.randomUUID()}`,
        provisionRequest(),
      ).expect(201);
      await postProvisionIntent(
        humanApp,
        first.workspaceId,
        `delivery-b-${crypto.randomUUID()}`,
        provisionRequest({ clusterId: "cluster-b", certificateName: "cluster-b-cert", secretName: "cluster-b-tls" }),
      ).expect(201);

      const clusterA = await createControllerToken(first);
      const clusterB = await createControllerToken({ ...first, clusterId: "cluster-b" });
      const otherWorkspace = await createControllerToken(second);
      const observationOnly = await createControllerToken({
        ...first,
        scopes: ["certops:observations:write"],
      });
      const genericExecutor = await createApiToken({
        workspaceId: first.workspaceId,
        name: "Generic executor",
        scopes: ["certops:events:write", "certops:evidence:write"],
        createdBy: first.ownerId,
      });

      await commandRequest(executorApp, observationOnly.plaintextToken).expect(403);
      await commandRequest(executorApp, genericExecutor.plaintextToken).expect(403);
      await commandRequest(executorApp, otherWorkspace.plaintextToken).expect(204);
      const commandA = await commandRequest(executorApp, clusterA.plaintextToken).expect(200);
      const commandB = await commandRequest(executorApp, clusterB.plaintextToken).expect(200);
      expect(commandA.body.command.clusterId).to.equal("cluster-a");
      expect(commandB.body.command.clusterId).to.equal("cluster-b");
      await mutationAuthorizationRequest(
        executorApp,
        observationOnly.plaintextToken,
        commandA.body.command.jobId,
      ).expect(403);
      await mutationAuthorizationRequest(
        executorApp,
        genericExecutor.plaintextToken,
        commandA.body.command.jobId,
      ).expect(403);
      await mutationAuthorizationRequest(
        executorApp,
        otherWorkspace.plaintextToken,
        commandA.body.command.jobId,
      ).expect(409);
      await mutationAuthorizationRequest(
        executorApp,
        clusterB.plaintextToken,
        commandA.body.command.jobId,
      ).expect(409);
      await mutationAuthorizationRequest(
        executorApp,
        clusterA.plaintextToken,
        commandA.body.command.jobId,
      ).expect(204);
      await mutationAuthorizationRequest(
        executorApp,
        clusterB.plaintextToken,
        commandB.body.command.jobId,
      ).expect(204);
    } finally {
      await cleanupWorkspace(first);
      await cleanupWorkspace(second);
    }
  });

  it("returns 204 for no work and uses SKIP LOCKED delivery without creating an agent protocol record", async () => {
    const fixture = await createWorkspace("controller-provisioning-concurrency");
    const humanApp = createHumanProvisioningApp(fixture.ownerId);
    const executorApp = createControllerExecutorApp();
    try {
      const token = await createControllerToken(fixture);
      await commandRequest(executorApp, token.plaintextToken).expect(204);

      const intent = await postProvisionIntent(
        humanApp,
        fixture.workspaceId,
        `concurrent-${crypto.randomUUID()}`,
        provisionRequest(),
      ).expect(201);
      const [left, right] = await Promise.all([
        commandRequest(executorApp, token.plaintextToken),
        commandRequest(executorApp, token.plaintextToken),
      ]);
      expect([left.status, right.status].sort()).to.deep.equal([200, 204]);
      const delivered = left.status === 200 ? left : right;
      expect(delivered.body.command.jobId).to.equal(intent.body.job.id);
      expect(await provisioningCounts(fixture.workspaceId)).to.deep.include({ deliveries: 1, jobs: 1 });

      const agentProtocolTables = await TestUtils.execQuery(
        `SELECT table_name
           FROM information_schema.tables
          WHERE table_schema = 'public'
            AND table_name = ANY($1::text[])`,
        [[
          "certops_agents",
          "certificate_job_claims",
          "certificate_job_signatures",
          "certificate_agent_heartbeats",
          "certificate_job_nonces",
        ]],
      );
      expect(agentProtocolTables.rows).to.deep.equal([]);
      const payload = await TestUtils.execQuery(
        "SELECT payload FROM certificate_jobs WHERE id = $1",
        [intent.body.job.id],
      );
      expect(payload.rows[0].payload).to.not.have.any.keys(
        "agentId",
        "attemptId",
        "signature",
        "signingKeyId",
        "nonce",
      );
    } finally {
      await cleanupWorkspace(fixture);
    }
  });

  it("redelivers a non-terminal ambiguous command after the bounded interval and never redelivers a terminal job", async () => {
    const fixture = await createWorkspace("controller-provisioning-redelivery");
    const humanApp = createHumanProvisioningApp(fixture.ownerId);
    const executorApp = createControllerExecutorApp();
    try {
      const token = await createControllerToken({
        ...fixture,
        scopes: ["certops:provision:execute", "certops:events:write"],
      });
      const intent = await postProvisionIntent(
        humanApp,
        fixture.workspaceId,
        `redelivery-${crypto.randomUUID()}`,
        provisionRequest(),
      ).expect(201);
      const first = await commandRequest(executorApp, token.plaintextToken).expect(200);
      expect(first.body.command.jobId).to.equal(intent.body.job.id);
      const startedAt = "2026-07-21T12:00:00.000Z";
      await supertest(executorApp)
        .post(`/api/v1/certops/jobs/${intent.body.job.id}/events`)
        .set("Authorization", `Bearer ${token.plaintextToken}`)
        .send(executorEventPayload(fixture.workspaceId, intent.body.job.id, {
          eventId: `event-${crypto.randomUUID()}`,
          eventType: "job.started",
          occurredAt: startedAt,
          status: "running",
        }))
        .expect(202);

      await TestUtils.execQuery(
        "UPDATE certificate_controller_provision_deliveries SET delivered_at = NOW() - INTERVAL '31 seconds' WHERE job_id = $1",
        [intent.body.job.id],
      );
      const replay = await commandRequest(executorApp, token.plaintextToken).expect(200);
      expect(replay.body.command).to.deep.equal(first.body.command);
      expect(replay.body.eventTimestamps.started).to.equal(startedAt);

      await TestUtils.execQuery(
        "UPDATE certificate_jobs SET status = 'succeeded' WHERE id = $1",
        [intent.body.job.id],
      );
      await TestUtils.execQuery(
        "UPDATE certificate_controller_provision_deliveries SET delivered_at = NOW() - INTERVAL '31 seconds' WHERE job_id = $1",
        [intent.body.job.id],
      );
      await commandRequest(executorApp, token.plaintextToken).expect(204);
    } finally {
      await cleanupWorkspace(fixture);
    }
  });

  it("uses one canonical server timeline for older completed and failed controller events", async () => {
    const fixture = await createWorkspace("controller-provisioning-timestamps");
    const humanApp = createHumanProvisioningApp(fixture.ownerId);
    const executorApp = createControllerExecutorApp();
    try {
      const token = await createControllerToken({
        ...fixture,
        scopes: [
          "certops:provision:execute",
          "certops:events:write",
          "certops:evidence:write",
        ],
      });
      const startedAt = "2026-07-21T12:00:00.000Z";
      const olderAt = "2026-07-21T11:00:00.000Z";
      for (const [certificateName, terminalEventType, terminalStatus] of [
        ["timestamp-completed", "job.completed", "succeeded"],
        ["timestamp-failed", "job.failed", "failed"],
      ]) {
        const intent = await postProvisionIntent(
          humanApp,
          fixture.workspaceId,
          `timestamps-${certificateName}-${crypto.randomUUID()}`,
          provisionRequest({
            certificateName,
            secretName: `${certificateName}-tls`,
          }),
        ).expect(201);
        await commandRequest(executorApp, token.plaintextToken).expect(200);
        await supertest(executorApp)
          .post(`/api/v1/certops/jobs/${intent.body.job.id}/events`)
          .set("Authorization", `Bearer ${token.plaintextToken}`)
          .send(executorEventPayload(fixture.workspaceId, intent.body.job.id, {
            eventId: `event-${crypto.randomUUID()}`,
            eventType: "job.started",
            occurredAt: startedAt,
            status: "running",
          }))
          .expect(202);

        const terminalEventId = `event-${crypto.randomUUID()}`;
        const terminalPayload = executorEventPayload(
          fixture.workspaceId,
          intent.body.job.id,
          {
            eventId: terminalEventId,
            eventType: terminalEventType,
            occurredAt: olderAt,
            status: terminalStatus,
            evidence: [
              {
                schemaVersion: 1,
                evidenceId: `evidence-${crypto.randomUUID()}`,
                eventType:
                  terminalEventType === "job.failed"
                    ? "validation.failed"
                    : "deployment.updated",
                source: "executor",
                status:
                  terminalEventType === "job.failed" ? "failed" : "accepted",
                summary: "Public cert-manager reconciliation result",
              },
            ],
          },
        );
        const accepted = await supertest(executorApp)
          .post(`/api/v1/certops/jobs/${intent.body.job.id}/events`)
          .set("Authorization", `Bearer ${token.plaintextToken}`)
          .send(terminalPayload)
          .expect(202);
        expect(accepted.body.duplicate).to.equal(false);

        for (const retryOccurredAt of [olderAt, startedAt]) {
          const replay = await supertest(executorApp)
            .post(`/api/v1/certops/jobs/${intent.body.job.id}/events`)
            .set("Authorization", `Bearer ${token.plaintextToken}`)
            .send({ ...terminalPayload, occurredAt: retryOccurredAt })
            .expect(202);
          expect(replay.body.duplicate).to.equal(true);
          expect(replay.body.logId).to.equal(accepted.body.logId);
          expect(replay.body.evidenceIds).to.deep.equal(
            accepted.body.evidenceIds,
          );
        }

        const conflict = await supertest(executorApp)
          .post(`/api/v1/certops/jobs/${intent.body.job.id}/events`)
          .set("Authorization", `Bearer ${token.plaintextToken}`)
          .send({ ...terminalPayload, occurredAt: "2026-07-21T12:01:00.000Z" })
          .expect(409);
        expect(conflict.body.code).to.equal("CERTOPS_EXECUTOR_EVENT_CONFLICT");

        const canonicalPayload = { ...terminalPayload, occurredAt: startedAt };
        const canonicalEvent = normalizeExecutorEventBody(canonicalPayload, {
          workspaceId: fixture.workspaceId,
        });
        const expectedRequestHash = requestHash(
          executorEventIdempotencyPayload(canonicalEvent),
        );
        const terminalColumn =
          terminalEventType === "job.completed" ? "completed_at" : "failed_at";
        const persisted = await TestUtils.execQuery(
          `SELECT j.status, d.started_at, d.${terminalColumn} AS terminal_at,
                  ee.request_hash,
                  jl.metadata->>'occurredAt' AS log_occurred_at,
                  e.observed_at,
                  (SELECT COUNT(*)::int FROM certificate_executor_events
                    WHERE workspace_id = $1 AND job_id = $2) AS event_count,
                  (SELECT COUNT(*)::int FROM certificate_job_log
                    WHERE workspace_id = $1 AND job_id = $2) AS log_count,
                  (SELECT COUNT(*)::int FROM certificate_evidence
                    WHERE workspace_id = $1 AND job_id = $2) AS evidence_count,
                  (SELECT COUNT(*)::int FROM audit_events
                    WHERE workspace_id = $1
                      AND metadata->>'jobId' = $2::text
                      AND action = 'CERTOPS_EXECUTOR_EVENT_ACCEPTED') AS event_audit_count,
                  (SELECT COUNT(*)::int FROM audit_events
                    WHERE workspace_id = $1
                      AND metadata->>'jobId' = $2::text
                      AND action = 'CERTOPS_EVIDENCE_ACCEPTED') AS evidence_audit_count
           FROM certificate_jobs j
           JOIN certificate_controller_provision_deliveries d ON d.job_id = j.id
           JOIN certificate_executor_events ee
             ON ee.job_id = j.id AND ee.executor_event_id = $3
           JOIN certificate_job_log jl
             ON jl.job_id = j.id
            AND jl.metadata->>'executorEventId' = $3
           JOIN certificate_evidence e ON e.job_id = j.id
          WHERE j.workspace_id = $1 AND j.id = $2`,
          [fixture.workspaceId, intent.body.job.id, terminalEventId],
        );
        expect(persisted.rows).to.have.length(1);
        const row = persisted.rows[0];
        expect(row.status).to.equal(terminalStatus);
        expect(new Date(row.started_at).toISOString()).to.equal(startedAt);
        expect(new Date(row.terminal_at).toISOString()).to.equal(startedAt);
        expect(row.request_hash).to.equal(expectedRequestHash);
        expect(row.log_occurred_at).to.equal(startedAt);
        expect(new Date(row.observed_at).toISOString()).to.equal(startedAt);
        expect(row).to.include({
          event_count: 2,
          log_count: 2,
          evidence_count: 1,
          event_audit_count: 2,
          evidence_audit_count: 1,
        });
      }
    } finally {
      await cleanupWorkspace(fixture);
    }
  });

  it("preserves later controller times, explicit evidence times, and generic executor event times", async () => {
    const fixture = await createWorkspace("controller-provisioning-timestamp-scope");
    const humanApp = createHumanProvisioningApp(fixture.ownerId);
    const executorApp = createControllerExecutorApp();
    try {
      const controllerToken = await createControllerToken({
        ...fixture,
        scopes: [
          "certops:provision:execute",
          "certops:events:write",
          "certops:evidence:write",
        ],
      });
      const intent = await postProvisionIntent(
        humanApp,
        fixture.workspaceId,
        `later-timestamp-${crypto.randomUUID()}`,
        provisionRequest({
          certificateName: "timestamp-later",
          secretName: "timestamp-later-tls",
        }),
      ).expect(201);
      await commandRequest(executorApp, controllerToken.plaintextToken).expect(200);

      const startedAt = "2026-07-21T12:00:00.000Z";
      const laterAt = "2026-07-21T13:00:00.000Z";
      const explicitEvidenceAt = "2026-07-21T12:30:00.000Z";
      await supertest(executorApp)
        .post(`/api/v1/certops/jobs/${intent.body.job.id}/events`)
        .set("Authorization", `Bearer ${controllerToken.plaintextToken}`)
        .send(executorEventPayload(fixture.workspaceId, intent.body.job.id, {
          eventType: "job.started",
          occurredAt: startedAt,
          status: "running",
        }))
        .expect(202);
      const laterEventId = `event-${crypto.randomUUID()}`;
      const laterPayload = executorEventPayload(
        fixture.workspaceId,
        intent.body.job.id,
        {
          eventId: laterEventId,
          eventType: "job.completed",
          occurredAt: laterAt,
          status: "succeeded",
          evidence: [
            {
              schemaVersion: 1,
              evidenceId: `evidence-${crypto.randomUUID()}`,
              eventType: "deployment.updated",
              source: "executor",
              status: "accepted",
              observedAt: explicitEvidenceAt,
            },
          ],
        },
      );
      await supertest(executorApp)
        .post(`/api/v1/certops/jobs/${intent.body.job.id}/events`)
        .set("Authorization", `Bearer ${controllerToken.plaintextToken}`)
        .send(laterPayload)
        .expect(202);

      const controllerTimeline = await TestUtils.execQuery(
        `SELECT d.completed_at,
                jl.metadata->>'occurredAt' AS log_occurred_at,
                e.observed_at
           FROM certificate_controller_provision_deliveries d
           JOIN certificate_job_log jl
             ON jl.job_id = d.job_id
            AND jl.metadata->>'executorEventId' = $2
           JOIN certificate_evidence e ON e.job_id = d.job_id
          WHERE d.workspace_id = $1 AND d.job_id = $3`,
        [fixture.workspaceId, laterEventId, intent.body.job.id],
      );
      expect(new Date(controllerTimeline.rows[0].completed_at).toISOString()).to.equal(laterAt);
      expect(controllerTimeline.rows[0].log_occurred_at).to.equal(laterAt);
      expect(new Date(controllerTimeline.rows[0].observed_at).toISOString()).to.equal(explicitEvidenceAt);

      const genericToken = await createApiToken({
        workspaceId: fixture.workspaceId,
        name: "Generic executor",
        scopes: ["certops:events:write"],
        createdBy: fixture.ownerId,
      });
      const genericJob = await createCertificateJob({
        workspaceId: fixture.workspaceId,
        operation: "deploy",
        source: "api",
        subjectType: "managed_certificate",
        subjectId: `cert-${crypto.randomUUID()}`,
        payload: { deploymentTarget: "generic/public-target" },
        requestedByUserId: fixture.ownerId,
      });
      const genericOccurredAt = "2026-07-21T11:00:00.000Z";
      const genericEventId = `event-${crypto.randomUUID()}`;
      const genericPayload = executorEventPayload(
        fixture.workspaceId,
        genericJob.id,
        {
          eventId: genericEventId,
          eventType: "job.completed",
          occurredAt: genericOccurredAt,
          status: "succeeded",
        },
      );
      await supertest(executorApp)
        .post(`/api/v1/certops/jobs/${genericJob.id}/events`)
        .set("Authorization", `Bearer ${genericToken.plaintextToken}`)
        .send(genericPayload)
        .expect(202);

      const genericTimeline = await TestUtils.execQuery(
        `SELECT jl.metadata->>'occurredAt' AS log_occurred_at,
                ee.request_hash
           FROM certificate_job_log jl
           JOIN certificate_executor_events ee
             ON ee.job_id = jl.job_id
            AND ee.executor_event_id = $3
          WHERE jl.workspace_id = $1
            AND jl.job_id = $2
            AND jl.metadata->>'executorEventId' = $3`,
        [fixture.workspaceId, genericJob.id, genericEventId],
      );
      const expectedGenericHash = requestHash(
        executorEventIdempotencyPayload(
          normalizeExecutorEventBody(genericPayload, {
            workspaceId: fixture.workspaceId,
          }),
        ),
      );
      expect(genericTimeline.rows[0].log_occurred_at).to.equal(genericOccurredAt);
      expect(genericTimeline.rows[0].request_hash).to.equal(expectedGenericHash);
    } finally {
      await cleanupWorkspace(fixture);
    }
  });
});
