"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createRequire } = require("node:module");
const { describe, it, before, after } = require("mocha");
const { expect, TestUtils } = require("./setup");
const { loadRootEnv } = require("../../scripts/load-root-env");
const { requireMigrateModule } = require("./variant-paths");

loadRootEnv();

const { runMigrations } = requireMigrateModule();
const { createApiToken } = require("../../apps/api/services/certops/apiTokens");
const { createControllerProvisionIntent } = require("../../apps/api/services/certops/controllerProvisioning");
const { createCertOpsExecutorRouter } = require("../../apps/api/routes/certops-executor");
const {
  certificateFor,
  createCertificateProvisioner,
} = require("../../apps/k8s-controller/src/certificate-provisioner");
const { createControllerProvisioningCommandClient } = require("../../apps/k8s-controller/src/provisioning-command-client");
const { createProvisioningRunner } = require("../../apps/k8s-controller/src/provisioning-runner");

const apiRequire = createRequire(require.resolve("../../apps/api/package.json"));
const express = apiRequire("express");

function provisionRequest(overrides = {}) {
  return {
    schemaVersion: 1,
    clusterId: "cluster-a",
    namespace: "certops",
    certificateName: "execution-cert",
    secretName: "execution-tls",
    issuerRef: { group: "cert-manager.io", kind: "ClusterIssuer", name: "public-issuer" },
    dnsNames: ["execution.example.test"],
    ...overrides,
  };
}

async function createWorkspace(label) {
  const email = `${label}-${crypto.randomUUID()}@example.test`;
  const user = await TestUtils.execQuery(
    `INSERT INTO users (email, email_original, display_name, password_hash, auth_method, email_verified)
     VALUES ($1, $2, $3, $4, 'local', TRUE) RETURNING id`,
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
  await TestUtils.execQuery("DELETE FROM audit_events WHERE workspace_id = $1", [workspaceId]);
  await TestUtils.execQuery("DELETE FROM certificate_executor_events WHERE workspace_id = $1", [workspaceId]);
  await TestUtils.execQuery("DELETE FROM certificate_evidence WHERE workspace_id = $1", [workspaceId]);
  await TestUtils.execQuery("DELETE FROM certificate_job_log WHERE workspace_id = $1", [workspaceId]);
  await TestUtils.execQuery("DELETE FROM certificate_controller_provision_deliveries WHERE workspace_id = $1", [workspaceId]);
  await TestUtils.execQuery("DELETE FROM certificate_jobs WHERE workspace_id = $1", [workspaceId]);
  await TestUtils.execQuery("DELETE FROM certificate_targets WHERE workspace_id = $1", [workspaceId]);
  await TestUtils.execQuery("DELETE FROM managed_certificates WHERE workspace_id = $1", [workspaceId]);
  await TestUtils.execQuery("DELETE FROM api_tokens WHERE workspace_id = $1", [workspaceId]);
  await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
  await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
}

async function eventually(check, attempts = 80) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try { return await check(); } catch (error) { lastError = error; }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw lastError;
}

async function startServer({ rejectCompleted = () => false, completedBodies = [] } = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, res, next) => {
    if (
      req.method === "POST" &&
      /^\/api\/v1\/certops\/jobs\/[^/]+\/events$/.test(req.path) &&
      req.body?.eventType === "job.completed"
    ) {
      completedBodies.push(req.body);
      if (rejectCompleted()) return res.status(503).json({ code: "TEMPORARY_REPORT_FAILURE" });
    }
    return next();
  });
  app.use(createCertOpsExecutorRouter({ rateLimitOptions: { windowMs: 60_000, max: 10_000 } }));
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  const address = server.address();
  return {
    apiUrl: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

function createKubernetesClient({ fail = null } = {}) {
  let resource = null;
  const calls = [];
  const missing = Object.assign(new Error("missing"), { statusCode: 404 });
  return {
    calls,
    client: {
      async getCertificate() {
        calls.push("getCertificate");
        if (fail) throw fail;
        if (!resource) throw missing;
        return { body: resource };
      },
      async createCertificate({ certificate }) {
        calls.push("createCertificate");
        resource = { ...certificate, metadata: { ...certificate.metadata, uid: "public-certificate-uid" } };
        return { body: resource };
      },
      async patchCertificate({ certificate }) {
        calls.push("patchCertificate");
        resource = { ...certificate, metadata: { ...certificate.metadata, uid: resource?.metadata?.uid || "public-certificate-uid" } };
        return { body: resource };
      },
    },
  };
}

function createTokenFile(token) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-m3a7-"));
  const file = path.join(directory, "token");
  fs.writeFileSync(file, `${token}\n`, { mode: 0o600 });
  return { directory, file };
}

function createCommandClient(apiUrl, apiTokenFile) {
  return createControllerProvisioningCommandClient({
    apiUrl,
    apiTokenFile,
    sleep: async () => {},
  });
}

async function createIntent(fixture, request = provisionRequest()) {
  return createControllerProvisionIntent({
    request,
    workspaceId: fixture.workspaceId,
    idempotencyKey: `execution-${crypto.randomUUID()}`,
    actorUserId: fixture.ownerId,
  });
}

async function jobStatus(jobId) {
  const result = await TestUtils.execQuery("SELECT status FROM certificate_jobs WHERE id = $1", [jobId]);
  return result.rows[0]?.status;
}

describe("M3-A7 controller provisioning execution path", function () {
  this.timeout(90_000);
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

  it("delivers a command through HTTP, creates a Certificate, records events/evidence, and reconciles a later intent", async () => {
    const fixture = await createWorkspace("controller-execution-success");
    const server = await startServer();
    let tokenDirectory;
    try {
      const token = await createApiToken({
        workspaceId: fixture.workspaceId,
        name: "Execution controller",
        scopes: ["certops:provision:execute", "certops:events:write", "certops:evidence:write"],
        controllerClusterId: "cluster-a",
        createdBy: fixture.ownerId,
      });
      const tokenFile = createTokenFile(token.plaintextToken);
      tokenDirectory = tokenFile.directory;
      const first = await createIntent(fixture);
      const kubernetes = createKubernetesClient();
      const firstCommandClient = createCommandClient(server.apiUrl, tokenFile.file);
      const provisioner = createCertificateProvisioner({
        authorizeMutation: firstCommandClient.authorizeMutation,
        client: kubernetes.client,
        clusterId: "cluster-a",
        watchNamespaces: ["certops"],
        workspaceId: fixture.workspaceId,
      });
      const runner = createProvisioningRunner({ commandClient: firstCommandClient, provisioner, intervalMs: 30_000 });
      await runner.start({ trackWork: (work) => work });
      await eventually(async () => expect(await jobStatus(first.job.id)).to.equal("succeeded"));
      await runner.stopAcceptingWork();
      await runner.close();

      const persisted = await TestUtils.execQuery(
        `SELECT d.started_at, d.completed_at,
          (SELECT COUNT(*)::int FROM certificate_executor_events WHERE workspace_id = $1 AND job_id = $2) AS events,
          (SELECT COUNT(*)::int FROM certificate_evidence WHERE workspace_id = $1) AS evidence
         FROM certificate_controller_provision_deliveries d WHERE d.job_id = $2`,
        [fixture.workspaceId, first.job.id],
      );
      expect(persisted.rows[0].started_at).to.not.equal(null);
      expect(persisted.rows[0].completed_at).to.not.equal(null);
      expect(new Date(persisted.rows[0].started_at).getTime()).to.be.at.most(new Date(persisted.rows[0].completed_at).getTime());
      expect(persisted.rows[0]).to.include({ events: 2, evidence: 1 });
      expect(kubernetes.calls).to.deep.equal(["getCertificate", "createCertificate"]);

      const second = await createIntent(fixture, provisionRequest({ secretName: "execution-tls-v2", dnsNames: ["v2.execution.example.test"] }));
      const secondCommandClient = createCommandClient(server.apiUrl, tokenFile.file);
      const secondProvisioner = createCertificateProvisioner({
        authorizeMutation: secondCommandClient.authorizeMutation,
        client: kubernetes.client,
        clusterId: "cluster-a",
        watchNamespaces: ["certops"],
        workspaceId: fixture.workspaceId,
      });
      const secondRunner = createProvisioningRunner({ commandClient: secondCommandClient, provisioner: secondProvisioner, intervalMs: 30_000 });
      await secondRunner.start({ trackWork: (work) => work });
      await eventually(async () => expect(await jobStatus(second.job.id)).to.equal("succeeded"));
      await secondRunner.stopAcceptingWork();
      await secondRunner.close();
      expect(kubernetes.calls).to.include("patchCertificate");
      expect(kubernetes.calls).to.not.include.members(["deleteCertificate", "createSecret", "patchSecret", "createCertificateRequest", "patchCertificateRequest", "getSecret", "getTlsKey"]);
    } finally {
      if (tokenDirectory) fs.rmSync(tokenDirectory, { recursive: true, force: true });
      await server.close();
      await cleanupWorkspace(fixture);
    }
  });

  it("pauses after delivery and performs no create or patch while failure reporting remains available", async () => {
    for (const operation of ["create", "patch"]) {
      const fixture = await createWorkspace(`controller-execution-paused-${operation}`);
      const server = await startServer();
      let tokenDirectory;
      try {
        const token = await createApiToken({
          workspaceId: fixture.workspaceId,
          name: `Paused ${operation} controller`,
          scopes: ["certops:provision:execute", "certops:events:write"],
          controllerClusterId: "cluster-a",
          createdBy: fixture.ownerId,
        });
        const tokenFile = createTokenFile(token.plaintextToken);
        tokenDirectory = tokenFile.directory;
        const request = provisionRequest({
          certificateName: `paused-${operation}`,
          secretName: `paused-${operation}-tls`,
        });
        const intent = await createIntent(fixture, request);
        const deliveredCommand = {
          ...request,
          jobId: intent.job.id,
          managedCertificateId: intent.managedCertificateId,
          workspaceId: fixture.workspaceId,
        };
        const existing = certificateFor({
          ...deliveredCommand,
          dnsNames: ["previous.example.test"],
        });
        const kubernetesCalls = [];
        const missing = Object.assign(new Error("missing"), { statusCode: 404 });
        const kubernetesClient = {
          async getCertificate() {
            kubernetesCalls.push("getCertificate");
            await TestUtils.execQuery(
              "UPDATE workspaces SET certops_paused = TRUE WHERE id = $1",
              [fixture.workspaceId],
            );
            if (operation === "create") throw missing;
            return { body: existing };
          },
          async createCertificate() { kubernetesCalls.push("createCertificate"); },
          async patchCertificate() { kubernetesCalls.push("patchCertificate"); },
        };
        const commandClient = createCommandClient(server.apiUrl, tokenFile.file);
        const provisioner = createCertificateProvisioner({
          authorizeMutation: commandClient.authorizeMutation,
          client: kubernetesClient,
          clusterId: "cluster-a",
          watchNamespaces: ["certops"],
          workspaceId: fixture.workspaceId,
        });
        const runner = createProvisioningRunner({
          commandClient,
          intervalMs: 30_000,
          provisioner,
        });

        await runner.start({ trackWork: (work) => work });
        await eventually(async () => expect(await jobStatus(intent.job.id)).to.equal("failed"));
        await runner.stopAcceptingWork();
        await runner.close();

        expect(kubernetesCalls).to.deep.equal(["getCertificate"]);
        const reporting = await TestUtils.execQuery(
          `SELECT
             (SELECT COUNT(*)::int FROM certificate_executor_events
               WHERE workspace_id = $1 AND job_id = $2) AS events,
             (SELECT COUNT(*)::int FROM certificate_evidence
               WHERE workspace_id = $1 AND job_id = $2) AS evidence`,
          [fixture.workspaceId, intent.job.id],
        );
        expect(reporting.rows[0]).to.deep.equal({ events: 2, evidence: 0 });
      } finally {
        if (tokenDirectory) fs.rmSync(tokenDirectory, { recursive: true, force: true });
        await server.close();
        await cleanupWorkspace(fixture);
      }
    }
  });

  it("reports reconciliation failure, then redelivers a completion-report failure without job.failed", async () => {
    const fixture = await createWorkspace("controller-execution-failures");
    let rejectCompletion = true;
    const completedBodies = [];
    const server = await startServer({ rejectCompleted: () => rejectCompletion, completedBodies });
    let tokenDirectory;
    try {
      const token = await createApiToken({
        workspaceId: fixture.workspaceId,
        name: "Failure controller",
        scopes: ["certops:provision:execute", "certops:events:write", "certops:evidence:write"],
        controllerClusterId: "cluster-a",
        createdBy: fixture.ownerId,
      });
      const tokenFile = createTokenFile(token.plaintextToken);
      tokenDirectory = tokenFile.directory;

      const failingIntent = await createIntent(fixture, provisionRequest({ certificateName: "kube-fail", secretName: "kube-fail-tls" }));
      const failedClient = createKubernetesClient({ fail: Object.assign(new Error("kube unavailable"), { code: "KUBE_UNAVAILABLE" }) });
      const failedCommandClient = createCommandClient(server.apiUrl, tokenFile.file);
      const failedProvisioner = createCertificateProvisioner({
        authorizeMutation: failedCommandClient.authorizeMutation,
        client: failedClient.client,
        clusterId: "cluster-a",
        watchNamespaces: ["certops"],
        workspaceId: fixture.workspaceId,
      });
      const failedRunner = createProvisioningRunner({ commandClient: failedCommandClient, provisioner: failedProvisioner, intervalMs: 30_000 });
      await failedRunner.start({ trackWork: (work) => work });
      await eventually(async () => expect(await jobStatus(failingIntent.job.id)).to.equal("failed"));
      await failedRunner.stopAcceptingWork();
      await failedRunner.close();

      const intent = await createIntent(fixture, provisionRequest({ certificateName: "completion-retry", secretName: "completion-retry-tls" }));
      const kubernetes = createKubernetesClient();
      const timers = [];
      const retryCommandClient = createCommandClient(server.apiUrl, tokenFile.file);
      const retryRunner = createProvisioningRunner({
        commandClient: retryCommandClient,
        provisioner: createCertificateProvisioner({
          authorizeMutation: retryCommandClient.authorizeMutation,
          client: kubernetes.client,
          clusterId: "cluster-a",
          watchNamespaces: ["certops"],
          workspaceId: fixture.workspaceId,
        }),
        intervalMs: 1,
        setTimeoutFn: (callback) => { timers.push(callback); return timers.length; },
        clearTimeoutFn: () => {},
      });
      await retryRunner.start({ trackWork: (work) => work });
      await eventually(() => expect(completedBodies.length).to.equal(4));
      expect(await jobStatus(intent.job.id)).to.equal("running");
      const failedLog = await TestUtils.execQuery("SELECT COUNT(*)::int AS count FROM certificate_job_log WHERE job_id = $1 AND event_type = 'job.failed'", [intent.job.id]);
      expect(failedLog.rows[0].count).to.equal(0);
      await TestUtils.execQuery("UPDATE certificate_controller_provision_deliveries SET delivered_at = NOW() - INTERVAL '31 seconds' WHERE job_id = $1", [intent.job.id]);
      rejectCompletion = false;
      await timers.shift()();
      await eventually(async () => expect(await jobStatus(intent.job.id)).to.equal("succeeded"));
      expect(completedBodies.length).to.equal(5);
      expect(completedBodies.every((body) => body.eventId === completedBodies[0].eventId)).to.equal(true);
      expect(completedBodies.every((body) => body.occurredAt === completedBodies[0].occurredAt)).to.equal(true);
      expect(kubernetes.calls).to.deep.equal(["getCertificate", "createCertificate", "getCertificate"]);
      await retryRunner.stopAcceptingWork();
      await retryRunner.close();

      const terminal = await createIntent(fixture, provisionRequest({ certificateName: "terminal-delivery", secretName: "terminal-delivery-tls" }));
      await TestUtils.execQuery("UPDATE managed_certificates SET status = 'revoked' WHERE id = $1", [terminal.managedCertificateId]);
      const terminalClient = createCommandClient(server.apiUrl, tokenFile.file);
      await terminalClient.start();
      expect(await terminalClient.nextCommand()).to.equal(null);
      await terminalClient.close();
      expect(await jobStatus(terminal.job.id)).to.equal("blocked");
    } finally {
      if (tokenDirectory) fs.rmSync(tokenDirectory, { recursive: true, force: true });
      await server.close();
      await cleanupWorkspace(fixture);
    }
  });
});
