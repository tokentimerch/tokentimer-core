const crypto = require("crypto");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const {
  createApiToken,
} = require("../../apps/api/services/certops/apiTokens");
const {
  normalizeControllerObservation,
  persistControllerObservation,
} = require("../../apps/api/services/certops/controllerObservations");

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

function rawObservation(workspaceId, overrides = {}) {
  return {
    schemaVersion: 1,
    observationId: crypto.randomUUID(),
    idempotencyKey: "a".repeat(64),
    workspaceId,
    clusterId: "controller-a",
    namespace: "certops",
    certificateName: "example-com",
    certificateUid: crypto.randomUUID(),
    certificateGeneration: 1,
    resourceVersion: "1",
    issuerRef: { name: "issuer" },
    secretName: "example-com-tls",
    certificateRequestRef: null,
    dnsNames: ["example.com"],
    conditions: [{ type: "Ready", status: "True" }],
    ready: true,
    publicCertificate: { fingerprintSha256: "b".repeat(64) },
    observationSource: "cert_manager",
    observedAt: "2026-07-21T10:00:00.000Z",
    ...overrides,
  };
}

describe("CertOps controller observation persistence", function () {
  this.timeout(60000);

  before(async () => runMigrations());

  it("atomically creates source-stable inventory, jobless evidence, and one acceptance audit", async () => {
    const { ownerId, workspaceId } = await createWorkspace("controller-observation");
    try {
      const token = await createApiToken({
        workspaceId,
        name: "Controller",
        scopes: ["certops:observations:write"],
        controllerClusterId: "controller-a",
        createdBy: ownerId,
      });
      const normalized = normalizeControllerObservation(rawObservation(workspaceId));
      const first = await persistControllerObservation({
        apiTokenId: token.token.id,
        observation: normalized.observation,
        redaction: normalized.redaction,
      });
      expect(first.duplicate).to.equal(false);
      expect(first.managedCertificateId).to.be.a("string");
      expect(first.targetId).to.be.a("string");
      expect(first.certificateInstanceId).to.be.a("string");

      const replayObservation = {
        ...normalized.observation,
        observationId: crypto.randomUUID(),
        observedAt: "2026-07-21T10:01:00.000Z",
      };
      const replay = await persistControllerObservation({
        apiTokenId: token.token.id,
        observation: replayObservation,
        redaction: normalized.redaction,
      });
      expect(replay).to.deep.equal({ ...first, duplicate: true });

      const counts = await TestUtils.execQuery(
        `SELECT
           (SELECT COUNT(*)::int FROM managed_certificates WHERE workspace_id = $1 AND source = 'cert_manager') AS managed,
           (SELECT COUNT(*)::int FROM certificate_targets WHERE workspace_id = $1 AND source = 'cert_manager' AND target_type = 'kubernetes-secret') AS targets,
           (SELECT COUNT(*)::int FROM certificate_instances WHERE workspace_id = $1 AND source = 'cert_manager') AS instances,
           (SELECT COUNT(*)::int FROM certificate_evidence WHERE workspace_id = $1 AND job_id IS NULL) AS evidence,
           (SELECT COUNT(*)::int FROM audit_events WHERE workspace_id = $1 AND action = 'CERTOPS_CONTROLLER_OBSERVATION_ACCEPTED') AS audits,
           (SELECT COUNT(*)::int FROM certificate_controller_observations WHERE workspace_id = $1) AS idempotency`,
        [workspaceId],
      );
      expect(counts.rows[0]).to.deep.include({
        managed: 1,
        targets: 1,
        instances: 1,
        evidence: 1,
        audits: 1,
        idempotency: 1,
      });
    } finally {
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
      await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
    }
  });
});
