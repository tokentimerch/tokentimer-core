const crypto = require("crypto");
const { createRequire } = require("module");
const supertest = require("supertest");

const { loadRootEnv } = require("../../scripts/load-root-env");

loadRootEnv();

const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");
const { runMigrations } = requireMigrateModule();
const {
  createApiToken,
} = require("../../apps/api/services/certops/apiTokens");
const {
  importPublicCertificates,
} = require("../../apps/api/services/certops/inventory");
const {
  parsePublicCertificateMaterial,
} = require("../../apps/api/services/certops/parser");
const {
  normalizeControllerObservation,
  persistControllerObservation,
} = require("../../apps/api/services/certops/controllerObservations");
const {
  createCertOpsExecutorRouter,
} = require("../../apps/api/routes/certops-executor");

const apiRequire = createRequire(require.resolve("../../apps/api/package.json"));
const express = apiRequire("express");

const PUBLIC_LEAF_CERT = `
-----BEGIN CERTIFICATE-----
MIIDgjCCAmqgAwIBAgIUKJShixxx/7TH81hKwHE3UsvIFMkwDQYJKoZIhvcNAQEL
BQAwNDEYMBYGA1UEAwwPY2VydG9wcy5leGFtcGxlMRgwFgYDVQQKDA9Ub2tlblRp
bWVyIFRlc3QwHhcNMjYwNjI2MDA0MDU5WhcNMjcwNjI2MDA0MDU5WjA0MRgwFgYD
VQQDDA9jZXJ0b3BzLmV4YW1wbGUxGDAWBgNVBAoMD1Rva2VuVGltZXIgVGVzdDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANoaAIgElNelqNg6TsY++HnK
rFeOgn7csJYu9AbFfQRAoFO592aVI9QdyejoGesSy+tDN06vJl411Ntz6caB2+fd
+qkllZ+c39IZEbp++PDp7dD+4aEC68tGoZ9F/9dOGRaZ4xSFp0W0+5hd8E5q4E9U
MSdc4cUjQKuZX+jwBQqy+SRxhhNh6GPVWg3Cr6W0F53yFxWlb8q+4cwOZg0AP7sK
2u8UvordGO3o4eiPsVtmRh87YeRnUDRuzPb4Mi/Fo9Cr+1Fq3Q3xdWH9LhP0DSmD
89Ho84nvn+DfM+Dbnb7PsmNgqOVictn/LxHMOrl1F04BkvY9rNuBkh7wHC7TOR8C
AwEAAaOBizCBiDAdBgNVHQ4EFgQUoOXgW3/xFso+3GDIpFqimZ2K2TUwHwYDVR0j
BBgwFoAUoOXgW3/xFso+3GDIpFqimZ2K2TUwDwYDVR0TAQH/BAUwAwEB/zA1BgNV
HREELjAsgg9jZXJ0b3BzLmV4YW1wbGWCE2FwaS5jZXJ0b3BzLmV4YW1wbGWHBH8A
AAEwDQYJKoZIhvcNAQELBQADggEBAGi4XAScskH5bdxNbXwtEqlep2eDyseUyulF
g2yILrkiA22+WveOZrmReuxHx+umHVAO4O6JtHwD1figZyKgCrMzrREqmRwGj6pb
jgaW6Eeck+zFh1cKTH6ZUYlN6yOHOhKR0nBnseSuoh/gEangQVLRug3SqCCi6GQI
aOAUKMHYsxTyfjtE2k7URQYy7fbfLW/k+68l+xI/ktwFlS+MncmrS+Lx+dWwxVCn
EucPyYnACaKyw2oY6kCVaW9OReglxzoFzLxZvqxyrA1LpWjzgJiR7nIpZCappsi9
gB1JS6DPep8dhLORucnHS/Opy2xOB0lB3kmNoh5bierJUVeReSc=
-----END CERTIFICATE-----
`;

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

function observationWithKey(workspaceId, keyCharacter, overrides = {}) {
  return rawObservation(workspaceId, {
    idempotencyKey: keyCharacter.repeat(64),
    ...overrides,
  });
}

async function persistRawObservation({ apiTokenId, workspaceId, keyCharacter = "a", overrides = {} }) {
  const normalized = normalizeControllerObservation(
    observationWithKey(workspaceId, keyCharacter, overrides),
  );
  return persistControllerObservation({
    apiTokenId,
    observation: normalized.observation,
    redaction: normalized.redaction,
  });
}

function createObservationApp({ controllerObservationGateMiddleware } = {}) {
  const app = express();
  app.use(express.json());
  app.use(createCertOpsExecutorRouter({
    certOpsEnabledMiddleware: (_req, _res, next) => next(),
    controllerObservationGateMiddleware,
    rateLimitOptions: { windowMs: 60_000, max: 1000 },
  }));
  return app;
}

async function workspaceCounts(workspaceId) {
  const result = await TestUtils.execQuery(
    `SELECT
       (SELECT COUNT(*)::int FROM managed_certificates WHERE workspace_id = $1 AND source = 'cert_manager') AS managed,
       (SELECT COUNT(*)::int FROM certificate_targets WHERE workspace_id = $1 AND source = 'cert_manager') AS targets,
       (SELECT COUNT(*)::int FROM certificate_instances WHERE workspace_id = $1 AND source = 'cert_manager') AS instances,
       (SELECT COUNT(*)::int FROM certificate_evidence WHERE workspace_id = $1 AND job_id IS NULL) AS evidence,
       (SELECT COUNT(*)::int FROM audit_events WHERE workspace_id = $1 AND action = 'CERTOPS_CONTROLLER_OBSERVATION_ACCEPTED') AS audits,
       (SELECT COUNT(*)::int FROM certificate_controller_observations WHERE workspace_id = $1) AS idempotency,
       (SELECT COUNT(*)::int FROM certificate_jobs WHERE workspace_id = $1) AS jobs`,
    [workspaceId],
  );
  return result.rows[0];
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

  it("keeps public PEM imports idempotent while cert-manager keeps a separate source identity", async () => {
    const { ownerId, workspaceId } = await createWorkspace("controller-import-conflict");
    try {
      const [parsed] = parsePublicCertificateMaterial(PUBLIC_LEAF_CERT);
      const firstImport = await importPublicCertificates({
        workspaceId,
        createdBy: ownerId,
        certificatePem: PUBLIC_LEAF_CERT,
      });
      const secondImport = await importPublicCertificates({
        workspaceId,
        createdBy: ownerId,
        certificatePem: PUBLIC_LEAF_CERT,
      });
      expect(firstImport).to.have.length(1);
      expect(secondImport).to.have.length(1);
      expect(secondImport[0].id).to.equal(firstImport[0].id);

      const token = await createApiToken({
        workspaceId,
        name: "Import conflict controller",
        scopes: ["certops:observations:write"],
        controllerClusterId: "controller-a",
        createdBy: ownerId,
      });
      const controller = await persistRawObservation({
        apiTokenId: token.token.id,
        workspaceId,
        keyCharacter: "c",
        overrides: { publicCertificate: { fingerprintSha256: parsed.fingerprintSha256 } },
      });
      expect(controller.managedCertificateId).to.not.equal(firstImport[0].id);
      const sourceRows = await TestUtils.execQuery(
        `SELECT source, id FROM managed_certificates
          WHERE workspace_id = $1 AND fingerprint_sha256 = $2
          ORDER BY source`,
        [workspaceId, parsed.fingerprintSha256],
      );
      expect(sourceRows.rows.map((row) => row.source)).to.deep.equal(["cert_manager", "import"]);
    } finally {
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
      await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
    }
  });

  it("creates pending observations without instances and keeps managed identity through rotation and recreation", async () => {
    const { ownerId, workspaceId } = await createWorkspace("controller-lifecycle");
    try {
      const token = await createApiToken({
        workspaceId,
        name: "Lifecycle controller",
        scopes: ["certops:observations:write"],
        controllerClusterId: "controller-a",
        createdBy: ownerId,
      });
      const pending = await persistRawObservation({
        apiTokenId: token.token.id,
        workspaceId,
        keyCharacter: "a",
        overrides: { ready: false, publicCertificate: null },
      });
      expect(pending.certificateInstanceId).to.equal(null);

      const first = await persistRawObservation({
        apiTokenId: token.token.id,
        workspaceId,
        keyCharacter: "b",
        overrides: { resourceVersion: "2", publicCertificate: { fingerprintSha256: "c".repeat(64) } },
      });
      const refreshed = await persistRawObservation({
        apiTokenId: token.token.id,
        workspaceId,
        keyCharacter: "c",
        overrides: { resourceVersion: "3", publicCertificate: { fingerprintSha256: "c".repeat(64) } },
      });
      const rotated = await persistRawObservation({
        apiTokenId: token.token.id,
        workspaceId,
        keyCharacter: "d",
        overrides: { resourceVersion: "4", publicCertificate: { fingerprintSha256: "d".repeat(64) } },
      });
      const recreatedUid = crypto.randomUUID();
      const recreated = await persistRawObservation({
        apiTokenId: token.token.id,
        workspaceId,
        keyCharacter: "e",
        overrides: {
          certificateUid: recreatedUid,
          resourceVersion: "5",
          publicCertificate: { fingerprintSha256: "e".repeat(64) },
        },
      });
      expect(first.managedCertificateId).to.equal(pending.managedCertificateId);
      expect(refreshed.managedCertificateId).to.equal(first.managedCertificateId);
      expect(refreshed.certificateInstanceId).to.equal(first.certificateInstanceId);
      expect(rotated.managedCertificateId).to.equal(first.managedCertificateId);
      expect(rotated.certificateInstanceId).to.not.equal(first.certificateInstanceId);
      expect(recreated.managedCertificateId).to.equal(first.managedCertificateId);
      const state = await TestUtils.execQuery(
        `SELECT public_metadata->'controllerObservation'->>'resourceRecreated' AS recreated
           FROM managed_certificates WHERE id = $1`,
        [first.managedCertificateId],
      );
      expect(state.rows[0].recreated).to.equal("true");
      expect((await workspaceCounts(workspaceId))).to.deep.include({ managed: 1, targets: 1, instances: 3 });
    } finally {
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
      await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
    }
  });

  it("isolates controller inventory by workspace and cluster and never resurrects terminal certificates", async () => {
    const firstWorkspace = await createWorkspace("controller-isolation-a");
    const secondWorkspace = await createWorkspace("controller-isolation-b");
    try {
      const firstToken = await createApiToken({
        workspaceId: firstWorkspace.workspaceId,
        name: "Isolation A",
        scopes: ["certops:observations:write"],
        controllerClusterId: "controller-a",
        createdBy: firstWorkspace.ownerId,
      });
      const secondToken = await createApiToken({
        workspaceId: secondWorkspace.workspaceId,
        name: "Isolation B",
        scopes: ["certops:observations:write"],
        controllerClusterId: "controller-a",
        createdBy: secondWorkspace.ownerId,
      });
      const first = await persistRawObservation({
        apiTokenId: firstToken.token.id,
        workspaceId: firstWorkspace.workspaceId,
        keyCharacter: "a",
      });
      const secondWorkspaceResult = await persistRawObservation({
        apiTokenId: secondToken.token.id,
        workspaceId: secondWorkspace.workspaceId,
        keyCharacter: "b",
      });
      const secondCluster = await persistRawObservation({
        apiTokenId: firstToken.token.id,
        workspaceId: firstWorkspace.workspaceId,
        keyCharacter: "c",
        overrides: { clusterId: "controller-b", resourceVersion: "2" },
      });
      expect(first.managedCertificateId).to.not.equal(secondWorkspaceResult.managedCertificateId);
      expect(first.managedCertificateId).to.not.equal(secondCluster.managedCertificateId);

      for (const status of ["revoked", "decommissioned"]) {
        await TestUtils.execQuery(
          "UPDATE managed_certificates SET status = $2 WHERE id = $1",
          [first.managedCertificateId, status],
        );
        await persistRawObservation({
          apiTokenId: firstToken.token.id,
          workspaceId: firstWorkspace.workspaceId,
          keyCharacter: status === "revoked" ? "d" : "e",
          overrides: { resourceVersion: status === "revoked" ? "3" : "4" },
        });
        const persisted = await TestUtils.execQuery("SELECT status FROM managed_certificates WHERE id = $1", [first.managedCertificateId]);
        expect(persisted.rows[0].status).to.equal(status);
      }
    } finally {
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = ANY($1::uuid[])", [[firstWorkspace.workspaceId, secondWorkspace.workspaceId]]);
      await TestUtils.execQuery("DELETE FROM users WHERE id = ANY($1::int[])", [[firstWorkspace.ownerId, secondWorkspace.ownerId]]);
    }
  });

  it("serializes identical idempotency and atomically reuses one target for concurrent observations", async () => {
    const { ownerId, workspaceId } = await createWorkspace("controller-concurrency");
    try {
      const token = await createApiToken({
        workspaceId,
        name: "Concurrency controller",
        scopes: ["certops:observations:write"],
        controllerClusterId: "controller-a",
        createdBy: ownerId,
      });
      const same = normalizeControllerObservation(rawObservation(workspaceId)).observation;
      const [first, replay] = await Promise.all([
        persistControllerObservation({ apiTokenId: token.token.id, observation: same }),
        persistControllerObservation({ apiTokenId: token.token.id, observation: { ...same } }),
      ]);
      expect([first.duplicate, replay.duplicate].sort()).to.deep.equal([false, true]);
      expect(first.managedCertificateId).to.equal(replay.managedCertificateId);

      const [left, right] = await Promise.all([
        persistRawObservation({
          apiTokenId: token.token.id,
          workspaceId,
          keyCharacter: "b",
          overrides: { resourceVersion: "2", publicCertificate: { fingerprintSha256: "c".repeat(64) } },
        }),
        persistRawObservation({
          apiTokenId: token.token.id,
          workspaceId,
          keyCharacter: "c",
          overrides: { resourceVersion: "3", publicCertificate: { fingerprintSha256: "d".repeat(64) } },
        }),
      ]);
      expect(left.targetId).to.equal(right.targetId);
      expect((await workspaceCounts(workspaceId))).to.deep.include({ targets: 1, idempotency: 3 });
    } finally {
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
      await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
    }
  });

  it("rolls back inventory and idempotency when required controller evidence or audit writes fail", async () => {
    const { ownerId, workspaceId } = await createWorkspace("controller-rollback");
    const triggerName = `fail_controller_observation_${crypto.randomUUID().replaceAll("-", "")}`;
    const functionName = `${triggerName}_fn`;
    try {
      const token = await createApiToken({
        workspaceId,
        name: "Rollback controller",
        scopes: ["certops:observations:write"],
        controllerClusterId: "controller-a",
        createdBy: ownerId,
      });
      await TestUtils.execQuery(`
        CREATE OR REPLACE FUNCTION ${functionName}() RETURNS trigger AS $$
        BEGIN
          IF NEW.workspace_id = '${workspaceId}'::uuid THEN
            RAISE EXCEPTION 'controller observation test failure';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        CREATE TRIGGER ${triggerName}
          BEFORE INSERT ON certificate_evidence FOR EACH ROW EXECUTE FUNCTION ${functionName}();
      `);
      let evidenceFailure;
      try {
        await persistRawObservation({
          apiTokenId: token.token.id,
          workspaceId,
          keyCharacter: "a",
        });
      } catch (error) {
        evidenceFailure = error;
      }
      expect(evidenceFailure?.message).to.include("controller observation test failure");
      expect(await workspaceCounts(workspaceId)).to.deep.include({ managed: 0, targets: 0, instances: 0, evidence: 0, idempotency: 0 });
      await TestUtils.execQuery(`DROP TRIGGER ${triggerName} ON certificate_evidence; DROP FUNCTION ${functionName}();`);

      await TestUtils.execQuery(`
        CREATE OR REPLACE FUNCTION ${functionName}() RETURNS trigger AS $$
        BEGIN
          IF NEW.workspace_id = '${workspaceId}'::uuid
             AND NEW.action = 'CERTOPS_CONTROLLER_OBSERVATION_ACCEPTED' THEN
            RAISE EXCEPTION 'controller observation audit test failure';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        CREATE TRIGGER ${triggerName}
          BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION ${functionName}();
      `);
      let auditFailure;
      try {
        await persistRawObservation({
          apiTokenId: token.token.id,
          workspaceId,
          keyCharacter: "b",
        });
      } catch (error) {
        auditFailure = error;
      }
      expect(auditFailure?.message).to.include("controller observation audit test failure");
      expect(await workspaceCounts(workspaceId)).to.deep.include({ managed: 0, targets: 0, instances: 0, evidence: 0, audits: 0, idempotency: 0 });
    } finally {
      await TestUtils.execQuery(`DROP TRIGGER IF EXISTS ${triggerName} ON certificate_evidence`);
      await TestUtils.execQuery(`DROP TRIGGER IF EXISTS ${triggerName} ON audit_events`);
      await TestUtils.execQuery(`DROP FUNCTION IF EXISTS ${functionName}()`);
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = $1", [workspaceId]);
      await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
    }
  });

  it("enforces the controller route's authenticated binding, passive pause, private-key precedence, and idempotency responses", async () => {
    const firstWorkspace = await createWorkspace("controller-route-a");
    const secondWorkspace = await createWorkspace("controller-route-b");
    let gateCalls = 0;
    const app = createObservationApp({
      controllerObservationGateMiddleware: (_req, res) => {
        gateCalls += 1;
        return res.status(451).json({ code: "TEST_GATE" });
      },
    });
    try {
      const valid = await createApiToken({
        workspaceId: firstWorkspace.workspaceId,
        name: "Route controller",
        scopes: ["certops:observations:write"],
        controllerClusterId: "controller-a",
        createdBy: firstWorkspace.ownerId,
      });
      const wrongScope = await createApiToken({
        workspaceId: firstWorkspace.workspaceId,
        name: "Route wrong scope",
        scopes: ["certops:read"],
        createdBy: firstWorkspace.ownerId,
      });
      const appWithoutGate = createObservationApp();
      const observation = observationWithKey(firstWorkspace.workspaceId, "a");
      const request = (target, token, body = observation) => {
        const call = supertest(target)
          .post("/api/v1/certops/executor/observations")
          .set("Idempotency-Key", body.idempotencyKey)
          .send(body);
        return token ? call.set("Authorization", `Bearer ${token}`) : call;
      };

      await request(appWithoutGate, null).expect(401);
      await request(appWithoutGate, wrongScope.plaintextToken).expect(403);
      await request(appWithoutGate, valid.plaintextToken, {
        ...observation,
        workspaceId: secondWorkspace.workspaceId,
        idempotencyKey: "b".repeat(64),
      }).expect(403);
      await request(appWithoutGate, valid.plaintextToken, {
        ...observation,
        clusterId: "controller-b",
        idempotencyKey: "c".repeat(64),
      }).expect(403);

      const keyPayload = {
        ...observation,
        idempotencyKey: "d".repeat(64),
        failureMessage: "-----BEGIN PRIVATE KEY-----",
      };
      await request(appWithoutGate, wrongScope.plaintextToken, keyPayload).expect(422);
      await request(app, wrongScope.plaintextToken, { ...keyPayload, idempotencyKey: "e".repeat(64) }).expect(422);
      expect(gateCalls).to.equal(0);

      await TestUtils.execQuery("UPDATE workspaces SET certops_paused = TRUE WHERE id = $1", [firstWorkspace.workspaceId]);
      const first = await request(appWithoutGate, valid.plaintextToken).expect(201);
      expect(first.body).to.include({ duplicate: false });
      const replay = await request(appWithoutGate, valid.plaintextToken, {
        ...observation,
        observationId: crypto.randomUUID(),
        observedAt: "2026-07-21T10:01:00.000Z",
      }).expect(200);
      expect(replay.body).to.deep.equal({ ...first.body, duplicate: true });
      await request(appWithoutGate, valid.plaintextToken, {
        ...observation,
        ready: false,
      }).expect(409);
      expect(await workspaceCounts(firstWorkspace.workspaceId)).to.deep.include({ jobs: 0, audits: 1, evidence: 1, idempotency: 1 });
    } finally {
      await TestUtils.execQuery("DELETE FROM workspaces WHERE id = ANY($1::uuid[])", [[firstWorkspace.workspaceId, secondWorkspace.workspaceId]]);
      await TestUtils.execQuery("DELETE FROM users WHERE id = ANY($1::int[])", [[firstWorkspace.ownerId, secondWorkspace.ownerId]]);
    }
  });
});
