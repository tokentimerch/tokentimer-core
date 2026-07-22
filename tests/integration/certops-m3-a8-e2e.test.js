"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createRequire } = require("node:module");
const { Readable } = require("node:stream");
const { describe, it, before, after } = require("mocha");

const { loadRootEnv } = require("../../scripts/load-root-env");
const { expect, TestUtils } = require("./setup");
const { requireMigrateModule } = require("./variant-paths");

loadRootEnv();

const { runMigrations } = requireMigrateModule();
const certOpsRouter = require("../../apps/api/routes/certops");
const {
  createCertOpsExecutorRouter,
} = require("../../apps/api/routes/certops-executor");
const {
  createApiToken,
} = require("../../apps/api/services/certops/apiTokens");
const {
  createInClusterCertManagerClient,
} = require("../../apps/k8s-controller/src/cert-manager-client");
const {
  createCertManagerObserver,
} = require("../../apps/k8s-controller/src/cert-manager-observer");
const {
  createTlsCertificateFallback,
  MAX_DECODED_TLS_CRT_BYTES,
} = require("../../apps/k8s-controller/src/tls-certificate-fallback");
const {
  createControllerObservationReporter,
} = require("../../apps/k8s-controller/src/observation-reporter");
const {
  createControllerRuntime,
} = require("../../apps/k8s-controller/src/runtime");
const {
  createCertificateProvisioner,
} = require("../../apps/k8s-controller/src/certificate-provisioner");
const {
  createControllerProvisioningCommandClient,
} = require("../../apps/k8s-controller/src/provisioning-command-client");
const {
  createProvisioningRunner,
} = require("../../apps/k8s-controller/src/provisioning-runner");
const {
  extractTlsCertificateFromSecretJson,
} = require("../../apps/k8s-controller/src/tls-crt-secret-reader");

const apiRequire = createRequire(require.resolve("../../apps/api/package.json"));
const express = apiRequire("express");

const PRIVATE_SENTINEL = `-----BEGIN PRIVATE KEY-----
never-cross-the-controller-boundary
-----END PRIVATE KEY-----`;

const PUBLIC_LEAF_CERT = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`;

const ENCODED_PUBLIC_CERT = Buffer.from(PUBLIC_LEAF_CERT).toString("base64");

function provisionRequest(overrides = {}) {
  return {
    schemaVersion: 1,
    clusterId: "cluster-a",
    namespace: "certops",
    certificateName: "m3-a8-cert",
    secretName: "m3-a8-tls",
    issuerRef: {
      group: "cert-manager.io",
      kind: "ClusterIssuer",
      name: "public-issuer",
    },
    dnsNames: ["m3-a8.example.test"],
    ...overrides,
  };
}

function observation({ workspaceId, certificateName, fingerprint, resourceVersion, uid, overrides = {} }) {
  return {
    schemaVersion: 1,
    workspaceId,
    clusterId: "cluster-a",
    namespace: "certops",
    certificateName,
    certificateUid: uid,
    certificateGeneration: 1,
    resourceVersion,
    issuerRef: {
      group: "cert-manager.io",
      kind: "ClusterIssuer",
      name: "public-issuer",
    },
    secretName: `${certificateName}-tls`,
    certificateRequestRef: null,
    dnsNames: [`${certificateName}.example.test`],
    conditions: [{ type: "Ready", status: "True", reason: "Issued" }],
    ready: true,
    ...(fingerprint
      ? { publicCertificate: { fingerprintSha256: fingerprint } }
      : {}),
    observationSource: "cert_manager",
    observedAt: "2026-07-21T10:00:00.000Z",
    ...overrides,
  };
}

function certificateResource({
  certificateName = "status-only",
  secretName = `${certificateName}-tls`,
  resourceVersion = "1",
  uid = crypto.randomUUID(),
  ready = true,
} = {}) {
  return {
    apiVersion: "cert-manager.io/v1",
    kind: "Certificate",
    metadata: {
      generation: 1,
      name: certificateName,
      namespace: "certops",
      resourceVersion,
      uid,
    },
    spec: {
      dnsNames: [`${certificateName}.example.test`],
      issuerRef: {
        group: "cert-manager.io",
        kind: "ClusterIssuer",
        name: "public-issuer",
      },
      secretName,
    },
    status: {
      conditions: [{
        lastTransitionTime: "2026-07-21T10:00:00.000Z",
        reason: ready ? "Issued" : "Pending",
        status: ready ? "True" : "False",
        type: "Ready",
      }],
      notAfter: "2027-06-26T00:40:59.000Z",
      notBefore: "2026-06-26T00:40:59.000Z",
      revision: 1,
    },
  };
}

async function createWorkspace(label) {
  const email = `${label}-${crypto.randomUUID()}@example.test`;
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
  await TestUtils.execQuery("DELETE FROM users WHERE id = $1", [ownerId]);
}

function createTokenFile(token) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-m3-a8-"));
  const file = path.join(directory, "token");
  fs.writeFileSync(file, `${token}\n`, { mode: 0o600 });
  return {
    file,
    remove() {
      fs.rmSync(directory, { recursive: true, force: true });
    },
  };
}

async function startApiServer(ownerId) {
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use((req, _res, next) => {
    const match = /^\/api\/v1\/workspaces\/([^/]+)\/certops(?:\/|$)/.exec(req.path);
    if (match) {
      req.workspace = { id: match[1] };
      req.user = { id: ownerId };
      req.authz = { workspaceRole: "workspace_manager" };
    }
    next();
  });
  app.use(certOpsRouter);
  app.use(createCertOpsExecutorRouter({
    rateLimitOptions: { windowMs: 60_000, max: 10_000 },
  }));
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  return {
    apiUrl: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  return {
    body: text ? JSON.parse(text) : null,
    headers: response.headers,
    status: response.status,
  };
}

async function eventually(check, attempts = 120) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await check();
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw lastError;
}

async function expectRejectedCode(action, code) {
  let failure;
  try {
    await action();
  } catch (error) {
    failure = error;
  }
  expect(failure).to.be.instanceOf(Error);
  expect(failure.code).to.equal(code);
}

function createKubernetesBoundary() {
  const certificates = new Map();
  const certificateRequests = new Map();
  const secrets = new Map();
  const calls = {
    abort: 0,
    createCertificate: [],
    getCertificate: [],
    list: [],
    patchCertificate: [],
    readSecret: [],
    watch: [],
  };
  let nextResourceVersion = 10;

  function key(namespace, name) {
    return `${namespace}/${name}`;
  }

  const notFound = () => Object.assign(new Error("not found"), { statusCode: 404 });

  const customObjectsApi = {
    async listNamespacedCustomObject(options) {
      calls.list.push(options);
      const values = options.plural === "certificates"
        ? [...certificates.values()]
        : [...certificateRequests.values()];
      return {
        body: {
          items: values.filter((item) => item.metadata.namespace === options.namespace),
          metadata: { resourceVersion: String(nextResourceVersion) },
        },
      };
    },
    async listClusterCustomObject(options) {
      calls.list.push(options);
      const values = options.plural === "certificates"
        ? [...certificates.values()]
        : [...certificateRequests.values()];
      return {
        body: {
          items: values,
          metadata: { resourceVersion: String(nextResourceVersion) },
        },
      };
    },
    async getNamespacedCustomObject(options) {
      calls.getCertificate.push(options);
      const value = certificates.get(key(options.namespace, options.name));
      if (!value) throw notFound();
      return { body: value };
    },
    async createNamespacedCustomObject(options) {
      calls.createCertificate.push(options);
      const resourceKey = key(options.namespace, options.name);
      if (certificates.has(resourceKey)) {
        throw Object.assign(new Error("already exists"), { statusCode: 409 });
      }
      nextResourceVersion += 1;
      const value = {
        ...options.body,
        metadata: {
          ...options.body.metadata,
          generation: 1,
          resourceVersion: String(nextResourceVersion),
          uid: crypto.randomUUID(),
        },
      };
      certificates.set(resourceKey, value);
      return { body: value };
    },
    async patchNamespacedCustomObject(options) {
      calls.patchCertificate.push(options);
      const resourceKey = key(options.namespace, options.name);
      const current = certificates.get(resourceKey);
      if (!current) throw notFound();
      nextResourceVersion += 1;
      const value = {
        ...current,
        ...options.body,
        metadata: {
          ...current.metadata,
          ...options.body.metadata,
          generation: Number(current.metadata.generation || 0) + 1,
          resourceVersion: String(nextResourceVersion),
        },
        spec: { ...current.spec, ...options.body.spec },
      };
      certificates.set(resourceKey, value);
      return { body: value };
    },
  };

  const secretReader = {
    async close() {},
    async read(options) {
      calls.readSecret.push(options);
      const value = secrets.get(key(options.namespace, options.secretName));
      if (!value) throw notFound();
      return extractTlsCertificateFromSecretJson(
        Readable.from([Buffer.from(JSON.stringify(value))]),
      );
    },
  };

  class CustomObjectsApi {}
  class Observable {
    constructor(value) {
      this.value = value;
    }
  }
  class KubeConfig {
    loadFromCluster() {}
    makeApiClient() { return customObjectsApi; }
  }
  class Watch {
    async watch(resourcePath, options, onEvent, onError) {
      calls.watch.push({ resourcePath, options, onEvent, onError });
      return {
        abort() {
          calls.abort += 1;
        },
      };
    }
  }

  return {
    calls,
    createClient(options = {}) {
      return createInClusterCertManagerClient({
        ...options,
        createSecretReader: () => secretReader,
        loadClient: async () => ({
          CustomObjectsApi,
          KubeConfig,
          Observable,
          Watch,
        }),
      });
    },
    getCertificate(namespace, name) {
      return certificates.get(key(namespace, name));
    },
    setCertificate(value) {
      certificates.set(key(value.metadata.namespace, value.metadata.name), value);
    },
    setSecret(namespace, name, value) {
      secrets.set(key(namespace, name), value);
    },
  };
}

async function createControllerToken(fixture, scopes) {
  return createApiToken({
    workspaceId: fixture.workspaceId,
    name: `M3-A8 controller ${crypto.randomUUID()}`,
    scopes,
    controllerClusterId: "cluster-a",
    createdBy: fixture.ownerId,
  });
}

async function inventoryCounts(workspaceId, certificateName) {
  const sourceRef = `cluster-a/certops/${certificateName}`;
  const result = await TestUtils.execQuery(
    `SELECT
       (SELECT COUNT(*)::int FROM managed_certificates
          WHERE workspace_id = $1 AND source = 'cert_manager' AND source_ref = $2) AS managed,
       (SELECT COUNT(*)::int FROM certificate_targets
          WHERE workspace_id = $1 AND source = 'cert_manager') AS targets,
       (SELECT COUNT(*)::int FROM certificate_instances
          WHERE workspace_id = $1 AND source = 'cert_manager') AS instances,
       (SELECT COUNT(*)::int FROM audit_events
          WHERE workspace_id = $1 AND action = 'CERTOPS_CONTROLLER_OBSERVATION_ACCEPTED') AS observation_audits`,
    [workspaceId, sourceRef],
  );
  return result.rows[0];
}

describe("CertOps M3-A8 end-to-end composition", function () {
  this.timeout(120_000);

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

  it("composes status-first observation and the instrumented tls.crt fallback into real inventory", async () => {
    const fixture = await createWorkspace("m3-a8-observe");
    const server = await startApiServer(fixture.ownerId);
    let tokenFile;
    try {
      const token = await createControllerToken(fixture, ["certops:observations:write"]);
      tokenFile = createTokenFile(token.plaintextToken);

      const statusBoundary = createKubernetesBoundary();
      statusBoundary.setCertificate(certificateResource({ certificateName: "status-only" }));
      const statusClient = statusBoundary.createClient();
      const statusReporter = createControllerObservationReporter({
        apiTokenFile: tokenFile.file,
        apiUrl: server.apiUrl,
      });
      const statusObserver = createCertManagerObserver({
        client: statusClient,
        clusterId: "cluster-a",
        observationHandler: (value) => statusReporter.report(value),
        watchNamespaces: ["certops"],
        workspaceId: fixture.workspaceId,
      });
      const statusRuntime = createControllerRuntime({
        kubernetesClient: statusObserver,
        reporter: statusReporter,
      });
      await statusRuntime.start();
      await eventually(async () => {
        const counts = await inventoryCounts(fixture.workspaceId, "status-only");
        expect(counts).to.include({ managed: 1, instances: 0 });
      });
      expect(statusRuntime.isReady()).to.equal(true);
      expect(statusBoundary.calls.readSecret).to.deep.equal([]);
      expect(statusBoundary.calls.list.map((call) => call.plural).sort()).to.deep.equal([
        "certificaterequests",
        "certificates",
      ]);
      expect(statusBoundary.calls.watch).to.have.length(2);
      await statusRuntime.stopAcceptingWork();
      expect(await statusRuntime.waitForIdle(1_000)).to.equal(true);
      await statusRuntime.close();

      const fallbackBoundary = createKubernetesBoundary();
      fallbackBoundary.setCertificate(certificateResource({ certificateName: "fallback-cert" }));
      fallbackBoundary.setSecret("certops", "fallback-cert-tls", {
        data: {
          "tls.crt": ENCODED_PUBLIC_CERT,
          "tls.key": PRIVATE_SENTINEL,
          password: "never-access-password",
          "tls.crt.backup": PRIVATE_SENTINEL,
        },
      });
      const fallbackClient = fallbackBoundary.createClient({ secretFallbackEnabled: true });
      const outboundBodies = [];
      const logs = [];
      const fallbackReporter = createControllerObservationReporter({
        apiTokenFile: tokenFile.file,
        apiUrl: server.apiUrl,
        fetchImpl: async (url, options) => {
          outboundBodies.push(options.body);
          return fetch(url, options);
        },
      });
      const fallback = createTlsCertificateFallback({
        enabled: true,
        kubernetesClient: fallbackClient,
      });
      const fallbackObserver = createCertManagerObserver({
        client: fallbackClient,
        clusterId: "cluster-a",
        enrichObservation: fallback.enrichObservation,
        logger: {
          debug() {},
          error(message, metadata) { logs.push({ message, metadata }); },
          info(message, metadata) { logs.push({ message, metadata }); },
          warn(message, metadata) { logs.push({ message, metadata }); },
        },
        observationHandler: (value) => fallbackReporter.report(value),
        watchNamespaces: ["certops"],
        workspaceId: fixture.workspaceId,
      });
      const fallbackRuntime = createControllerRuntime({
        kubernetesClient: fallbackObserver,
        reporter: fallbackReporter,
      });
      await fallbackRuntime.start();
      await eventually(async () => {
        const counts = await inventoryCounts(fixture.workspaceId, "fallback-cert");
        expect(counts.instances).to.equal(1);
      });
      expect(fallbackRuntime.isReady()).to.equal(true);
      expect(fallbackBoundary.calls.readSecret).to.deep.equal([
        { namespace: "certops", secretName: "fallback-cert-tls" },
      ]);
      expect(outboundBodies).to.have.length(1);
      expect(outboundBodies[0]).to.include("BEGIN CERTIFICATE");
      expect(outboundBodies[0]).to.not.include("never-cross-the-controller-boundary");
      expect(outboundBodies[0]).to.not.include("never-access-password");
      expect(JSON.stringify(logs)).to.not.include("never-cross-the-controller-boundary");
      expect(JSON.stringify(logs)).to.not.include("never-access-password");
      await fallbackRuntime.stopAcceptingWork();
      expect(await fallbackRuntime.waitForIdle(1_000)).to.equal(true);
      await fallbackRuntime.close();

      const invalidMaterials = [
        [Buffer.from("not a certificate").toString("base64"), "CERTOPS_CERTIFICATE_PARSE_FAILED"],
        [Buffer.from(`${PUBLIC_LEAF_CERT}\n${PRIVATE_SENTINEL}`).toString("base64"), "PRIVATE_KEY_MATERIAL_REJECTED"],
        [Buffer.alloc(MAX_DECODED_TLS_CRT_BYTES + 1, 0x41).toString("base64"), "CERTOPS_TLS_CRT_TOO_LARGE"],
      ];
      for (const [encoded, code] of invalidMaterials) {
        const rejectingFallback = createTlsCertificateFallback({
          enabled: true,
          kubernetesClient: { async readTlsCertificate() { return encoded; } },
        });
        await expectRejectedCode(() => rejectingFallback.enrichObservation({
          namespace: "certops",
          ready: true,
          secretName: "adversarial-tls",
        }), code);
      }

      const persisted = await TestUtils.execQuery(
        `SELECT CONCAT_WS(' ',
          COALESCE((SELECT STRING_AGG(metadata::text, ' ') FROM certificate_evidence WHERE workspace_id = $1), ''),
          COALESCE((SELECT STRING_AGG(metadata::text, ' ') FROM audit_events WHERE workspace_id = $1), '')
        ) AS value`,
        [fixture.workspaceId],
      );
      expect(persisted.rows[0].value).to.not.include("never-cross-the-controller-boundary");
      expect(persisted.rows[0].value).to.not.include("never-access-password");
    } finally {
      tokenFile?.remove();
      await server.close();
      await cleanupWorkspace(fixture);
    }
  });

  it("preserves source identity through replay, rotation, UID replacement, and both D7 terminal states", async () => {
    const fixture = await createWorkspace("m3-a8-inventory");
    const server = await startApiServer(fixture.ownerId);
    let tokenFile;
    try {
      const token = await createControllerToken(fixture, ["certops:observations:write"]);
      tokenFile = createTokenFile(token.plaintextToken);
      const reporter = createControllerObservationReporter({
        apiTokenFile: tokenFile.file,
        apiUrl: server.apiUrl,
      });
      await reporter.start();

      const firstObservation = observation({
        workspaceId: fixture.workspaceId,
        certificateName: "rotation-cert",
        fingerprint: "a".repeat(64),
        resourceVersion: "1",
        uid: crypto.randomUUID(),
      });
      const first = await reporter.report(firstObservation);
      const beforeReplay = await inventoryCounts(fixture.workspaceId, "rotation-cert");
      const replay = await reporter.report({
        ...firstObservation,
        observedAt: "2026-07-21T10:01:00.000Z",
      });
      const afterReplay = await inventoryCounts(fixture.workspaceId, "rotation-cert");
      expect(first.duplicate).to.equal(false);
      expect(replay).to.deep.include({
        managedCertificateId: first.managedCertificateId,
        targetId: first.targetId,
        certificateInstanceId: first.certificateInstanceId,
        duplicate: true,
      });
      expect(afterReplay).to.deep.equal(beforeReplay);

      const sameFingerprint = await reporter.report(observation({
        workspaceId: fixture.workspaceId,
        certificateName: "rotation-cert",
        fingerprint: "a".repeat(64),
        resourceVersion: "2",
        uid: firstObservation.certificateUid,
      }));
      const rotated = await reporter.report(observation({
        workspaceId: fixture.workspaceId,
        certificateName: "rotation-cert",
        fingerprint: "b".repeat(64),
        resourceVersion: "3",
        uid: firstObservation.certificateUid,
      }));
      const recreated = await reporter.report(observation({
        workspaceId: fixture.workspaceId,
        certificateName: "rotation-cert",
        fingerprint: "b".repeat(64),
        resourceVersion: "4",
        uid: crypto.randomUUID(),
      }));
      expect(sameFingerprint.certificateInstanceId).to.equal(first.certificateInstanceId);
      expect(rotated.managedCertificateId).to.equal(first.managedCertificateId);
      expect(recreated.managedCertificateId).to.equal(first.managedCertificateId);
      let counts = await inventoryCounts(fixture.workspaceId, "rotation-cert");
      expect(counts).to.include({ managed: 1, targets: 1, instances: 2 });

      for (const [index, terminalStatus] of ["revoked", "decommissioned"].entries()) {
        const certificateName = index === 0 ? "rotation-cert" : "decommissioned-cert";
        let managedCertificateId = first.managedCertificateId;
        if (index > 0) {
          const created = await reporter.report(observation({
            workspaceId: fixture.workspaceId,
            certificateName,
            fingerprint: "c".repeat(64),
            resourceVersion: "1",
            uid: crypto.randomUUID(),
          }));
          managedCertificateId = created.managedCertificateId;
        }
        await TestUtils.execQuery(
          "UPDATE managed_certificates SET status = $1 WHERE id = $2",
          [terminalStatus, managedCertificateId],
        );
        const later = await reporter.report(observation({
          workspaceId: fixture.workspaceId,
          certificateName,
          fingerprint: index === 0 ? "d".repeat(64) : "e".repeat(64),
          resourceVersion: index === 0 ? "5" : "2",
          uid: crypto.randomUUID(),
        }));
        expect(later.managedCertificateId).to.equal(managedCertificateId);
        const terminal = await TestUtils.execQuery(
          "SELECT status, source, source_ref FROM managed_certificates WHERE id = $1",
          [managedCertificateId],
        );
        expect(terminal.rows[0]).to.deep.equal({
          status: terminalStatus,
          source: "cert_manager",
          source_ref: `cluster-a/certops/${certificateName}`,
        });

        const provisionResponse = await fetchJson(
          `${server.apiUrl}/api/v1/workspaces/${fixture.workspaceId}/certops/provision-intents`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Idempotency-Key": `terminal-${terminalStatus}-${crypto.randomUUID()}`,
            },
            body: JSON.stringify(provisionRequest({ certificateName })),
          },
        );
        expect(provisionResponse.status).to.equal(409);
        expect(provisionResponse.body.code).to.equal("CERTOPS_CONTROLLER_PROVISIONING_TERMINAL_IDENTITY");
      }

      await expectRejectedCode(() => reporter.report(observation({
        workspaceId: fixture.workspaceId,
        certificateName: "wrong-cluster",
        fingerprint: "f".repeat(64),
        resourceVersion: "1",
        uid: crypto.randomUUID(),
        overrides: { clusterId: "cluster-b" },
      })), "CONTROLLER_REPORTER_HTTP_403");
      counts = await inventoryCounts(fixture.workspaceId, "wrong-cluster");
      expect(counts.managed).to.equal(0);
      await reporter.close();
    } finally {
      tokenFile?.remove();
      await server.close();
      await cleanupWorkspace(fixture);
    }
  });

  it("composes manager intent, command execution, owned create/patch, evidence, and eventual issuance observation", async () => {
    const fixture = await createWorkspace("m3-a8-provision");
    const server = await startApiServer(fixture.ownerId);
    let tokenFile;
    try {
      const token = await createControllerToken(fixture, [
        "certops:observations:write",
        "certops:provision:execute",
        "certops:events:write",
        "certops:evidence:write",
      ]);
      tokenFile = createTokenFile(token.plaintextToken);
      const firstKey = `m3-a8-${crypto.randomUUID()}`;
      const firstRequest = provisionRequest();
      const first = await fetchJson(
        `${server.apiUrl}/api/v1/workspaces/${fixture.workspaceId}/certops/provision-intents`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json", "Idempotency-Key": firstKey },
          body: JSON.stringify(firstRequest),
        },
      );
      const replay = await fetchJson(
        `${server.apiUrl}/api/v1/workspaces/${fixture.workspaceId}/certops/provision-intents`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json", "Idempotency-Key": firstKey },
          body: JSON.stringify(firstRequest),
        },
      );
      expect(first.status).to.equal(201);
      expect(replay.status).to.equal(200);
      expect(replay.body).to.deep.include({
        managedCertificateId: first.body.managedCertificateId,
        targetId: first.body.targetId,
        duplicate: true,
      });
      expect(replay.body.job.id).to.equal(first.body.job.id);

      const boundary = createKubernetesBoundary();
      const kubernetesClient = boundary.createClient({
        provisionEnabled: true,
        secretFallbackEnabled: true,
      });
      await kubernetesClient.start();
      const createRunner = () => {
        const commandClient = createControllerProvisioningCommandClient({
          apiTokenFile: tokenFile.file,
          apiUrl: server.apiUrl,
          sleep: async () => {},
        });
        return createProvisioningRunner({
          commandClient,
          intervalMs: 30_000,
          provisioner: createCertificateProvisioner({
            authorizeMutation: commandClient.authorizeMutation,
            client: kubernetesClient,
            clusterId: "cluster-a",
            watchNamespaces: ["certops"],
            workspaceId: fixture.workspaceId,
          }),
        });
      };
      const firstRunner = createRunner();
      await firstRunner.start({ trackWork: (work) => work });
      await eventually(async () => {
        const job = await TestUtils.execQuery(
          "SELECT status FROM certificate_jobs WHERE id = $1",
          [first.body.job.id],
        );
        expect(job.rows[0].status).to.equal("succeeded");
      });
      await firstRunner.stopAcceptingWork();
      await firstRunner.close();

      const beforeIssuance = await TestUtils.execQuery(
        "SELECT COUNT(*)::int AS count FROM certificate_instances WHERE managed_certificate_id = $1",
        [first.body.managedCertificateId],
      );
      expect(beforeIssuance.rows[0].count).to.equal(0);
      expect(boundary.calls.createCertificate).to.have.length(1);

      const secondRequest = provisionRequest({
        secretName: "m3-a8-tls-v2",
        dnsNames: ["rotated.m3-a8.example.test"],
      });
      const second = await fetchJson(
        `${server.apiUrl}/api/v1/workspaces/${fixture.workspaceId}/certops/provision-intents`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": `m3-a8-${crypto.randomUUID()}`,
          },
          body: JSON.stringify(secondRequest),
        },
      );
      expect(second.status).to.equal(201);
      expect(second.body.managedCertificateId).to.equal(first.body.managedCertificateId);
      const secondRunner = createRunner();
      await secondRunner.start({ trackWork: (work) => work });
      await eventually(async () => {
        const job = await TestUtils.execQuery(
          "SELECT status FROM certificate_jobs WHERE id = $1",
          [second.body.job.id],
        );
        expect(job.rows[0].status).to.equal("succeeded");
      });
      await secondRunner.stopAcceptingWork();
      await secondRunner.close();
      expect(boundary.calls.patchCertificate).to.have.length(1);

      const createdCertificate = boundary.getCertificate("certops", "m3-a8-cert");
      expect(createdCertificate).to.deep.include({
        apiVersion: "cert-manager.io/v1",
        kind: "Certificate",
      });
      expect(createdCertificate.spec).to.deep.equal({
        secretName: "m3-a8-tls-v2",
        dnsNames: ["rotated.m3-a8.example.test"],
        issuerRef: secondRequest.issuerRef,
      });
      expect(createdCertificate.metadata.labels).to.include({
        "app.kubernetes.io/managed-by": "tokentimer",
        "certops.tokentimer.io/workspace-id": fixture.workspaceId,
        "certops.tokentimer.io/cluster-id": "cluster-a",
        "certops.tokentimer.io/managed-certificate-id": first.body.managedCertificateId,
        "certops.tokentimer.io/last-intent-id": second.body.job.id,
      });

      boundary.setSecret("certops", "m3-a8-tls-v2", {
        data: {
          "tls.crt": ENCODED_PUBLIC_CERT,
          "tls.key": PRIVATE_SENTINEL,
          credential: "never-access-credential",
        },
      });
      boundary.setCertificate({
        ...createdCertificate,
        metadata: {
          ...createdCertificate.metadata,
          resourceVersion: "99",
        },
        status: certificateResource({
          certificateName: "m3-a8-cert",
          secretName: "m3-a8-tls-v2",
        }).status,
      });
      const reporter = createControllerObservationReporter({
        apiTokenFile: tokenFile.file,
        apiUrl: server.apiUrl,
      });
      const fallback = createTlsCertificateFallback({
        enabled: true,
        kubernetesClient,
      });
      const observer = createCertManagerObserver({
        client: kubernetesClient,
        clusterId: "cluster-a",
        enrichObservation: fallback.enrichObservation,
        observationHandler: (value) => reporter.report(value),
        watchNamespaces: ["certops"],
        workspaceId: fixture.workspaceId,
      });
      const runtime = createControllerRuntime({ kubernetesClient: observer, reporter });
      await runtime.start();
      await eventually(async () => {
        const result = await TestUtils.execQuery(
          "SELECT COUNT(*)::int AS count FROM certificate_instances WHERE managed_certificate_id = $1",
          [first.body.managedCertificateId],
        );
        expect(result.rows[0].count).to.equal(1);
      });
      expect(runtime.isReady()).to.equal(true);
      await runtime.stopAcceptingWork();
      expect(await runtime.waitForIdle(1_000)).to.equal(true);
      await runtime.close();

      const persisted = await TestUtils.execQuery(
        `SELECT
           COUNT(*) FILTER (WHERE j.source = 'controller_provisioning')::int AS controller_jobs,
           COUNT(*) FILTER (WHERE j.status = 'succeeded')::int AS succeeded_jobs,
           COUNT(DISTINCT j.id)::int AS distinct_jobs,
           COALESCE(STRING_AGG(j.payload::text, ' '), '') AS payloads,
           (SELECT COUNT(*)::int FROM certificate_executor_events e
              WHERE e.workspace_id = $1 AND e.job_id IN ($2, $3)) AS events,
           (SELECT COUNT(*)::int FROM certificate_evidence e
              WHERE e.workspace_id = $1 AND e.job_id IN ($2, $3)) AS job_evidence
         FROM certificate_jobs j
         WHERE j.workspace_id = $1 AND j.id IN ($2, $3)`,
        [fixture.workspaceId, first.body.job.id, second.body.job.id],
      );
      expect(persisted.rows[0]).to.include({
        controller_jobs: 2,
        succeeded_jobs: 2,
        distinct_jobs: 2,
        events: 4,
        job_evidence: 2,
      });
      expect(persisted.rows[0].payloads).to.not.include("apiVersion");
      expect(persisted.rows[0].payloads).to.not.include("tls.key");
      expect(persisted.rows[0].payloads).to.not.include("privateKey");
      expect(Object.keys(boundary.calls)).to.not.include.members([
        "createSecret",
        "patchSecret",
        "createCertificateRequest",
        "patchCertificateRequest",
        "deleteCertificate",
      ]);
    } finally {
      tokenFile?.remove();
      await server.close();
      await cleanupWorkspace(fixture);
    }
  });

  it("keeps key rejection ahead of scope and pause while passive reporting remains available", async () => {
    const fixture = await createWorkspace("m3-a8-pause");
    const server = await startApiServer(fixture.ownerId);
    try {
      const controllerToken = await createControllerToken(fixture, [
        "certops:observations:write",
        "certops:provision:execute",
        "certops:events:write",
        "certops:evidence:write",
      ]);
      const wrongScopeToken = await createApiToken({
        workspaceId: fixture.workspaceId,
        name: "M3-A8 wrong scope",
        scopes: ["certops:events:write", "certops:evidence:write"],
        createdBy: fixture.ownerId,
      });
      const intent = await fetchJson(
        `${server.apiUrl}/api/v1/workspaces/${fixture.workspaceId}/certops/provision-intents`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": `pause-${crypto.randomUUID()}`,
          },
          body: JSON.stringify(provisionRequest({ certificateName: "paused-cert" })),
        },
      );
      expect(intent.status).to.equal(201);
      await TestUtils.execQuery(
        "UPDATE workspaces SET certops_paused = TRUE WHERE id = $1",
        [fixture.workspaceId],
      );

      const blockedIntent = await fetchJson(
        `${server.apiUrl}/api/v1/workspaces/${fixture.workspaceId}/certops/provision-intents`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": `pause-${crypto.randomUUID()}`,
          },
          body: JSON.stringify(provisionRequest({ certificateName: "blocked-cert" })),
        },
      );
      expect(blockedIntent.status).to.equal(409);
      expect(blockedIntent.body.code).to.equal("CERTOPS_WORKSPACE_PAUSED");

      const blockedCommand = await fetchJson(
        `${server.apiUrl}/api/v1/certops/executor/provisioning-commands/next`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${controllerToken.plaintextToken}`,
            "Content-Type": "application/json",
          },
          body: "{}",
        },
      );
      expect(blockedCommand.status).to.equal(409);
      expect(blockedCommand.body.code).to.equal("CERTOPS_WORKSPACE_PAUSED");

      const passiveObservation = observation({
        workspaceId: fixture.workspaceId,
        certificateName: "paused-observation",
        fingerprint: "a".repeat(64),
        resourceVersion: "1",
        uid: crypto.randomUUID(),
      });
      const observationResponse = await fetchJson(
        `${server.apiUrl}/api/v1/certops/executor/observations`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${controllerToken.plaintextToken}`,
            "Content-Type": "application/json",
            "Idempotency-Key": "b".repeat(64),
          },
          body: JSON.stringify({
            ...passiveObservation,
            observationId: crypto.randomUUID(),
            idempotencyKey: "b".repeat(64),
          }),
        },
      );
      expect(observationResponse.status).to.equal(201);

      const progress = await fetchJson(
        `${server.apiUrl}/api/v1/certops/jobs/${intent.body.job.id}/events`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${controllerToken.plaintextToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            schemaVersion: 1,
            eventId: `pause-progress-${crypto.randomUUID()}`,
            workspaceId: fixture.workspaceId,
            jobId: intent.body.job.id,
            eventType: "job.progress",
            status: "running",
            occurredAt: "2026-07-21T10:05:00.000Z",
            message: "Public controller status remains reportable while paused",
          }),
        },
      );
      expect(progress.status).to.equal(202);

      const redacted = await fetchJson(
        `${server.apiUrl}/api/v1/certops/jobs/${intent.body.job.id}/evidence`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${controllerToken.plaintextToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            schemaVersion: 1,
            eventId: `pause-evidence-${crypto.randomUUID()}`,
            workspaceId: fixture.workspaceId,
            jobId: intent.body.job.id,
            eventType: "evidence.attached",
            status: "accepted",
            occurredAt: "2026-07-21T10:06:00.000Z",
            evidence: [{
              schemaVersion: 1,
              evidenceId: `pause-evidence-item-${crypto.randomUUID()}`,
              eventType: "deployment.checked",
              source: "executor",
              observedAt: "2026-07-21T10:06:00.000Z",
              output: "password=generic-secret-value",
            }],
          }),
        },
      );
      expect(redacted.status).to.equal(202);
      expect(redacted.body.redactionApplied).to.equal(true);

      const maliciousObservation = await fetchJson(
        `${server.apiUrl}/api/v1/certops/executor/observations`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${wrongScopeToken.plaintextToken}`,
            "Content-Type": "application/json",
            "Idempotency-Key": "c".repeat(64),
          },
          body: JSON.stringify({
            ...passiveObservation,
            observationId: crypto.randomUUID(),
            idempotencyKey: "c".repeat(64),
            conditions: [{ type: "Ready", status: "False", message: PRIVATE_SENTINEL }],
            publicCertificate: { certificatePem: PRIVATE_SENTINEL },
          }),
        },
      );
      expect(maliciousObservation.status).to.equal(422);
      expect(maliciousObservation.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");

      const maliciousIntent = await fetchJson(
        `${server.apiUrl}/api/v1/workspaces/${fixture.workspaceId}/certops/provision-intents`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": `malicious-${crypto.randomUUID()}`,
          },
          body: JSON.stringify({ ...provisionRequest(), privateKey: PRIVATE_SENTINEL }),
        },
      );
      expect(maliciousIntent.status).to.equal(422);
      expect(maliciousIntent.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");

      const maliciousCommand = await fetchJson(
        `${server.apiUrl}/api/v1/certops/executor/provisioning-commands/next`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${wrongScopeToken.plaintextToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ command: PRIVATE_SENTINEL }),
        },
      );
      expect(maliciousCommand.status).to.equal(422);
      expect(maliciousCommand.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");

      const maliciousEvent = await fetchJson(
        `${server.apiUrl}/api/v1/certops/jobs/${intent.body.job.id}/events`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${wrongScopeToken.plaintextToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            schemaVersion: 1,
            eventId: `malicious-${crypto.randomUUID()}`,
            workspaceId: fixture.workspaceId,
            jobId: intent.body.job.id,
            eventType: "job.progress",
            status: "running",
            occurredAt: "2026-07-21T10:07:00.000Z",
            metadata: [{ name: "public-note", value: PRIVATE_SENTINEL }],
          }),
        },
      );
      expect(maliciousEvent.status).to.equal(422);
      expect(maliciousEvent.body.code).to.equal("PRIVATE_KEY_MATERIAL_REJECTED");

      const persisted = await TestUtils.execQuery(
        `SELECT
           (SELECT COUNT(*)::int FROM audit_events
              WHERE workspace_id = $1 AND action = 'CERTOPS_KEY_MATERIAL_REJECTED') AS rejection_audits,
           (SELECT COUNT(*)::int FROM certificate_controller_observations
              WHERE workspace_id = $1 AND idempotency_key = $2) AS rejected_observations,
           COALESCE((SELECT STRING_AGG(metadata::text, ' ') FROM audit_events WHERE workspace_id = $1), '') AS audits,
           COALESCE((SELECT STRING_AGG(metadata::text || ' ' || COALESCE(redacted_output, ''), ' ')
              FROM certificate_evidence WHERE workspace_id = $1), '') AS evidence`,
        [fixture.workspaceId, "c".repeat(64)],
      );
      expect(persisted.rows[0].rejection_audits).to.be.at.least(3);
      expect(persisted.rows[0].rejected_observations).to.equal(0);
      expect(persisted.rows[0].audits).to.not.include("never-cross-the-controller-boundary");
      expect(persisted.rows[0].evidence).to.not.include("generic-secret-value");
      expect(persisted.rows[0].evidence).to.include("[REDACTED]");
      expect(persisted.rows[0].evidence).to.not.include("never-cross-the-controller-boundary");
    } finally {
      await server.close();
      await cleanupWorkspace(fixture);
    }
  });
});
