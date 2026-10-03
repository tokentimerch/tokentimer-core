"use strict";

const assert = require("node:assert/strict");
const { randomBytes, randomUUID } = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const https = require("node:https");
const { spawn, spawnSync } = require("node:child_process");
const { pool } = require("../../apps/api/db/database");
const {
  acknowledgeCsrNames, cancelCsrWorkflow, confirmCsrInstallation, createCsrWorkflow,
  getCsrWorkflow, importSignedCertificate, recordCsrObservation,
} = require("../../apps/api/services/certops/csrWorkflow");
const { transferTokenAssociations } = require("../../apps/api/services/workspaceTokenTransfer");
const { normalizeControllerObservation, persistControllerObservation } =
  require("../../apps/api/services/certops/controllerObservations");

function opensslBinary() {
  const candidates = ["openssl", "C:\\Program Files\\Git\\usr\\bin\\openssl.exe"];
  for (const candidate of candidates) {
    if (spawnSync(candidate, ["version"], { encoding: "utf8" }).status === 0) return candidate;
  }
  throw new Error("OpenSSL is required for CSR integration fixtures");
}

function generatePublicMaterial(dir, label, days = 365) {
  const openssl = opensslBinary();
  const key = path.join(dir, `${label}.key`);
  const csr = path.join(dir, `${label}.csr`);
  const cert = path.join(dir, `${label}.crt`);
  const ext = path.join(dir, `${label}.cnf`);
  fs.writeFileSync(ext, "[v3_req]\nsubjectAltName=DNS:issued.example.test\n");
  for (const args of [
    ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key],
    ["req", "-new", "-key", key, "-subj", "/CN=requested.example.test", "-addext", "subjectAltName=DNS:requested.example.test", "-out", csr],
    ["x509", "-req", "-in", csr, "-signkey", key, "-days", String(days), "-extfile", ext, "-extensions", "v3_req", "-out", cert],
  ]) {
    const result = spawnSync(openssl, args, { encoding: "utf8" });
    assert.equal(result.status, 0, `OpenSSL failed: ${result.stderr}`);
  }
  return { csrPem: fs.readFileSync(csr, "utf8"), certificatePem: fs.readFileSync(cert, "utf8") };
}

function runEndpointWorker() {
  return new Promise((resolve, reject) => {
    const worker = spawn(process.execPath, ["src/endpoint-check-worker.js"], {
      cwd: path.resolve(__dirname, "../../apps/worker"),
      env: { ...process.env, NODE_ENV: "test", CERTOPS_ENABLED: "true" },
    });
    let output = "";
    worker.stdout.on("data", (chunk) => { output += chunk; });
    worker.stderr.on("data", (chunk) => { output += chunk; });
    worker.once("error", reject);
    worker.once("close", (code) => code === 0 ? resolve() : reject(new Error(`Endpoint worker exited ${code}: ${output.slice(-4000)}`)));
  });
}

function serveCertificate(key, cert) {
  return new Promise((resolve, reject) => {
    const server = https.createServer({ key, cert }, (_request, response) => response.end("ok"));
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve({
      server,
      url: `https://127.0.0.1:${server.address().port}`,
    }));
  });
}

describe("operator supplied CSR workflow", function () {
  this.timeout(120000);
  let workspaceId;
  let userId;
  let fixtureDir;
  let material;

  before(async () => {
    fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), "certops-csr-workflow-"));
    material = generatePublicMaterial(fixtureDir, "first");
    const user = await pool.query(
      "INSERT INTO users (email, display_name, password_hash) VALUES ($1, 'CSR Test', 'test') RETURNING id",
      [`csr-${randomUUID()}@example.test`],
    );
    userId = user.rows[0].id;
    workspaceId = randomUUID();
    await pool.query("INSERT INTO workspaces (id, name, created_by) VALUES ($1, 'CSR Test', $2)", [workspaceId, userId]);
  });

  after(() => {
    if (fixtureDir) fs.rmSync(fixtureDir, { recursive: true, force: true });
  });

  it("keeps observations factual while name review blocks promotion", async () => {
    const input = { workspaceId, actorUserId: userId, csrPem: material.csrPem,
      target: { name: "CSR test host", type: "host" } };
    const created = await createCsrWorkflow(input);
    const duplicate = await createCsrWorkflow(input);
    assert.equal(duplicate.id, created.id);
    const signed = await importSignedCertificate({ workspaceId, workflowId: created.id,
      actorUserId: userId, certificatePem: material.certificatePem });
    assert.equal(signed.status, "signed_pending_install");
    assert.equal(signed.namesChanged, true);
    const provisional = await pool.query("SELECT status, token_id FROM managed_certificates WHERE id = $1", [signed.managedCertificateId]);
    assert.equal(provisional.rows[0].status, "provisioning");
    assert.equal(provisional.rows[0].token_id, null);

    const client = await pool.connect();
    let instanceId;
    try {
      await client.query("BEGIN");
      const instance = await client.query(
        `INSERT INTO certificate_instances (workspace_id, managed_certificate_id, target_id,
          source, observed_fingerprint_sha256, observed_at)
         VALUES ($1, $2, $3, 'api', $4, NOW()) RETURNING id`,
        [workspaceId, signed.managedCertificateId, signed.targetId, signed.signedFingerprintSha256],
      );
      instanceId = instance.rows[0].id;
      await recordCsrObservation(client, { workspaceId, targetId: signed.targetId,
        fingerprintSha256: signed.signedFingerprintSha256, instanceId });
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    const pending = await getCsrWorkflow({ workspaceId, workflowId: created.id });
    assert.equal(pending.status, "signed_pending_install");
    assert.equal(pending.observedInstanceId, instanceId);
    assert.equal(pending.confirmedAt, null);
    const completed = await acknowledgeCsrNames({ workspaceId, workflowId: created.id, actorUserId: userId });
    assert.equal(completed.status, "completed");
    assert.equal(completed.confirmedAt, null);
    assert.equal(completed.confirmationMethod, null);
    const promoted = await pool.query("SELECT status, token_id FROM managed_certificates WHERE id = $1", [signed.managedCertificateId]);
    assert.equal(promoted.rows[0].status, "active");
    assert.ok(promoted.rows[0].token_id);
  });

  it("observes a certificate actually served by a host before promoting the CSR", async () => {
    const previousMaterial = generatePublicMaterial(fixtureDir, "live-host-previous");
    const hostMaterial = generatePublicMaterial(fixtureDir, "live-host");
    const parsed = require("../../apps/api/services/certops/parser").parsePublicCertificateMaterial(hostMaterial.certificatePem)[0];
    const { server, url } = await serveCertificate(
      fs.readFileSync(path.join(fixtureDir, "live-host-previous.key"), "utf8"),
      previousMaterial.certificatePem,
    );
    try {
      const monitor = await pool.query(
        `INSERT INTO domain_monitors (workspace_id, url, health_check_enabled, check_interval, created_by)
         VALUES ($1, $2, FALSE, '1min', $3) RETURNING id`,
        [workspaceId, url, userId],
      );
      const monitorId = monitor.rows[0].id;
      const target = await pool.query(
        `INSERT INTO certificate_targets (workspace_id, domain_monitor_id, name, target_type, source, source_ref)
         VALUES ($1, $2, 'Live HTTPS host', 'endpoint', 'endpoint_monitor', $3) RETURNING id`,
        [workspaceId, monitorId, monitorId],
      );
      const workflow = await createCsrWorkflow({ workspaceId, actorUserId: userId,
        csrPem: hostMaterial.csrPem, targetId: target.rows[0].id });
      const signed = await importSignedCertificate({ workspaceId, workflowId: workflow.id,
        actorUserId: userId, certificatePem: hostMaterial.certificatePem });
      assert.equal(signed.status, "signed_pending_install");
      assert.equal(signed.namesChanged, true);
      const before = await pool.query(
        "SELECT count(*)::int AS count FROM certificate_instances WHERE workspace_id = $1 AND target_id = $2",
        [workspaceId, target.rows[0].id],
      );
      assert.equal(before.rows[0].count, 0);

      // The operator installs the signed leaf on the host after import.
      server.setSecureContext({
        key: fs.readFileSync(path.join(fixtureDir, "live-host.key"), "utf8"),
        cert: hostMaterial.certificatePem,
      });
      await runEndpointWorker();

      const observed = await pool.query(
        `SELECT ci.id, ci.managed_certificate_id, ci.observed_fingerprint_sha256,
                ci.observed_at, dm.ssl_fingerprint
           FROM certificate_instances ci
           JOIN domain_monitors dm ON dm.id = ci.domain_monitor_id
          WHERE ci.workspace_id = $1 AND ci.target_id = $2`,
        [workspaceId, target.rows[0].id],
      );
      assert.equal(observed.rows.length, 1);
      assert.equal(observed.rows[0].observed_fingerprint_sha256, parsed.fingerprintSha256);
      assert.ok(observed.rows[0].observed_at);
      assert.ok(observed.rows[0].ssl_fingerprint);
      const pending = await getCsrWorkflow({ workspaceId, workflowId: workflow.id });
      assert.equal(pending.status, "signed_pending_install");
      assert.equal(pending.observedInstanceId, observed.rows[0].id);
      assert.equal(pending.confirmedAt, null);

      const completed = await acknowledgeCsrNames({ workspaceId, workflowId: workflow.id, actorUserId: userId });
      assert.equal(completed.status, "completed");
      assert.equal(completed.confirmationMethod, null);
      const promoted = await pool.query(
        "SELECT id, status, fingerprint_sha256, token_id FROM managed_certificates WHERE id = $1",
        [completed.managedCertificateId],
      );
      assert.equal(promoted.rows[0].status, "active");
      assert.equal(promoted.rows[0].fingerprint_sha256, parsed.fingerprintSha256);
      assert.equal(observed.rows[0].managed_certificate_id, promoted.rows[0].id);
      assert.ok(promoted.rows[0].token_id);
    } finally {
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("keeps a monitor-backed certificate unchanged until CSR review, then active on re-observation", async () => {
    const previous = generatePublicMaterial(fixtureDir, "monitored-previous", 100);
    const replacement = generatePublicMaterial(fixtureDir, "monitored-replacement");
    const parser = require("../../apps/api/services/certops/parser");
    const oldLeaf = parser.parsePublicCertificateMaterial(previous.certificatePem)[0];
    const newLeaf = parser.parsePublicCertificateMaterial(replacement.certificatePem)[0];
    const { server, url } = await serveCertificate(
      fs.readFileSync(path.join(fixtureDir, "monitored-previous.key"), "utf8"), previous.certificatePem,
    );
    try {
      const token = await pool.query(
        `INSERT INTO tokens (workspace_id, name, expiration, type, category)
         VALUES ($1, 'Monitored CSR rotation', $2, 'ssl_cert', 'cert') RETURNING id`,
        [workspaceId, new Date(oldLeaf.notAfter).toISOString().slice(0, 10)],
      );
      const monitor = await pool.query(
        `INSERT INTO domain_monitors (workspace_id, url, token_id, health_check_enabled, check_interval, created_by)
         VALUES ($1, $2, $3, FALSE, '1min', $4) RETURNING id`,
        [workspaceId, url, token.rows[0].id, userId],
      );
      const monitorId = monitor.rows[0].id;
      const target = await pool.query(
        `INSERT INTO certificate_targets (workspace_id, domain_monitor_id, token_id, name, target_type, source, source_ref)
         VALUES ($1, $2, $3, 'Monitored CSR target', 'endpoint', 'endpoint_monitor', $4) RETURNING id`,
        [workspaceId, monitorId, token.rows[0].id, monitorId],
      );
      const current = await pool.query(
        `INSERT INTO managed_certificates (workspace_id, token_id, status, source, source_ref,
          name, certificate_pem, fingerprint_sha256, spki_fingerprint_sha256, not_after)
         VALUES ($1, $2, 'active', 'endpoint_monitor', $3, 'Current monitored leaf', $4, $5, $6, $7)
         RETURNING id`,
        [workspaceId, token.rows[0].id, monitorId, oldLeaf.certificatePem,
          oldLeaf.fingerprintSha256, oldLeaf.spkiFingerprintSha256, oldLeaf.notAfter],
      );
      const workflow = await createCsrWorkflow({ workspaceId, actorUserId: userId,
        existingCertificateId: current.rows[0].id, csrPem: replacement.csrPem, targetId: target.rows[0].id });
      await importSignedCertificate({ workspaceId, workflowId: workflow.id,
        actorUserId: userId, certificatePem: replacement.certificatePem });
      server.setSecureContext({ key: fs.readFileSync(path.join(fixtureDir, "monitored-replacement.key"), "utf8"),
        cert: replacement.certificatePem });
      await runEndpointWorker();

      const pending = await getCsrWorkflow({ workspaceId, workflowId: workflow.id });
      const beforeReview = await pool.query(
        "SELECT status, fingerprint_sha256, certificate_pem, not_after FROM managed_certificates WHERE id = $1",
        [current.rows[0].id],
      );
      const observed = await pool.query(
        "SELECT id, observed_fingerprint_sha256 FROM certificate_instances WHERE target_id = $1",
        [target.rows[0].id],
      );
      assert.equal(pending.status, "signed_pending_install");
      assert.equal(observed.rows.length, 1);
      assert.equal(observed.rows[0].observed_fingerprint_sha256, newLeaf.fingerprintSha256);
      assert.equal(pending.observedInstanceId, observed.rows[0].id);
      assert.equal(beforeReview.rows[0].status, "active");
      assert.equal(beforeReview.rows[0].fingerprint_sha256, oldLeaf.fingerprintSha256);
      assert.equal(beforeReview.rows[0].certificate_pem, oldLeaf.certificatePem);
      assert.equal(new Date(beforeReview.rows[0].not_after).toISOString(), new Date(oldLeaf.notAfter).toISOString());
      const tokenBeforeReview = await pool.query("SELECT expiration::text AS expiration FROM tokens WHERE id = $1", [token.rows[0].id]);
      assert.equal(tokenBeforeReview.rows[0].expiration,
        new Date(oldLeaf.notAfter).toISOString().slice(0, 10));

      await acknowledgeCsrNames({ workspaceId, workflowId: workflow.id, actorUserId: userId });
      await pool.query("UPDATE domain_monitors SET last_health_check_at = NOW() - INTERVAL '2 minutes' WHERE id = $1", [monitorId]);
      await runEndpointWorker();
      const after = await pool.query("SELECT status, fingerprint_sha256 FROM managed_certificates WHERE id = $1", [current.rows[0].id]);
      assert.equal(after.rows[0].status, "active");
      assert.equal(after.rows[0].fingerprint_sha256, newLeaf.fingerprintSha256);
    } finally {
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("records a controller deployment without changing an existing certificate before name review", async () => {
    const previous = generatePublicMaterial(fixtureDir, "controller-previous", 100);
    const replacement = generatePublicMaterial(fixtureDir, "controller-replacement");
    const parser = require("../../apps/api/services/certops/parser");
    const oldLeaf = parser.parsePublicCertificateMaterial(previous.certificatePem)[0];
    const newLeaf = parser.parsePublicCertificateMaterial(replacement.certificatePem)[0];
    const clusterId = `csr-${randomUUID()}`;
    const namespace = "certops";
    const certificateName = "csr-rotation";
    const secretName = "csr-rotation-tls";
    const current = await pool.query(
      `INSERT INTO managed_certificates (workspace_id, status, source, source_ref, name,
        certificate_pem, fingerprint_sha256, spki_fingerprint_sha256, not_after)
       VALUES ($1, 'active', 'cert_manager', $2, 'Controller current leaf', $3, $4, $5, $6) RETURNING id`,
      [workspaceId, `${clusterId}/${namespace}/${certificateName}`, oldLeaf.certificatePem,
        oldLeaf.fingerprintSha256, oldLeaf.spkiFingerprintSha256, oldLeaf.notAfter],
    );
    const target = await pool.query(
      `INSERT INTO certificate_targets (workspace_id, name, target_type, source, source_ref)
       VALUES ($1, 'Controller CSR target', 'kubernetes-secret', 'cert_manager', $2) RETURNING id`,
      [workspaceId, `${clusterId}/${namespace}/${secretName}`],
    );
    const workflow = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      existingCertificateId: current.rows[0].id, csrPem: replacement.csrPem,
      targetId: target.rows[0].id });
    await importSignedCertificate({ workspaceId, workflowId: workflow.id,
      actorUserId: userId, certificatePem: replacement.certificatePem });
    const tokensBefore = await pool.query("SELECT count(*)::int AS count FROM tokens WHERE workspace_id = $1", [workspaceId]);
    const normalized = normalizeControllerObservation({
      schemaVersion: 1, observationId: randomUUID(),
      idempotencyKey: randomBytes(32).toString("hex"), workspaceId,
      clusterId, namespace, certificateName, certificateUid: randomUUID(),
      issuerRef: { name: "issuer" }, secretName, certificateRequestRef: null,
      dnsNames: ["issued.example.test"], conditions: [{ type: "Ready", status: "True" }],
      ready: true, observationSource: "cert_manager", observedAt: new Date().toISOString(),
      notBefore: new Date(newLeaf.notBefore).toISOString(),
      notAfter: new Date(newLeaf.notAfter).toISOString(),
      publicCertificate: { certificatePem: newLeaf.certificatePem,
        fingerprintSha256: newLeaf.fingerprintSha256, subject: newLeaf.subject,
        issuer: newLeaf.issuer, serialNumber: newLeaf.serialNumber,
        subjectAltNames: newLeaf.subjectAltNames },
    });
    await persistControllerObservation({ observation: normalized.observation,
      redaction: normalized.redaction });
    const pending = await getCsrWorkflow({ workspaceId, workflowId: workflow.id });
    const unchanged = await pool.query(
      "SELECT status, fingerprint_sha256, certificate_pem, not_after FROM managed_certificates WHERE id = $1",
      [current.rows[0].id],
    );
    const instance = await pool.query(
      "SELECT id, managed_certificate_id, observed_fingerprint_sha256 FROM certificate_instances WHERE target_id = $1",
      [target.rows[0].id],
    );
    assert.equal(pending.status, "signed_pending_install");
    assert.equal(instance.rows.length, 1);
    assert.equal(instance.rows[0].managed_certificate_id, current.rows[0].id);
    assert.equal(instance.rows[0].observed_fingerprint_sha256, newLeaf.fingerprintSha256);
    assert.equal(pending.observedInstanceId, instance.rows[0].id);
    assert.equal(unchanged.rows[0].status, "active");
    assert.equal(unchanged.rows[0].fingerprint_sha256, oldLeaf.fingerprintSha256);
    assert.equal(unchanged.rows[0].certificate_pem, oldLeaf.certificatePem);
    assert.equal(new Date(unchanged.rows[0].not_after).toISOString(), new Date(oldLeaf.notAfter).toISOString());
    const tokensAfter = await pool.query("SELECT count(*)::int AS count FROM tokens WHERE workspace_id = $1", [workspaceId]);
    assert.equal(tokensAfter.rows[0].count, tokensBefore.rows[0].count);
    const completed = await acknowledgeCsrNames({ workspaceId, workflowId: workflow.id, actorUserId: userId });
    assert.equal(completed.status, "completed");
    const promoted = await pool.query("SELECT fingerprint_sha256, token_id FROM managed_certificates WHERE id = $1", [current.rows[0].id]);
    assert.equal(promoted.rows[0].fingerprint_sha256, newLeaf.fingerprintSha256);
    assert.ok(promoted.rows[0].token_id);
  });

  it("restarts a cancelled CSR and releases its exclusively owned provisioning certificate", async () => {
    const retry = generatePublicMaterial(fixtureDir, "cancel-retry");
    const created = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: retry.csrPem, target: { name: "Cancelled CSR target", type: "host" } });
    const signed = await importSignedCertificate({ workspaceId, workflowId: created.id,
      actorUserId: userId, certificatePem: retry.certificatePem });
    const cancelled = await cancelCsrWorkflow({ workspaceId, workflowId: created.id, actorUserId: userId });
    assert.equal(cancelled.status, "cancelled");
    const provisional = await pool.query("SELECT 1 FROM managed_certificates WHERE id = $1", [signed.managedCertificateId]);
    assert.equal(provisional.rows.length, 0);
    const restarted = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: retry.csrPem, targetId: created.targetId });
    assert.equal(restarted.id, created.id);
    assert.equal(restarted.status, "pending_signature");
    assert.equal(restarted.managedCertificateId, null);
  });

  it("keeps a shared provisioning certificate until the last CSR is cancelled", async () => {
    const shared = generatePublicMaterial(fixtureDir, "cancel-shared");
    const first = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: shared.csrPem, target: { name: "Shared cancellation A", type: "host" } });
    const second = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: shared.csrPem, target: { name: "Shared cancellation B", type: "host" } });
    const signedFirst = await importSignedCertificate({ workspaceId, workflowId: first.id,
      actorUserId: userId, certificatePem: shared.certificatePem });
    const signedSecond = await importSignedCertificate({ workspaceId, workflowId: second.id,
      actorUserId: userId, certificatePem: shared.certificatePem });
    assert.equal(signedSecond.managedCertificateId, signedFirst.managedCertificateId);
    await cancelCsrWorkflow({ workspaceId, workflowId: first.id, actorUserId: userId });
    const stillShared = await pool.query("SELECT status FROM managed_certificates WHERE id = $1", [signedFirst.managedCertificateId]);
    assert.equal(stillShared.rows[0].status, "provisioning");
    await cancelCsrWorkflow({ workspaceId, workflowId: second.id, actorUserId: userId });
    const removed = await pool.query("SELECT 1 FROM managed_certificates WHERE id = $1", [signedFirst.managedCertificateId]);
    assert.equal(removed.rows.length, 0);

    const third = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: shared.csrPem, target: { name: "Concurrent cancellation C", type: "host" } });
    const fourth = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: shared.csrPem, target: { name: "Concurrent cancellation D", type: "host" } });
    const signedThird = await importSignedCertificate({ workspaceId, workflowId: third.id,
      actorUserId: userId, certificatePem: shared.certificatePem });
    await importSignedCertificate({ workspaceId, workflowId: fourth.id,
      actorUserId: userId, certificatePem: shared.certificatePem });
    await Promise.all([third, fourth].map((workflow) => cancelCsrWorkflow({
      workspaceId, workflowId: workflow.id, actorUserId: userId,
    })));
    const removedAfterRace = await pool.query("SELECT 1 FROM managed_certificates WHERE id = $1", [signedThird.managedCertificateId]);
    assert.equal(removedAfterRace.rows.length, 0);
  });

  it("transfers a token's CSR workflow with its target and managed certificate", async () => {
    const transfer = generatePublicMaterial(fixtureDir, "transfer-csr");
    const leaf = require("../../apps/api/services/certops/parser").parsePublicCertificateMaterial(transfer.certificatePem)[0];
    const destinationId = randomUUID();
    await pool.query("INSERT INTO workspaces (id, name, created_by) VALUES ($1, 'CSR destination', $2)", [destinationId, userId]);
    const token = await pool.query(
      `INSERT INTO tokens (workspace_id, name, expiration, type, category)
       VALUES ($1, 'CSR transfer token', $2, 'ssl_cert', 'cert') RETURNING id`,
      [workspaceId, new Date(leaf.notAfter).toISOString().slice(0, 10)],
    );
    const cert = await pool.query(
      `INSERT INTO managed_certificates (workspace_id, token_id, status, source, name, certificate_pem,
        fingerprint_sha256, spki_fingerprint_sha256, not_after)
       VALUES ($1, $2, 'active', 'api', 'Transfer certificate', $3, $4, $5, $6) RETURNING id`,
      [workspaceId, token.rows[0].id, leaf.certificatePem, leaf.fingerprintSha256,
        leaf.spkiFingerprintSha256, leaf.notAfter],
    );
    const target = await pool.query(
      `INSERT INTO certificate_targets (workspace_id, token_id, name, target_type, source, source_ref)
       VALUES ($1, $2, 'Transfer target', 'host', 'api', $3) RETURNING id`,
      [workspaceId, token.rows[0].id, `transfer:${randomUUID()}`],
    );
    const workflow = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      existingCertificateId: cert.rows[0].id, csrPem: transfer.csrPem, targetId: target.rows[0].id });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await transferTokenAssociations(client, { tokenIds: [token.rows[0].id],
        fromWorkspaceId: workspaceId, toWorkspaceId: destinationId, targetOwnerId: userId });
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    const moved = await getCsrWorkflow({ workspaceId: destinationId, workflowId: workflow.id });
    assert.equal(moved.targetId, target.rows[0].id);
    assert.equal(moved.existingCertificateId, cert.rows[0].id);
    const old = await pool.query("SELECT 1 FROM certificate_csr_workflows WHERE workspace_id = $1 AND id = $2", [workspaceId, workflow.id]);
    assert.equal(old.rows.length, 0);
  });

  it("transfers a signed CSR and its tokenless provisioning certificate with a monitored target", async () => {
    const material = generatePublicMaterial(fixtureDir, "transfer-provisioning");
    const destinationId = randomUUID();
    await pool.query("INSERT INTO workspaces (id, name, created_by) VALUES ($1, 'Provisioning destination', $2)", [destinationId, userId]);
    const token = await pool.query(
      `INSERT INTO tokens (workspace_id, name, expiration, type, category)
       VALUES ($1, 'CSR monitor transfer', '2099-12-31', 'ssl_cert', 'cert') RETURNING id`,
      [workspaceId],
    );
    const monitor = await pool.query(
      `INSERT INTO domain_monitors (workspace_id, url, token_id, created_by)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [workspaceId, `https://csr-transfer-${randomUUID()}.example.test`, token.rows[0].id, userId],
    );
    const target = await pool.query(
      `INSERT INTO certificate_targets (workspace_id, domain_monitor_id, token_id, name, target_type, source, source_ref)
       VALUES ($1, $2, $3, 'Provisioning target', 'endpoint', 'endpoint_monitor', $4) RETURNING id`,
      [workspaceId, monitor.rows[0].id, token.rows[0].id, monitor.rows[0].id],
    );
    const workflow = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: material.csrPem, targetId: target.rows[0].id });
    const signed = await importSignedCertificate({ workspaceId, workflowId: workflow.id,
      actorUserId: userId, certificatePem: material.certificatePem });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await transferTokenAssociations(client, { tokenIds: [token.rows[0].id],
        fromWorkspaceId: workspaceId, toWorkspaceId: destinationId, targetOwnerId: userId });
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    const moved = await getCsrWorkflow({ workspaceId: destinationId, workflowId: workflow.id });
    assert.equal(moved.status, "signed_pending_install");
    assert.equal(moved.managedCertificateId, signed.managedCertificateId);
    const provisional = await pool.query("SELECT workspace_id, token_id, status FROM managed_certificates WHERE id = $1", [signed.managedCertificateId]);
    assert.equal(provisional.rows[0].workspace_id, destinationId);
    assert.equal(provisional.rows[0].token_id, null);
    assert.equal(provisional.rows[0].status, "provisioning");
  });

  it("transfers a completed CSR with its observed instance", async () => {
    const material = generatePublicMaterial(fixtureDir, "transfer-observed");
    const leaf = require("../../apps/api/services/certops/parser").parsePublicCertificateMaterial(material.certificatePem)[0];
    const destinationId = randomUUID();
    await pool.query("INSERT INTO workspaces (id, name, created_by) VALUES ($1, 'Observed destination', $2)", [destinationId, userId]);
    const workflow = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: material.csrPem, target: { name: "Observed transfer target", type: "host" } });
    const signed = await importSignedCertificate({ workspaceId, workflowId: workflow.id,
      actorUserId: userId, certificatePem: material.certificatePem });
    await acknowledgeCsrNames({ workspaceId, workflowId: workflow.id, actorUserId: userId });
    const client = await pool.connect();
    let instanceId;
    try {
      await client.query("BEGIN");
      const instance = await client.query(
        `INSERT INTO certificate_instances (workspace_id, managed_certificate_id, target_id,
          source, observed_fingerprint_sha256, observed_at)
         VALUES ($1, $2, $3, 'api', $4, NOW()) RETURNING id`,
        [workspaceId, signed.managedCertificateId, signed.targetId, leaf.fingerprintSha256],
      );
      instanceId = instance.rows[0].id;
      await recordCsrObservation(client, { workspaceId, targetId: signed.targetId,
        fingerprintSha256: leaf.fingerprintSha256, instanceId });
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    const completed = await getCsrWorkflow({ workspaceId, workflowId: workflow.id });
    assert.equal(completed.status, "completed");
    const token = await pool.query("SELECT token_id FROM managed_certificates WHERE id = $1", [completed.managedCertificateId]);
    const target = await pool.query("SELECT token_id FROM certificate_targets WHERE id = $1", [completed.targetId]);
    assert.equal(target.rows[0].token_id, null);
    await pool.query("UPDATE certificate_targets SET token_id = $1 WHERE id = $2", [token.rows[0].token_id, completed.targetId]);
    const transferClient = await pool.connect();
    try {
      await transferClient.query("BEGIN");
      await transferTokenAssociations(transferClient, { tokenIds: [token.rows[0].token_id],
        fromWorkspaceId: workspaceId, toWorkspaceId: destinationId, targetOwnerId: userId });
      await transferClient.query("COMMIT");
    } catch (error) {
      await transferClient.query("ROLLBACK");
      throw error;
    } finally {
      transferClient.release();
    }
    const moved = await getCsrWorkflow({ workspaceId: destinationId, workflowId: workflow.id });
    assert.equal(moved.observedInstanceId, instanceId);
    const observed = await pool.query("SELECT workspace_id FROM certificate_instances WHERE id = $1", [instanceId]);
    assert.equal(observed.rows[0].workspace_id, destinationId);
  });

  it("rejects private PEM before creating a workflow or target", async () => {
    const before = await pool.query("SELECT count(*)::int AS count FROM certificate_csr_workflows WHERE workspace_id = $1", [workspaceId]);
    const privatePem = fs.readFileSync(path.join(fixtureDir, "first.key"), "utf8");
    await assert.rejects(createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: `${material.csrPem}\n${privatePem}`,
      target: { name: "Rejected private target", type: "host" } }),
    { code: "PRIVATE_KEY_MATERIAL_REJECTED", status: 422 });
    const after = await pool.query("SELECT count(*)::int AS count FROM certificate_csr_workflows WHERE workspace_id = $1", [workspaceId]);
    assert.equal(after.rows[0].count, before.rows[0].count);
    const target = await pool.query("SELECT 1 FROM certificate_targets WHERE workspace_id = $1 AND name = $2",
      [workspaceId, "Rejected private target"]);
    assert.equal(target.rows.length, 0);
  });

  it("rejects retired fingerprints and records manual attestation without an instance", async () => {
    const first = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: material.csrPem, target: { name: "Another host", type: "host" } });
    const signed = await importSignedCertificate({ workspaceId, workflowId: first.id,
      actorUserId: userId, certificatePem: material.certificatePem });
    await acknowledgeCsrNames({ workspaceId, workflowId: first.id, actorUserId: userId });
    const complete = await confirmCsrInstallation({ workspaceId, workflowId: first.id, actorUserId: userId });
    assert.equal(complete.status, "completed");
    assert.equal(complete.confirmationMethod, "manual");
    assert.equal(complete.observedInstanceId, null);
    assert.ok(complete.confirmedAt);
    await pool.query("UPDATE managed_certificates SET status = 'revoked' WHERE id = $1", [signed.managedCertificateId]);
    const next = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: material.csrPem, target: { name: "Third host", type: "host" } });
    await assert.rejects(importSignedCertificate({ workspaceId, workflowId: next.id,
      actorUserId: userId, certificatePem: material.certificatePem }),
    { code: "CERTOPS_CSR_IDENTITY_CONFLICT", status: 409 });
  });

  it("rejects a signed leaf owned by B when rotating A and keeps A unchanged", async () => {
    const other = generatePublicMaterial(fixtureDir, "other");
    const collision = generatePublicMaterial(fixtureDir, "collision");
    const parsed = require("../../apps/api/services/certops/parser").parsePublicCertificateMaterial(other.certificatePem)[0];
    const collisionLeaf = require("../../apps/api/services/certops/parser").parsePublicCertificateMaterial(collision.certificatePem)[0];
    const inserted = await pool.query(
      `INSERT INTO managed_certificates (workspace_id, status, source, name, certificate_pem,
         fingerprint_sha256, spki_fingerprint_sha256, not_after)
       VALUES ($1, 'active', 'api', 'Certificate A', $2, $3, $4, $5) RETURNING id, not_after`,
      [workspaceId, parsed.certificatePem, parsed.fingerprintSha256,
        parsed.spkiFingerprintSha256, parsed.notAfter],
    );
    const certificateA = inserted.rows[0];
    await pool.query(
      `INSERT INTO managed_certificates (workspace_id, status, source, name, certificate_pem,
         fingerprint_sha256, spki_fingerprint_sha256, not_after)
       VALUES ($1, 'active', 'api', 'Certificate B', $2, $3, $4, $5)`,
      [workspaceId, collisionLeaf.certificatePem, collisionLeaf.fingerprintSha256,
        collisionLeaf.spkiFingerprintSha256, collisionLeaf.notAfter],
    );
    const otherWorkflow = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: other.csrPem, target: { name: "Wrong key target", type: "host" } });
    await assert.rejects(importSignedCertificate({ workspaceId, workflowId: otherWorkflow.id,
      actorUserId: userId, certificatePem: material.certificatePem }),
    { code: "CERTOPS_CSR_PUBLIC_KEY_MISMATCH", status: 422 });

    // B already owns this leaf. The CSR key matches, but A must not be rebound.
    const workflow = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      existingCertificateId: certificateA.id, csrPem: collision.csrPem,
      target: { name: "Identity conflict target", type: "host" } });
    await assert.rejects(importSignedCertificate({ workspaceId, workflowId: workflow.id,
      actorUserId: userId, certificatePem: collision.certificatePem }),
    { code: "CERTOPS_CSR_IDENTITY_CONFLICT", status: 409 });
    const unchanged = await pool.query(
      "SELECT status, certificate_pem, not_after FROM managed_certificates WHERE id = $1",
      [certificateA.id],
    );
    assert.equal(unchanged.rows[0].status, "active");
    assert.equal(unchanged.rows[0].certificate_pem, parsed.certificatePem);
    assert.equal(new Date(unchanged.rows[0].not_after).toISOString(), new Date(certificateA.not_after).toISOString());
  });

  it("preserves an existing certificate until manager attestation promotes the new leaf", async () => {
    const oldMaterial = generatePublicMaterial(fixtureDir, "rotation-old");
    const newMaterial = generatePublicMaterial(fixtureDir, "rotation-new");
    const parser = require("../../apps/api/services/certops/parser");
    const oldLeaf = parser.parsePublicCertificateMaterial(oldMaterial.certificatePem)[0];
    const newLeaf = parser.parsePublicCertificateMaterial(newMaterial.certificatePem)[0];
    const inserted = await pool.query(
      `INSERT INTO managed_certificates (workspace_id, status, source, name, certificate_pem,
         fingerprint_sha256, spki_fingerprint_sha256, not_after)
       VALUES ($1, 'active', 'api', 'Rotation A', $2, $3, $4, $5) RETURNING id`,
      [workspaceId, oldLeaf.certificatePem, oldLeaf.fingerprintSha256,
        oldLeaf.spkiFingerprintSha256, oldLeaf.notAfter],
    );
    const id = inserted.rows[0].id;
    const workflow = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      existingCertificateId: id, csrPem: newMaterial.csrPem,
      target: { name: "Rotation host", type: "host" } });
    const signed = await importSignedCertificate({ workspaceId, workflowId: workflow.id,
      actorUserId: userId, certificatePem: newMaterial.certificatePem });
    assert.equal(signed.managedCertificateId, id);
    const before = await pool.query("SELECT status, fingerprint_sha256, not_after FROM managed_certificates WHERE id = $1", [id]);
    assert.equal(before.rows[0].status, "active");
    assert.equal(before.rows[0].fingerprint_sha256, oldLeaf.fingerprintSha256);
    assert.equal(new Date(before.rows[0].not_after).toISOString(), new Date(oldLeaf.notAfter).toISOString());
    await acknowledgeCsrNames({ workspaceId, workflowId: workflow.id, actorUserId: userId });
    const complete = await confirmCsrInstallation({ workspaceId, workflowId: workflow.id, actorUserId: userId });
    assert.equal(complete.confirmationMethod, "manual");
    const after = await pool.query("SELECT fingerprint_sha256, not_after, token_id FROM managed_certificates WHERE id = $1", [id]);
    assert.equal(after.rows[0].fingerprint_sha256, newLeaf.fingerprintSha256);
    assert.equal(new Date(after.rows[0].not_after).toISOString(), new Date(newLeaf.notAfter).toISOString());
    assert.ok(after.rows[0].token_id);
  });

  it("persists a B-owned observation and exposes a conflict without promoting A", async () => {
    const oldMaterial = generatePublicMaterial(fixtureDir, "late-conflict-old");
    const newMaterial = generatePublicMaterial(fixtureDir, "late-conflict-new");
    const parser = require("../../apps/api/services/certops/parser");
    const oldLeaf = parser.parsePublicCertificateMaterial(oldMaterial.certificatePem)[0];
    const newLeaf = parser.parsePublicCertificateMaterial(newMaterial.certificatePem)[0];
    const certificateA = await pool.query(
      `INSERT INTO managed_certificates (workspace_id, status, source, name, certificate_pem,
         fingerprint_sha256, spki_fingerprint_sha256, not_after)
       VALUES ($1, 'active', 'api', 'Conflict A', $2, $3, $4, $5) RETURNING id`,
      [workspaceId, oldLeaf.certificatePem, oldLeaf.fingerprintSha256,
        oldLeaf.spkiFingerprintSha256, oldLeaf.notAfter],
    );
    const target = await pool.query(
      `INSERT INTO certificate_targets (workspace_id, name, target_type, source, source_ref)
       VALUES ($1, 'Monitored conflict target', 'host', 'endpoint_monitor', $2) RETURNING id`,
      [workspaceId, `csr-conflict:${randomUUID()}`],
    );
    const workflow = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      existingCertificateId: certificateA.rows[0].id, csrPem: newMaterial.csrPem,
      targetId: target.rows[0].id });
    const signed = await importSignedCertificate({ workspaceId, workflowId: workflow.id,
      actorUserId: userId, certificatePem: newMaterial.certificatePem });
    assert.equal(signed.managedCertificateId, certificateA.rows[0].id);

    // B appears only after signed import, through normal observation inventory.
    const certificateB = await pool.query(
      `INSERT INTO managed_certificates (workspace_id, status, source, source_ref,
         name, certificate_pem, fingerprint_sha256, spki_fingerprint_sha256, not_after)
       VALUES ($1, 'active', 'agent_filesystem', $2, 'Observed B', $3, $4, $5, $6) RETURNING id`,
      [workspaceId, `csr-observed:${randomUUID()}`, newLeaf.certificatePem,
        newLeaf.fingerprintSha256, newLeaf.spkiFingerprintSha256, newLeaf.notAfter],
    );
    const client = await pool.connect();
    let instanceId;
    try {
      await client.query("BEGIN");
      const instance = await client.query(
        `INSERT INTO certificate_instances (workspace_id, managed_certificate_id, target_id,
           source, observed_fingerprint_sha256, observed_at)
         VALUES ($1, $2, $3, 'endpoint_monitor', $4, NOW()) RETURNING id`,
        [workspaceId, certificateB.rows[0].id, target.rows[0].id, newLeaf.fingerprintSha256],
      );
      instanceId = instance.rows[0].id;
      await recordCsrObservation(client, { workspaceId, targetId: target.rows[0].id,
        fingerprintSha256: newLeaf.fingerprintSha256, instanceId });
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    const observed = await pool.query("SELECT managed_certificate_id FROM certificate_instances WHERE id = $1", [instanceId]);
    assert.equal(observed.rows[0].managed_certificate_id, certificateB.rows[0].id);
    let pending = await getCsrWorkflow({ workspaceId, workflowId: workflow.id });
    assert.equal(pending.status, "signed_pending_install");
    assert.equal(pending.observedInstanceId, null);
    assert.equal(pending.identityConflict.observedCertificateId, certificateB.rows[0].id);
    assert.equal(pending.identityConflict.observedInstanceId, instanceId);
    pending = await acknowledgeCsrNames({ workspaceId, workflowId: workflow.id, actorUserId: userId });
    assert.equal(pending.status, "signed_pending_install");
    assert.ok(pending.namesAcknowledgedAt);
    await assert.rejects(confirmCsrInstallation({ workspaceId, workflowId: workflow.id, actorUserId: userId }),
      { code: "CERTOPS_CSR_IDENTITY_CONFLICT", status: 409 });
    const unchanged = await pool.query("SELECT fingerprint_sha256 FROM managed_certificates WHERE id = $1",
      [certificateA.rows[0].id]);
    assert.equal(unchanged.rows[0].fingerprint_sha256, oldLeaf.fingerprintSha256);
    const audit = await pool.query(
      `SELECT metadata FROM audit_events WHERE workspace_id = $1
       AND action = 'CERTOPS_CSR_OBSERVED_IDENTITY_CONFLICT'
       AND metadata->>'workflow_id' = $2`,
      [workspaceId, workflow.id],
    );
    assert.equal(audit.rows.length, 1);
  });

  it("reconciles other new workflows sharing a provisional fingerprint when one target observes it", async () => {
    const shared = generatePublicMaterial(fixtureDir, "shared-provisional");
    const parsed = require("../../apps/api/services/certops/parser").parsePublicCertificateMaterial(shared.certificatePem)[0];
    const first = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: shared.csrPem, target: { name: "Shared provisional first", type: "host" } });
    const second = await createCsrWorkflow({ workspaceId, actorUserId: userId,
      csrPem: shared.csrPem, target: { name: "Shared provisional second", type: "host" } });
    const firstSigned = await importSignedCertificate({ workspaceId, workflowId: first.id,
      actorUserId: userId, certificatePem: shared.certificatePem });
    const secondSigned = await importSignedCertificate({ workspaceId, workflowId: second.id,
      actorUserId: userId, certificatePem: shared.certificatePem });
    assert.equal(secondSigned.managedCertificateId, firstSigned.managedCertificateId);
    await acknowledgeCsrNames({ workspaceId, workflowId: first.id, actorUserId: userId });

    const observed = await pool.query(
      `INSERT INTO managed_certificates (workspace_id, status, source, source_ref,
         name, certificate_pem, fingerprint_sha256, spki_fingerprint_sha256, not_after)
       VALUES ($1, 'discovered', 'agent_filesystem', $2, 'Shared observed leaf', $3, $4, $5, $6)
       RETURNING id`,
      [workspaceId, `csr-shared:${randomUUID()}`, parsed.certificatePem,
        parsed.fingerprintSha256, parsed.spkiFingerprintSha256, parsed.notAfter],
    );
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const instance = await client.query(
        `INSERT INTO certificate_instances (workspace_id, managed_certificate_id, target_id,
          source, observed_fingerprint_sha256, observed_at)
         VALUES ($1, $2, $3, 'endpoint_monitor', $4, NOW()) RETURNING id`,
        [workspaceId, observed.rows[0].id, first.targetId, parsed.fingerprintSha256],
      );
      await recordCsrObservation(client, { workspaceId, targetId: first.targetId,
        fingerprintSha256: parsed.fingerprintSha256, instanceId: instance.rows[0].id });
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    const completed = await getCsrWorkflow({ workspaceId, workflowId: first.id });
    const waiting = await getCsrWorkflow({ workspaceId, workflowId: second.id });
    assert.equal(completed.status, "completed");
    assert.equal(waiting.status, "signed_pending_install");
    assert.equal(waiting.managedCertificateId, observed.rows[0].id);
    const provisional = await pool.query("SELECT 1 FROM managed_certificates WHERE id = $1", [firstSigned.managedCertificateId]);
    assert.equal(provisional.rows.length, 0);
  });
});
