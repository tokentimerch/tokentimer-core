"use strict";

const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { pool } = require("../../apps/api/db/database");
const {
  acknowledgeCsrNames, confirmCsrInstallation, createCsrWorkflow,
  getCsrWorkflow, importSignedCertificate, recordCsrObservation,
} = require("../../apps/api/services/certops/csrWorkflow");

function opensslBinary() {
  const candidates = ["openssl", "C:\\Program Files\\Git\\usr\\bin\\openssl.exe"];
  for (const candidate of candidates) {
    if (spawnSync(candidate, ["version"], { encoding: "utf8" }).status === 0) return candidate;
  }
  throw new Error("OpenSSL is required for CSR integration fixtures");
}

function generatePublicMaterial(dir, label) {
  const openssl = opensslBinary();
  const key = path.join(dir, `${label}.key`);
  const csr = path.join(dir, `${label}.csr`);
  const cert = path.join(dir, `${label}.crt`);
  const ext = path.join(dir, `${label}.cnf`);
  fs.writeFileSync(ext, "[v3_req]\nsubjectAltName=DNS:issued.example.test\n");
  for (const args of [
    ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key],
    ["req", "-new", "-key", key, "-subj", "/CN=requested.example.test", "-addext", "subjectAltName=DNS:requested.example.test", "-out", csr],
    ["x509", "-req", "-in", csr, "-signkey", key, "-days", "365", "-extfile", ext, "-extensions", "v3_req", "-out", cert],
  ]) {
    const result = spawnSync(openssl, args, { encoding: "utf8" });
    assert.equal(result.status, 0, `OpenSSL failed: ${result.stderr}`);
  }
  return { csrPem: fs.readFileSync(csr, "utf8"), certificatePem: fs.readFileSync(cert, "utf8") };
}

describe("operator supplied CSR workflow", function () {
  this.timeout(30000);
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
       VALUES ($1, 'active', 'endpoint_monitor', $2, 'Observed B', $3, $4, $5, $6) RETURNING id`,
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
       VALUES ($1, 'discovered', 'endpoint_monitor', $2, 'Shared observed leaf', $3, $4, $5, $6)
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
