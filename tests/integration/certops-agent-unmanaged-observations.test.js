"use strict";

const assert = require("node:assert/strict");
const { randomUUID, createHash, X509Certificate } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { Client, Pool } = require("pg");
const { migrations } = require("../../apps/api/migrations/migrate");
const { persistAgentDiscoveryEvidenceBatch } = require("../../apps/api/services/certops/agentObservations");
const { listCertificateIdentities, retireCertificateIdentity, stopManagingSource } = require("../../apps/api/services/certops/certificateIdentity");
const { countActiveManagedCertificatesWithClient, importPublicCertificates } = require("../../apps/api/services/certops/inventory");

const pem = readFileSync(join(__dirname, "../fixtures/certops-public-observation.txt"), "utf8");
const certificate = new X509Certificate(pem);
const fingerprint = certificate.fingerprint256.replaceAll(":", "").toLowerCase();
const connection = {
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || "tokentimer",
  password: process.env.DB_PASSWORD || "password",
};
const database = `certops_unmanaged_agent_${process.pid}_${Date.now()}`;

describe("Quota-blocked agent observations on real PostgreSQL", function () {
  this.timeout(120000);
  let db, userId;
  before(async () => {
    const admin = new Client({ ...connection, database: process.env.DB_NAME || "tokentimer" });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${database}`);
    await admin.end();
    db = new Pool({ ...connection, database });
    for (const migration of migrations) await db.query(migration.sql);
    userId = (await db.query(`INSERT INTO users(email,email_original,display_name,password_hash,auth_method)
      VALUES('unmanaged-agent@example.test','unmanaged-agent@example.test','Observation Test','x','local') RETURNING id`)).rows[0].id;
  });
  after(async () => {
    if (db) await db.end();
    const admin = new Client({ ...connection, database: process.env.DB_NAME || "tokentimer" });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.end();
  });
  async function agent(limit = 0, existingWorkspace = null) {
    const workspaceId = existingWorkspace || (await db.query(`INSERT INTO workspaces(id,name,plan,created_by,certops_managed_identity_limit)
      VALUES(gen_random_uuid(),'Quota observation test','oss',$1,$2) RETURNING id`, [userId, limit])).rows[0].id;
    const agentId = `observation-${randomUUID()}`;
    const row = (await db.query(`INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
      VALUES($1,$2,'test','1.0.0',$3,$4) RETURNING id`,
    [workspaceId, agentId, `ttagent_${randomUUID().replaceAll("-", "").slice(0, 16)}`,
      createHash("sha256").update(agentId).digest("hex")])).rows[0];
    return { id: row.id, workspaceId, agentId, hostname: "observation.example.test" };
  }
  function observation(filePath, overrides = {}) {
    return {
      evidenceId: randomUUID(), eventType: "certificate.observed",
      observedAt: new Date(Date.now() - 60000).toISOString(), fingerprintSha256: fingerprint,
      metadata: [
        { name: "filePath", value: filePath },
        { name: "certificatePem", value: pem },
        { name: "subject", value: certificate.subject },
        { name: "issuer", value: certificate.issuer },
        { name: "notBefore", value: new Date(certificate.validFrom).toISOString() },
        { name: "notAfter", value: new Date(certificate.validTo).toISOString() },
      ], ...overrides,
    };
  }
  async function send(principal, sequence, items) {
    return persistAgentDiscoveryEvidenceBatch({ dbPool: db, agent: principal,
      envelope: { sequence }, evidenceItems: items });
  }
  async function rows(table, workspaceId) {
    return (await db.query(`SELECT * FROM ${table} WHERE workspace_id=$1`, [workspaceId])).rows;
  }

  it("retains two locations and evidence without tokens or management, fences replays, and later enrolls the same identity", async () => {
    const principal = await agent();
    const one = observation("/etc/ssl/one.pem"), two = observation("/etc/ssl/two.pem");
    const accepted = await send(principal, 1, [one, two]);
    assert.equal(accepted.items.filter((item) => item.unmanaged && item.evidence).length, 2);
    const identities = await rows("certops_certificate_identities", principal.workspaceId);
    assert.equal(identities.length, 1);
    assert.equal((await rows("certops_slot_observations", principal.workspaceId)).length, 2);
    assert.equal((await rows("certificate_evidence", principal.workspaceId)).length, 2);
    const snapshot = (await rows("certops_identity_detail_history", principal.workspaceId))[0];
    assert.equal(snapshot.token_id, null);
    assert.equal(snapshot.token_details, null);
    assert.equal(snapshot.certificate_details.notBefore, new Date(certificate.validFrom).toISOString());
    assert.equal(snapshot.certificate_details.serialNumber, certificate.serialNumber);
    for (const table of ["tokens", "managed_certificates", "certops_management_periods"])
      assert.equal((await rows(table, principal.workspaceId)).length, 0, table);
    const capture = (await rows("certops_slot_observations", principal.workspaceId))
      .find((slot) => slot.source_ref.endsWith("/one.pem")).captured_at.toISOString();
    const replay = await send(principal, 2, [{ ...one, observedAt: new Date().toISOString() }]);
    assert.equal(replay.duplicateCount, 1);
    assert.equal(replay.items[0].unmanaged, true);
    assert.equal((await rows("certops_slot_observations", principal.workspaceId))
      .find((slot) => slot.source_ref.endsWith("/one.pem")).captured_at.toISOString(), capture);
    await assert.rejects(send(principal, 2, [two]), { code: "CERTOPS_AGENT_SEQUENCE_REGRESSION" });
    await db.query("UPDATE workspaces SET certops_managed_identity_limit=1 WHERE id=$1", [principal.workspaceId]);
    // Merely replaying old evidence cannot create a management period.
    assert.equal((await send(principal, 3, [one])).duplicateCount, 1);
    assert.equal((await rows("certops_management_periods", principal.workspaceId)).length, 0);
    const enrolled = await send(principal, 4, [observation("/etc/ssl/one.pem")]);
    assert.equal(enrolled.items[0].unmanaged, false);
    assert.equal((await rows("certops_certificate_identities", principal.workspaceId))[0].id, identities[0].id);
    await send(principal, 5, [observation("/etc/ssl/two.pem")]);
    assert.equal(await countActiveManagedCertificatesWithClient(db, principal.workspaceId), 1);
    const inventory = await listCertificateIdentities({ client: db, workspaceId: principal.workspaceId, includeDetails: true });
    assert.equal(inventory.items.length, 1);
    assert.equal(inventory.items[0].locations.length, 2, "adoption must not duplicate the old unmanaged slots");
  });

  it("retains unmanaged service bindings, blocks decommission, and preserves revoked lifecycle on rediscovery", async () => {
    const principal = await agent();
    const item = observation(null, { metadata: [
      { name: "locationKind", value: "iis_binding" },
      { name: "locationSlot", value: "Default Web Site:443#example.test" },
      { name: "siteName", value: "Default Web Site" },
      { name: "port", value: 443 },
      { name: "sniHost", value: "example.test" },
      { name: "certificatePem", value: pem },
      { name: "notAfter", value: new Date(certificate.validTo).toISOString() },
    ] });
    await send(principal, 1, [item]);
    const identityId = (await rows("certops_certificate_identities", principal.workspaceId))[0].id;
    await assert.rejects(retireCertificateIdentity({ client: db, workspaceId: principal.workspaceId,
      identityId, expectedFingerprintSha256: fingerprint, status: "decommissioned", reason: "Attempt", acknowledgeUncertainty: true, actorUserId: userId }),
    { code: "CERTOPS_CERTIFICATE_STILL_SERVING" });
    await retireCertificateIdentity({ client: db, workspaceId: principal.workspaceId,
      identityId, expectedFingerprintSha256: fingerprint, status: "revoked", reason: "Recorded revocation", actorUserId: userId });
    await send(principal, 2, [{ ...item, evidenceId: randomUUID() }]);
    assert.equal((await rows("certops_certificate_identities", principal.workspaceId))[0].lifecycle_status, "revoked");
  });

  it("keeps existing-source rotation admissible while over quota", async () => {
    const principal = await agent(1);
    await send(principal, 1, [observation("/etc/ssl/rotation.pem")]);
    await db.query("UPDATE workspaces SET certops_managed_identity_limit=0 WHERE id=$1", [principal.workspaceId]);
    const rotated = observation("/etc/ssl/rotation.pem", {
      fingerprintSha256: "b".repeat(64), metadata: [{ name: "filePath", value: "/etc/ssl/rotation.pem" }],
    });
    assert.equal((await send(principal, 2, [rotated])).items[0].unmanaged, false);
    assert.equal((await rows("managed_certificates", principal.workspaceId)).length, 1);
    assert.equal((await rows("certops_management_periods", principal.workspaceId)).length, 1);
  });

  it("persists unchanged and stopped-source observations while another transaction owns the quota lock", async () => {
    const principal = await agent(1);
    const first = await send(principal, 1, [observation("/etc/ssl/unchanged.pem")]);
    const managedCertificateId = first.items[0].managedCertificateId;
    const boundedPool = new Pool({ ...connection, database,
      options: "-c statement_timeout=2000" });
    const holder = await db.connect();
    async function withQuotaLock(sequence) {
      await holder.query("BEGIN");
      await holder.query("SELECT pg_advisory_xact_lock(hashtext('certops_managed_cert_quota_' || $1::text))", [principal.workspaceId]);
      try {
        return await persistAgentDiscoveryEvidenceBatch({ dbPool: boundedPool,
          agent: principal, envelope: { sequence },
          evidenceItems: [observation("/etc/ssl/unchanged.pem")] });
      } finally {
        await holder.query("ROLLBACK");
      }
    }
    try {
      assert.equal((await withQuotaLock(2)).items[0].managedCertificateId, managedCertificateId);
      const periodId = (await rows("certops_management_periods", principal.workspaceId))[0].id;
      await stopManagingSource({ client: db, workspaceId: principal.workspaceId,
        periodId, reason: "Stop management", actorUserId: userId });
      assert.equal((await withQuotaLock(3)).items[0].managedCertificateId, managedCertificateId);
      assert.ok((await rows("certops_management_periods", principal.workspaceId))[0].ended_at);
      assert.equal(await countActiveManagedCertificatesWithClient(db, principal.workspaceId), 0);
    } finally {
      holder.release();
      await boundedPool.end();
    }
  });

  it("admits concurrent agent locations and a manual import sharing one fingerprint at quota", async () => {
    const one = await agent(1), two = await agent(1, one.workspaceId);
    async function manualImport() {
      const client = await db.connect();
      try {
        await client.query("BEGIN");
        const result = await importPublicCertificates({ client, workspaceId: one.workspaceId,
          certificatePem: pem, source: "import", createdBy: userId });
        await client.query("COMMIT");
        return result;
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    }
    const result = await Promise.all([
      send(one, 1, [observation("/concurrent-one.pem")]),
      send(two, 1, [observation("/concurrent-two.pem")]),
      manualImport(),
    ]);
    assert.equal(result[0].items[0].unmanaged, false);
    assert.equal(result[1].items[0].unmanaged, false);
    assert.equal((await rows("certops_certificate_identities", one.workspaceId)).length, 1);
    assert.equal((await rows("certops_management_periods", one.workspaceId)).length, 3);
    assert.equal(await countActiveManagedCertificatesWithClient(db, one.workspaceId), 1);
  });

  it("does not deadlock token-first manual enrollment with an agent enriching the same certificate", async () => {
    const principal = await agent(1);
    await send(principal, 1, [observation("/shared-token.pem", { metadata: [
      { name: "filePath", value: "/shared-token.pem" },
      { name: "notAfter", value: new Date(certificate.validTo).toISOString() },
    ] })]);
    const tokenId = (await rows("managed_certificates", principal.workspaceId))[0].token_id;
    const applicationName = `agent_lock_order_${randomUUID()}`;
    const boundedPool = new Pool({ ...connection, database,
      application_name: applicationName, options: "-c statement_timeout=8000" });
    const manual = await db.connect();
    let pending;
    try {
      await manual.query("BEGIN");
      await manual.query("SELECT pg_advisory_xact_lock(hashtext('certops_managed_cert_quota_' || $1::text))", [principal.workspaceId]);
      await manual.query("SELECT id FROM tokens WHERE id=$1 FOR NO KEY UPDATE", [tokenId]);
      pending = persistAgentDiscoveryEvidenceBatch({ dbPool: boundedPool, agent: principal,
        envelope: { sequence: 2 }, evidenceItems: [observation("/shared-token.pem")] });
      // Attach rejection immediately while inspecting PostgreSQL's lock graph.
      const outcome = pending.then((value) => ({ value }), (error) => ({ error }));
      const blocker = (await manual.query("SELECT pg_backend_pid() pid")).rows[0].pid;
      let blocked = false;
      for (let attempt = 0; attempt < 300; attempt++) {
        blocked = (await db.query(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity
          WHERE application_name=$1 AND $2::int=ANY(pg_blocking_pids(pid))) blocked`, [applicationName, blocker])).rows[0].blocked;
        if (blocked) break;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      assert.ok(blocked, "the real agent transaction must reach the token lock");
      await importPublicCertificates({ client: manual, workspaceId: principal.workspaceId,
        certificatePem: pem, source: "import", tokenId, createdBy: userId });
      await manual.query("COMMIT");
      const finished = await outcome;
      assert.ok(!finished.error, `${finished.error?.code || ""}: ${finished.error?.detail || finished.error?.message || ""}`);
      assert.equal(finished.value.evidenceCount, 1);
      assert.equal((await rows("certops_management_periods", principal.workspaceId)).length, 2);
      assert.equal(await countActiveManagedCertificatesWithClient(db, principal.workspaceId), 1);
    } finally {
      await manual.query("ROLLBACK");
      if (pending) await pending.catch(() => {});
      manual.release();
      await boundedPool.end();
    }
  });

  it("rejects malformed and fingerprint-mismatched public material before burning sequence", async () => {
    const principal = await agent();
    await assert.rejects(send(principal, 1, [observation("/bad.pem", { fingerprintSha256: "c".repeat(64) })]),
      { code: "CERTOPS_AGENT_OBSERVATION_INVALID" });
    await assert.rejects(send(principal, 1, [observation("/bad.pem", { metadata: [
      { name: "filePath", value: "/bad.pem" }, { name: "certificatePem", value: "garbage" },
    ] })]));
    const row = (await db.query("SELECT last_sequence FROM certops_agents WHERE id=$1", [principal.id])).rows[0];
    assert.equal(Number(row.last_sequence), 0);
    assert.equal((await rows("certops_certificate_identities", principal.workspaceId)).length, 0);
  });

  it("rolls back the sequence and retained observations on non-admission database failures", async () => {
    const principal = await agent();
    await db.query(`CREATE FUNCTION reject_unmanaged_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'Evidence insert failed' USING ERRCODE='P0001', DETAIL='NOT_A_QUOTA_ERROR'; END $$;
      CREATE TRIGGER reject_unmanaged_evidence BEFORE INSERT ON certificate_evidence
      FOR EACH ROW EXECUTE FUNCTION reject_unmanaged_evidence()`);
    try {
      await assert.rejects(send(principal, 1, [observation("/failure.pem")]),
        (error) => error.code === "P0001" && error.detail === "NOT_A_QUOTA_ERROR");
    } finally {
      await db.query("DROP TRIGGER reject_unmanaged_evidence ON certificate_evidence; DROP FUNCTION reject_unmanaged_evidence()");
    }
    assert.equal(Number((await db.query("SELECT last_sequence FROM certops_agents WHERE id=$1", [principal.id])).rows[0].last_sequence), 0);
    for (const table of ["certops_certificate_identities", "certops_slot_observations", "certificate_evidence", "tokens"])
      assert.equal((await rows(table, principal.workspaceId)).length, 0, table);
  });
});
