"use strict";

const assert = require("node:assert/strict");
const { randomUUID, createHash, X509Certificate } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { Client, Pool } = require("pg");
const { migrations } = require("../../apps/api/migrations/migrate");
const { persistAgentDiscoveryEvidenceBatch } = require("../../apps/api/services/certops/agentObservations");
const { findCertificatesDueForRenewal } = require("../../apps/api/services/certops/renewalScheduler");
const { resolveRenewalPathForCertificate } = require("../../apps/api/services/certops/renewalPathHealth");
const { _test: dispatchTest } = require("../../apps/api/services/certops/agentDispatch");
const { claimJobs } = require("../../apps/api/services/certops/agentDispatch");
const { preflightManualRenewalRouting } = require("../../apps/api/services/certops/jobs");
const { replaceManagingSource } = require("../../apps/api/services/certops/certificateIdentity");
const { listCertificateIdentities } = require("../../apps/api/services/certops/certificateIdentity");
const { bindAuthenticatedCredential } = require("../../apps/api/services/certops/agentCredentialFence");
const { reassociateWindowsStore, listIisReassociationCandidates } = require("../../apps/api/services/certops/windowsStoreReassociation");
const { listRenewalProfiles } = require("../../apps/api/services/certops/renewalProfileAdmin");

const connection = {
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || "tokentimer",
  password: process.env.DB_PASSWORD || "password",
};
const database = `certops_store_collision_${process.pid}_${Date.now()}`;

describe("Windows store certificate collision on PostgreSQL", function () {
  this.timeout(120000);
  let db, userId;
  before(async () => {
    const admin = new Client({ ...connection, database: process.env.DB_NAME || "tokentimer" });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${database}`);
    await admin.end();
    db = new Pool({ ...connection, database });
    for (const migration of migrations) await db.query(migration.sql);
    for (const migration of migrations) if (migration.postCommitSql) await db.query(migration.postCommitSql);
    userId = (await db.query(`INSERT INTO users(email,email_original,display_name,password_hash,auth_method)
      VALUES('collision@example.test','collision@example.test','Collision Test','x','local') RETURNING id`)).rows[0].id;
  });
  after(async () => {
    if (db) await db.end();
    const admin = new Client({ ...connection, database: process.env.DB_NAME || "tokentimer" });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    await admin.end();
  });

  for (const order of [["good", "revoked"], ["revoked", "good"]]) {
    it(`preserves separate same-CN certificates and revocation when observed ${order.join(" then ")}`, async () => {
      const workspaceId = (await db.query(`INSERT INTO workspaces(id,name,plan,created_by)
        VALUES(gen_random_uuid(),'Collision test','oss',$1) RETURNING id`, [userId])).rows[0].id;
      const agentId = `collision-${randomUUID()}`;
      const id = (await db.query(`INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
        VALUES($1,$2,'test','1.0.0',$3,$4) RETURNING id`, [workspaceId, agentId,
        `ttagent_${randomUUID().replaceAll("-", "").slice(0, 16)}`, createHash("sha256").update(agentId).digest("hex")])).rows[0].id;
      const agent = bindAuthenticatedCredential({ id, agentId, workspaceId, hostname: "pilot.example.test" }, agentId);
      const capturedAt = new Date(Date.now() - 60000).toISOString();
      const expiry = new Date(Date.now() + 3600000).toISOString();
      function observation(verdict) {
        const revoked = verdict === "revoked";
        return { evidenceId: randomUUID(), eventType: "certificate.observed", observedAt: capturedAt,
          fingerprintSha256: (revoked ? "4" : "3").repeat(64), metadata: [
            { name: "locationKind", value: "windows_store" },
            { name: "locationSlot", value: "LocalMachine/My/shared.example.test" },
            { name: "targetHost", value: "pilot.example.test" },
            { name: "storeLocation", value: "LocalMachine" },
            { name: "storeName", value: "My" },
            { name: "thumbprint", value: (revoked ? "4" : "3").repeat(40) },
            { name: "subject", value: "CN=shared.example.test" },
            { name: "validTo", value: expiry },
            { name: "observedRevocationVerdict", value: verdict },
            { name: "observedChainStatus", value: "valid" },
            { name: "observedRevocationCheckedAt", value: capturedAt },
            { name: "observedRevocationValidUntil", value: expiry },
          ] };
      }
      for (let i = 0; i < order.length; i++) {
        await persistAgentDiscoveryEvidenceBatch({ dbPool: db, agent, envelope: { sequence: i + 1 }, evidenceItems: [observation(order[i])] });
      }
      const certs = (await db.query("SELECT id, fingerprint_sha256, source_ref FROM managed_certificates WHERE workspace_id=$1", [workspaceId])).rows;
      assert.equal(certs.length, 2);
      assert.equal(new Set(certs.map((c) => c.source_ref)).size, 2);
      const instances = (await db.query("SELECT id, managed_certificate_id, observed_fingerprint_sha256, public_metadata FROM certificate_instances WHERE workspace_id=$1", [workspaceId])).rows;
      assert.equal(instances.length, 2);
      for (const instance of instances) {
        assert.equal(instance.managed_certificate_id, certs.find((c) => c.fingerprint_sha256 === instance.observed_fingerprint_sha256).id);
        assert.equal(instance.public_metadata.observedRevocation.verdict,
          instance.observed_fingerprint_sha256 === "4".repeat(64) ? "revoked" : "good");
      }
      const revokedList=await listCertificateIdentities({client:db,workspaceId,status:'revoked'});
      assert.deepEqual(revokedList.items.map(item=>item.fingerprintSha256),['4'.repeat(64)]);
      assert.equal(revokedList.items[0].sources[0].targetHostname, 'pilot.example.test');
      assert.equal(revokedList.items[0].locations[0].targetHostname, 'pilot.example.test');
      const activeList=await listCertificateIdentities({client:db,workspaceId,status:'active'});
      assert.ok(!activeList.items.some(item=>item.fingerprintSha256==='4'.repeat(64)));
      assert.equal(revokedList.items[0].lifecycleStatus,'active');
      assert.equal(revokedList.items[0].securityStatus.state,'revoked');
      const revokedInstance=instances.find(item=>item.observed_fingerprint_sha256==='4'.repeat(64));
      await db.query("UPDATE certificate_instances SET public_metadata=jsonb_set(public_metadata,'{observedRevocation}',$2::jsonb) WHERE id=$1", [revokedInstance.id,JSON.stringify({verdict:'unknown',lastVerified:{verdict:'revoked',chainStatus:'valid',checkedAt:capturedAt,validUntil:expiry}})]);
      const lastKnown=await listCertificateIdentities({client:db,workspaceId,status:'revoked'});
      assert.ok(lastKnown.items.some(item=>item.fingerprintSha256==='4'.repeat(64)));
      assert.equal(lastKnown.items.find(item=>item.fingerprintSha256==='4'.repeat(64)).lifecycleStatus,'active');
      assert.equal(lastKnown.items.find(item=>item.fingerprintSha256==='4'.repeat(64)).securityStatus.state,'last_known_revoked');
      await db.query("UPDATE certificate_instances SET public_metadata=jsonb_set(public_metadata,'{observedRevocation}',$2::jsonb) WHERE id=$1", [revokedInstance.id,JSON.stringify({verdict:'good',chainStatus:'valid',checkedAt:capturedAt,validUntil:new Date(Date.now()-30000).toISOString(),lastVerified:{verdict:'revoked',chainStatus:'valid',checkedAt:capturedAt,validUntil:expiry}})]);
      const staleGood=await listCertificateIdentities({client:db,workspaceId,status:'revoked'});
      assert.equal(staleGood.items.find(item=>item.fingerprintSha256==='4'.repeat(64)).securityStatus.state,'last_known_revoked');
      assert.ok(!(await listCertificateIdentities({client:db,workspaceId,status:'active'})).items.some(item=>item.fingerprintSha256==='4'.repeat(64)));
      await db.query("UPDATE certificate_instances SET public_metadata=jsonb_set(public_metadata,'{observedRevocation}',$2::jsonb) WHERE id=$1", [revokedInstance.id,JSON.stringify({verdict:'good',chainStatus:'valid',checkedAt:capturedAt,validUntil:expiry})]);
      const recovered=await listCertificateIdentities({client:db,workspaceId,status:'revoked'});
      assert.ok(!recovered.items.some(item=>item.fingerprintSha256==='4'.repeat(64)));
      const stillActive=await listCertificateIdentities({client:db,workspaceId,status:'active'});
      assert.equal(stillActive.items.find(item=>item.fingerprintSha256==='4'.repeat(64)).lifecycleStatus,'active');
      assert.equal(stillActive.items.find(item=>item.fingerprintSha256==='4'.repeat(64)).securityStatus.state,'revocation_good');
      await db.query("UPDATE certificate_instances SET public_metadata=jsonb_set(public_metadata,'{observedRevocation}',$2::jsonb) WHERE id=$1", [revokedInstance.id,JSON.stringify({verdict:'issuer_revoked',chainStatus:'valid',checkedAt:capturedAt,validUntil:expiry,revokedIssuerFingerprintSha256:'3'.repeat(64)})]);
      const issuerRevoked=await listCertificateIdentities({client:db,workspaceId,status:'revoked'});
      assert.deepEqual(issuerRevoked.items.map(item=>item.fingerprintSha256),['3'.repeat(64)]);
      assert.equal(issuerRevoked.items[0].securityStatus.state,'revoked');
      assert.equal(issuerRevoked.items[0].observedRevocation.derivedFromIssuerChain,true);
      const child=await listCertificateIdentities({client:db,workspaceId});
      assert.equal(child.items.find(item=>item.fingerprintSha256==='4'.repeat(64)).securityStatus.state,'issuer_revoked');
      await db.query("UPDATE certificate_instances SET public_metadata=jsonb_set(public_metadata,'{observedRevocation}',$2::jsonb) WHERE id=$1", [revokedInstance.id,JSON.stringify({verdict:'unknown',lastVerified:{verdict:'issuer_revoked',chainStatus:'valid',checkedAt:capturedAt,validUntil:expiry,revokedIssuerFingerprintSha256:'3'.repeat(64)}})]);
      const lastKnownIssuer=await listCertificateIdentities({client:db,workspaceId,status:'revoked'});
      assert.equal(lastKnownIssuer.items.find(item=>item.fingerprintSha256==='3'.repeat(64)).securityStatus.state,'last_known_revoked');
      await db.query("UPDATE certificate_instances SET public_metadata=jsonb_set(public_metadata,'{observedRevocation}',$2::jsonb) WHERE id=$1", [revokedInstance.id,JSON.stringify({verdict:'issuer_revoked',chainStatus:'valid',checkedAt:capturedAt,validUntil:expiry,revokedIssuerFingerprintSha256:'c'.repeat(64),lastVerified:{verdict:'issuer_revoked',chainStatus:'valid',checkedAt:capturedAt,validUntil:expiry,revokedIssuerFingerprintSha256:'3'.repeat(64)}})]);
      const changedChain=await listCertificateIdentities({client:db,workspaceId,status:'revoked'});
      assert.equal(changedChain.items.find(item=>item.fingerprintSha256==='3'.repeat(64)).securityStatus.state,'last_known_revoked');
      await db.query("UPDATE certificate_instances SET public_metadata=jsonb_set(public_metadata,'{observedRevocation}',$2::jsonb) WHERE id=$1", [revokedInstance.id,JSON.stringify({verdict:'revoked',chainStatus:'valid',checkedAt:new Date(Date.now()+120000).toISOString(),validUntil:expiry})]);
      const future=await listCertificateIdentities({client:db,workspaceId,status:'active'});
      assert.equal(future.items.find(item=>item.fingerprintSha256==='4'.repeat(64)).securityStatus.state,'unknown');
      assert.ok(!(await listCertificateIdentities({client:db,workspaceId,status:'revoked'})).items.some(item=>item.fingerprintSha256==='4'.repeat(64)));
      await db.query('UPDATE certificate_instances SET public_metadata=$2 WHERE id=$1',[revokedInstance.id,revokedInstance.public_metadata]);
      // An upgrade may leave an old target and a fingerprint-keyed target for
      // the same store copy. Merge those observations only on the same host.
      const original = instances[0];
      const target = (await db.query(`SELECT t.* FROM certificate_targets t
        JOIN certificate_instances i ON i.target_id=t.id AND i.workspace_id=t.workspace_id
        WHERE i.id=$1`, [original.id])).rows[0];
      assert.ok(target.hostname && target.public_metadata.agentId);
      for (const host of [target.hostname, 'different-host.example.test']) {
        const other = (await db.query(`INSERT INTO certificate_targets(workspace_id,name,target_type,source,hostname,public_metadata)
          VALUES($1,'duplicate target','host','integration',$2,$3) RETURNING id`,
          [workspaceId,host,target.public_metadata])).rows[0].id;
        await db.query(`INSERT INTO certificate_instances(workspace_id,managed_certificate_id,target_id,source,source_ref,
          observed_fingerprint_sha256,deployment_reference,location_kind,presence_state,evidence_kind,captured_at,scan_interval_seconds)
          SELECT workspace_id,managed_certificate_id,$2::uuid,source,source_ref||'/duplicate-'||($2::uuid)::text,
          observed_fingerprint_sha256,deployment_reference,location_kind,presence_state,evidence_kind,captured_at,scan_interval_seconds
          FROM certificate_instances WHERE id=$1`, [original.id,other]);
      }
      const identities=await listCertificateIdentities({client:db,workspaceId});
      const matching=identities.items.find(item=>item.fingerprintSha256===original.observed_fingerprint_sha256);
      assert.equal(matching.locations.filter(location=>location.locationKind==='windows_store').length,2);
      // A fresh good result clears its own historical revocation, but must not
      // hide a different location that has not reported any check.
      await db.query("UPDATE certificate_instances SET public_metadata=jsonb_set(public_metadata,'{observedRevocation}',$2::jsonb) WHERE id=$1", [original.id, JSON.stringify({verdict:'good',chainStatus:'valid',checkedAt:capturedAt,validUntil:expiry,lastVerified:{verdict:'revoked',chainStatus:'valid',checkedAt:capturedAt,validUntil:expiry}})]);
      const conflicting=await listCertificateIdentities({client:db,workspaceId});
      assert.equal(conflicting.items.find(item=>item.fingerprintSha256===original.observed_fingerprint_sha256).securityStatus.state,'unknown');
      assert.ok(!(await listCertificateIdentities({client:db,workspaceId,status:'revoked'})).items.some(item=>item.fingerprintSha256===original.observed_fingerprint_sha256));
      const duplicate = (await db.query(`SELECT id FROM certificate_instances WHERE workspace_id=$1 AND observed_fingerprint_sha256=$2 AND id<>$3 LIMIT 1`, [workspaceId,original.observed_fingerprint_sha256,original.id])).rows[0];
      await db.query("UPDATE certificate_instances SET public_metadata=jsonb_build_object('observedRevocation',$2::jsonb) WHERE id=$1", [duplicate.id,JSON.stringify({verdict:'revoked',chainStatus:'valid',checkedAt:capturedAt,validUntil:expiry})]);
      const disputed=await listCertificateIdentities({client:db,workspaceId,status:'revoked'});
      assert.equal(disputed.items.find(item=>item.fingerprintSha256===original.observed_fingerprint_sha256).securityStatus.state,'revoked');
      assert.ok(!(await listCertificateIdentities({client:db,workspaceId,status:'active'})).items.some(item=>item.fingerprintSha256===original.observed_fingerprint_sha256));
      await db.query("UPDATE certificate_instances SET public_metadata='{}'::jsonb WHERE id=$1",[duplicate.id]);
      await db.query('UPDATE certificate_instances SET public_metadata=$2 WHERE id=$1',[original.id,original.public_metadata]);
      const observations = (await db.query("SELECT metadata FROM certificate_evidence WHERE workspace_id=$1 AND evidence_type='certificate.observed'", [workspaceId])).rows;
      assert.equal(observations.length, 2);
      for (const { metadata } of observations) {
        assert.equal(metadata.managedCertificateId, certs.find((c) => c.fingerprint_sha256 === metadata.fingerprintSha256).id);
      }
      // Simulate a legacy subject-keyed managed certificate whose existing
      // profile and history must survive detection during migration.
      const legacy = certs[0];
      const profile = (await db.query("INSERT INTO certificate_profiles(workspace_id,name) VALUES ($1,'Existing profile') RETURNING id", [workspaceId])).rows[0].id;
      await db.query("UPDATE managed_certificates SET source_ref=$1, profile_id=$2 WHERE id=$3", [
        `${agentId}/pilot.example.test/windows_store/LocalMachine/My/shared.example.test`, profile, legacy.id,
      ]);
      await db.query("UPDATE certops_management_periods SET automation_enabled=TRUE WHERE managed_certificate_id=$1 AND ended_at IS NULL", [legacy.id]);
      const beforeEvidence = (await db.query("SELECT count(*)::int AS count FROM certificate_evidence WHERE workspace_id=$1", [workspaceId])).rows[0].count;
      // The guard reads the existing identity, without moving its profile or
      // modifying the historical evidence.
      assert.equal((await db.query("SELECT profile_id FROM managed_certificates WHERE id=$1", [legacy.id])).rows[0].profile_id, profile);
      assert.equal((await db.query("SELECT count(*)::int AS count FROM certificate_evidence WHERE workspace_id=$1", [workspaceId])).rows[0].count, beforeEvidence);
      const due = await findCertificatesDueForRenewal({ db, thresholdDays: 30, terminalStatuses: ["failed", "cancelled", "succeeded"] });
      assert.equal(due.some((row) => row.id === legacy.id), false);
      const legacyRef = `${agentId}/pilot.example.test/windows_store/LocalMachine/My/shared.example.test`;
      await db.query("UPDATE managed_certificates SET source_ref=$1 WHERE id=$2", [`${agentId}/pilot.example.test/iis_binding/site:443`, legacy.id]);
      const otherwiseDue = await findCertificatesDueForRenewal({ db, thresholdDays: 30, terminalStatuses: ["failed", "cancelled", "succeeded"] });
      assert.equal(otherwiseDue.some((row) => row.id === legacy.id), true, "the store guard must be the reason scheduling is blocked");
      await db.query("UPDATE managed_certificates SET source_ref=$1 WHERE id=$2", [legacyRef, legacy.id]);
      const health = await resolveRenewalPathForCertificate({ db, workspaceId, certificateId: legacy.id });
      assert.equal(health.renewalPathReason, "windows_store_reassociation");
      assert.match(health.renewalPathSummary, /paused/);
      await assert.rejects(preflightManualRenewalRouting({ client: db, workspaceId, certificateId: legacy.id, payload: {} }),
        { code: "CERTOPS_CERTIFICATE_NOT_RENEWABLE" });
      const pending = (await db.query(`INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status)
        VALUES($1,'managed_certificate',$2,'renew','pending') RETURNING id`, [workspaceId, legacy.id])).rows[0];
      const signed = [];
      const claims = await claimJobs({ dbPool: db, agent,
        body: { supportedActions: ["renew"], maxJobs: 2 },
        deps: { enforceAgentSequence: async () => {},
          lockWorkspaceForCertOpsSideEffect: (args) => require("../../apps/api/services/certops/workspaceKillSwitch")
            .lockWorkspaceForCertOpsSideEffect({ ...args, env: { CERTOPS_ENABLED: "true" } }),
          computeAgentCompatibility: () => ({ compatibilityState: "compatible" }),
          signJobForDispatch: async (args) => { signed.push(args); return args; } } });
      assert.equal(claims.jobs.length, 0);
      assert.equal(signed.length, 0);
      assert.equal((await db.query("SELECT status FROM certificate_jobs WHERE id=$1", [pending.id])).rows[0].status, "pending");
      const oldPeriod = (await db.query("SELECT id FROM certops_management_periods WHERE managed_certificate_id=$1 AND ended_at IS NULL", [legacy.id])).rows[0].id;
      const current = certs.find((c) => c.id !== legacy.id);
      await assert.rejects(replaceManagingSource({ client: db, workspaceId, periodId: oldPeriod,
        managedCertificateId: current.id, renewalProfileId: profile, automationEnabled: true }),
      { code: "CERTOPS_MANAGEMENT_PERIOD_MISMATCH" });
      assert.equal((await db.query("SELECT profile_id FROM managed_certificates WHERE id=$1", [legacy.id])).rows[0].profile_id, profile,
        "cross-source reassociation refusal leaves the original profile intact");
    });
  }

  it("transfers verified store renewal lineage and serializes concurrent discovery", async () => {
    const workspaceId = (await db.query("INSERT INTO workspaces(id,name,plan,created_by) VALUES (gen_random_uuid(),'Renewal concurrency','oss',$1) RETURNING id", [userId])).rows[0].id;
    const agentId = `collision-${randomUUID()}`;
    const id = (await db.query(`INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash)
      VALUES($1,$2,'test','1.0.0',$3,$4) RETURNING id`, [workspaceId, agentId,
      `ttagent_${randomUUID().replaceAll("-", "").slice(0, 16)}`, createHash("sha256").update(agentId).digest("hex")])).rows[0].id;
    const agent = bindAuthenticatedCredential({ id, agentId, workspaceId, hostname: "pilot.example.test" }, agentId);
    const initialExpiry = new Date(Date.now() + 86400000).toISOString();
    const item = (fingerprint) => ({ evidenceId: randomUUID(), eventType: "certificate.observed",
      observedAt: new Date().toISOString(), fingerprintSha256: fingerprint,
      metadata: [{ name: "locationKind", value: "windows_store" },
        { name: "locationSlot", value: "LocalMachine/My/shared.example.test" },
        { name: "targetHost", value: "pilot.example.test" },
        { name: "storeLocation", value: "LocalMachine" }, { name: "storeName", value: "My" },
        { name: "subject", value: "CN=shared.example.test" },
        { name: "validTo", value: initialExpiry }] });
    await persistAgentDiscoveryEvidenceBatch({ dbPool: db, agent, envelope: { sequence: 1 }, evidenceItems: [item("a".repeat(64))] });
    const certId = (await db.query("SELECT id FROM managed_certificates WHERE workspace_id=$1", [workspaceId])).rows[0].id;
    const job = (await db.query(`INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,claim_id)
      VALUES($1,'managed_certificate',$2,'renew','claimed',$3) RETURNING *`, [workspaceId, certId, randomUUID()])).rows[0];
    const renewedFingerprint = "b".repeat(64);
    await db.query("INSERT INTO certificate_evidence(workspace_id,job_id,evidence_type,claim_id,metadata) VALUES($1,$2,'validation.passed',$3,$4::jsonb)",
      [workspaceId, job.id, job.claim_id, JSON.stringify({ step: "verify", fingerprintSha256: renewedFingerprint, validTo: initialExpiry })]);
    const client = await db.connect();
    let pending;
    try {
      await client.query("BEGIN");
      const result = await dispatchTest.refreshRenewedCertificateEvidence({ client, workspaceId, job });
      assert.equal(result.refreshed, true);
      pending = persistAgentDiscoveryEvidenceBatch({ dbPool: db, agent, envelope: { sequence: 2 }, evidenceItems: [item(renewedFingerprint)] });
      const blockerPid = (await client.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      let blocked = false;
      for (let i = 0; i < 100; i++) {
        const blockers = await db.query("SELECT 1 FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))", [blockerPid]);
        if (blockers.rowCount) { blocked = true; break; }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      assert.equal(blocked, true, "discovery waits for the renewal transaction's store lock");
      await client.query("COMMIT");
      await pending;
    } catch (error) { await client.query("ROLLBACK"); if (pending) await pending.catch(() => {}); throw error; }
    finally { client.release(); }
    const rows = (await db.query("SELECT id,fingerprint_sha256,source_ref FROM managed_certificates WHERE workspace_id=$1", [workspaceId])).rows;
    assert.equal(rows.length, 1);
    assert.equal(rows[0].id, certId);
    assert.equal(rows[0].fingerprint_sha256, renewedFingerprint);
    assert.ok(rows[0].source_ref.endsWith(`/sha256-${renewedFingerprint}`));

    // If discovery already created the next fingerprint, do not guess which
    // existing row owns the profile. Preserve both and pause automation.
    await db.query("UPDATE certificate_jobs SET status='succeeded' WHERE id=$1", [job.id]);
    const secondFingerprint = "d".repeat(64);
    const secondJob = (await db.query(`INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,claim_id)
      VALUES($1,'managed_certificate',$2,'renew','claimed',$3) RETURNING *`, [workspaceId, certId, randomUUID()])).rows[0];
    await db.query("INSERT INTO certificate_evidence(workspace_id,job_id,evidence_type,claim_id,metadata) VALUES($1,$2,'validation.passed',$3,$4::jsonb)",
      [workspaceId, secondJob.id, secondJob.claim_id, JSON.stringify({ step: "verify", fingerprintSha256: secondFingerprint, validTo: initialExpiry })]);
    const secondTx = await db.connect();
    try {
      await secondTx.query("BEGIN");
      assert.equal((await dispatchTest.refreshRenewedCertificateEvidence({ client: secondTx, workspaceId, job: secondJob })).refreshed, true);
      await secondTx.query("COMMIT");
    } catch (error) { await secondTx.query("ROLLBACK"); throw error; }
    finally { secondTx.release(); }
    await db.query("UPDATE certificate_jobs SET status='succeeded' WHERE id=$1", [secondJob.id]);
    await persistAgentDiscoveryEvidenceBatch({ dbPool: db, agent, envelope: { sequence: 3 }, evidenceItems: [item(secondFingerprint)] });
    const secondRows = (await db.query("SELECT id,fingerprint_sha256,source_ref FROM managed_certificates WHERE workspace_id=$1", [workspaceId])).rows;
    assert.equal(secondRows.length, 1);
    assert.equal(secondRows[0].id, certId);
    assert.ok(secondRows[0].source_ref.endsWith(`/sha256-${secondFingerprint}`));
    assert.equal((await db.query("SELECT count(*)::int AS count FROM certops_certificate_identities WHERE workspace_id=$1", [workspaceId])).rows[0].count, 3);
    const conflictFingerprint = "c".repeat(64);
    await persistAgentDiscoveryEvidenceBatch({ dbPool: db, agent, envelope: { sequence: 4 }, evidenceItems: [item(conflictFingerprint)] });
    const profile = (await db.query("INSERT INTO certificate_profiles(workspace_id,name) VALUES ($1,'Renewal profile') RETURNING id", [workspaceId])).rows[0].id;
    await db.query("UPDATE managed_certificates SET profile_id=$2 WHERE id=$1", [certId, profile]);
    await db.query("UPDATE certops_management_periods SET automation_enabled=TRUE WHERE managed_certificate_id=$1 AND ended_at IS NULL", [certId]);
    const conflictJob = (await db.query(`INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status,claim_id)
      VALUES($1,'managed_certificate',$2,'renew','claimed',$3) RETURNING *`, [workspaceId, certId, randomUUID()])).rows[0];
    await db.query("INSERT INTO certificate_evidence(workspace_id,job_id,evidence_type,claim_id,metadata) VALUES($1,$2,'validation.passed',$3,$4::jsonb)",
      [workspaceId, conflictJob.id, conflictJob.claim_id, JSON.stringify({ step: "verify", fingerprintSha256: conflictFingerprint, validTo: initialExpiry })]);
    const tx = await db.connect();
    try {
      await tx.query("BEGIN");
      const outcome = await dispatchTest.refreshRenewedCertificateEvidence({ client: tx, workspaceId, job: conflictJob });
      assert.equal(outcome.reason, "windows_store_identity_conflict");
      await tx.query("COMMIT");
    } catch (error) { await tx.query("ROLLBACK"); throw error; }
    finally { tx.release(); }
    const afterConflict = (await db.query("SELECT id,fingerprint_sha256,profile_id,reconciliation_reason FROM managed_certificates WHERE workspace_id=$1", [workspaceId])).rows;
    assert.equal(afterConflict.length, 2);
    assert.equal(afterConflict.find((row) => row.id === certId).fingerprint_sha256, secondFingerprint);
    assert.equal(afterConflict.find((row) => row.id === certId).profile_id, profile);
    assert.equal(afterConflict.find((row) => row.id === certId).reconciliation_reason, "windows_store_identity_conflict");
    await db.query("UPDATE certificate_jobs SET status='succeeded' WHERE id=$1", [conflictJob.id]);
    assert.equal((await findCertificatesDueForRenewal({ db, thresholdDays: 30, terminalStatuses: ["failed", "cancelled", "succeeded"] })).some((row) => row.id === certId), false);
    assert.equal((await resolveRenewalPathForCertificate({ db, workspaceId, certificateId: certId })).renewalPathReason, "windows_store_reassociation");
    await persistAgentDiscoveryEvidenceBatch({ dbPool: db, agent, envelope: { sequence: 5 }, evidenceItems: [item("a".repeat(64))] });
    const laterRows = (await db.query("SELECT id,fingerprint_sha256 FROM managed_certificates WHERE workspace_id=$1", [workspaceId])).rows;
    assert.equal(laterRows.length, 3, "an old store certificate remains independently observable");
    assert.equal(laterRows.find((row) => row.id === certId).fingerprint_sha256, secondFingerprint,
      "rediscovering the old certificate must not undo verified renewal");
  });

  it("refuses store-only reassociation until its separate workflow is qualified", async () => {
    const workspaceId = (await db.query("INSERT INTO workspaces(id,name,plan,created_by) VALUES(gen_random_uuid(),'Reassociation','oss',$1) RETURNING id", [userId])).rows[0].id;
    const agentId = `reassociation-${randomUUID()}`;
    const agentRowId = (await db.query(`INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash,status,last_seen_at,declared_target_selectors)
      VALUES($1,$2,'test','1.0.0',$3,$4,'active',NOW(),$5::jsonb) RETURNING id`, [workspaceId,agentId,
      `ttagent_${randomUUID().replaceAll("-", "").slice(0,16)}`,createHash("sha256").update(agentId).digest("hex"),JSON.stringify(["certops.example"])])).rows[0].id;
    const agent = bindAuthenticatedCredential({ id:agentRowId, agentId,workspaceId,hostname:"pilot.example.test" }, agentId);
    const pem = readFileSync(join(__dirname,"../fixtures/certops-public-observation.txt"),"utf8");
    const leaf = new X509Certificate(pem);
    const fingerprint = leaf.fingerprint256.replaceAll(":","").toLowerCase();
    const observation = (fp, extra=[]) => ({ evidenceId:randomUUID(),eventType:"certificate.observed",observedAt:new Date().toISOString(),fingerprintSha256:fp,
      metadata:[{name:"locationKind",value:"windows_store"},{name:"locationSlot",value:"LocalMachine/My/certops.example"},
        {name:"targetHost",value:"pilot.example.test"},{name:"storeLocation",value:"LocalMachine"},{name:"storeName",value:"My"},
        {name:"thumbprint",value:"a".repeat(40)},{name:"keyPresent",value:true},{name:"subject",value:"CN=certops.example"},
        {name:"validTo",value:new Date(leaf.validTo).toISOString()},...extra] });
    const first = await persistAgentDiscoveryEvidenceBatch({dbPool:db,agent,envelope:{sequence:1},evidenceItems:[observation("d".repeat(64))]});
    const legacyId = first.items[0].managedCertificateId;
    await db.query("UPDATE managed_certificates SET source_ref=$2 WHERE id=$1", [legacyId,`${agentId}/pilot.example.test/windows_store/LocalMachine/My/certops.example`]);
    const second = await persistAgentDiscoveryEvidenceBatch({dbPool:db,agent,envelope:{sequence:2},evidenceItems:[observation(fingerprint,[{name:"certificatePem",value:pem}])]});
    const currentId=second.items[0].managedCertificateId;
    const profileId=(await db.query("INSERT INTO certificate_profiles(workspace_id,name,public_metadata) VALUES($1,'Store renewal',$2::jsonb) RETURNING id",
      [workspaceId,JSON.stringify({renewalProfile:{target:{type:"windows-cert-store",reference:"certops.example",store:"My"},sanPolicy:{sans:["certops.example"]}}})])).rows[0].id;
    await db.query("UPDATE managed_certificates SET profile_id=$2 WHERE id=$1",[legacyId,profileId]);
    await db.query("UPDATE certops_management_periods SET renewal_profile_id=$2,automation_enabled=TRUE WHERE managed_certificate_id=$1 AND ended_at IS NULL",[legacyId,profileId]);
    const periods=(await db.query("SELECT id,managed_certificate_id FROM certops_management_periods WHERE workspace_id=$1 AND ended_at IS NULL",[workspaceId])).rows;
    const legacyPeriodId=periods.find((p)=>p.managed_certificate_id===legacyId).id;
    const currentPeriodId=periods.find((p)=>p.managed_certificate_id===currentId).id;
    const params={dbPool:db,workspaceId,legacyId,currentId,legacyPeriodId,currentPeriodId,agentId:agentRowId,expectedFingerprintSha256:fingerprint,expectedDnsName:"certops.example",actorUserId:userId};
    await assert.rejects(reassociateWindowsStore({...params,expectedFingerprintSha256:"f".repeat(64)}),{code:"CERTOPS_WINDOWS_REASSOCIATION_REFUSED"});
    await assert.rejects(reassociateWindowsStore({...params,expectedDnsName:"wrong.example"}),{code:"CERTOPS_WINDOWS_REASSOCIATION_REFUSED"});
    await assert.rejects(reassociateWindowsStore({...params,actorUserId:null}),{code:"CERTOPS_WINDOWS_REASSOCIATION_REFUSED"});
    const job=(await db.query("INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status) VALUES($1,'managed_certificate',$2,'renew','pending') RETURNING id",[workspaceId,legacyId])).rows[0];
    await assert.rejects(reassociateWindowsStore(params),(error)=>{ if(error.code!=="CERTOPS_WINDOWS_REASSOCIATION_REFUSED") throw error; return true; });
    await db.query("UPDATE certificate_jobs SET status='cancelled' WHERE id=$1",[job.id]);
    await db.query("UPDATE certificate_instances SET captured_at=NOW()-interval '25 hours' WHERE managed_certificate_id=$1",[currentId]);
    await assert.rejects(reassociateWindowsStore(params),{code:"CERTOPS_WINDOWS_REASSOCIATION_REFUSED"});
    await db.query("UPDATE certificate_instances SET captured_at=NOW() WHERE managed_certificate_id=$1",[currentId]);
    await assert.rejects(reassociateWindowsStore(params),{code:"CERTOPS_WINDOWS_REASSOCIATION_REFUSED"});
    const after=(await db.query("SELECT managed_certificate_id,renewal_profile_id,automation_enabled FROM certops_management_periods WHERE workspace_id=$1 AND ended_at IS NULL",[workspaceId])).rows;
    assert.ok(after.some((r)=>r.managed_certificate_id===legacyId && r.renewal_profile_id===profileId));
    assert.equal((await db.query("SELECT count(*)::int AS n FROM certops_management_periods WHERE workspace_id=$1 AND ended_at IS NOT NULL",[workspaceId])).rows[0].n,0);
    assert.equal((await db.query("SELECT count(*)::int AS n FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_WINDOWS_STORE_REASSOCIATED'",[workspaceId])).rows[0].n,0);
    assert.equal((await db.query("SELECT count(*)::int AS n FROM certops_windows_iis_renewal_consumers WHERE workspace_id=$1 AND automatic_update",[workspaceId])).rows[0].n,0);
  });
  it("reassociates an IIS profile only to the freshly observed matching binding", async () => {
    const workspaceId = (await db.query("INSERT INTO workspaces(id,name,plan,created_by) VALUES(gen_random_uuid(),'IIS reassociation','oss',$1) RETURNING id", [userId])).rows[0].id;
    const agentId = `iis-reassociation-${randomUUID()}`;
    const agentRowId = (await db.query(`INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash,status,last_seen_at,declared_target_selectors)
      VALUES($1,$2,'test','1.0.0',$3,$4,'active',NOW(),$5::jsonb) RETURNING id`, [workspaceId,agentId,
      `ttagent_${randomUUID().replaceAll('-', '').slice(0,16)}`,createHash('sha256').update(agentId).digest('hex'),JSON.stringify(['certops.example'])])).rows[0].id;
    const agent=bindAuthenticatedCredential({id:agentRowId,agentId,workspaceId,hostname:'pilot.example.test'},agentId);
    const pem=readFileSync(join(__dirname,'../fixtures/certops-public-observation.txt'),'utf8');
    const leaf=new X509Certificate(pem), fingerprint=leaf.fingerprint256.replaceAll(':','').toLowerCase();
    const item=(kind,port,fp,extra=[])=>({evidenceId:randomUUID(),eventType:'certificate.observed',observedAt:new Date().toISOString(),fingerprintSha256:fp,metadata:[
      {name:'locationKind',value:kind},{name:'locationSlot',value:kind==='iis_binding'?`Default Web Site:${port}`:'LocalMachine/My/certops.example'},
      {name:'targetHost',value:'pilot.example.test'},{name:'storeLocation',value:'LocalMachine'},{name:'storeName',value:'My'},
      {name:'thumbprint',value:'a'.repeat(40)},{name:'keyPresent',value:true},{name:'subject',value:'CN=certops.example'},
      {name:'validTo',value:new Date(leaf.validTo).toISOString()},...extra,...(kind==='iis_binding'?[{name:'siteName',value:'Default Web Site'},{name:'port',value:port}]:[])]});
    const first=await persistAgentDiscoveryEvidenceBatch({dbPool:db,agent,envelope:{sequence:1},evidenceItems:[item('windows_store',null,'d'.repeat(64))]});
    const legacyId=first.items[0].managedCertificateId;
    await db.query('UPDATE managed_certificates SET source_ref=$2 WHERE id=$1',[legacyId,`${agentId}/pilot.example.test/windows_store/LocalMachine/My/certops.example`]);
    const observed=await persistAgentDiscoveryEvidenceBatch({dbPool:db,agent,envelope:{sequence:2},evidenceItems:[item('iis_binding',443,fingerprint,[{name:'subjectAltNames',value:JSON.stringify(['certops.example'])}]),item('iis_binding',444,fingerprint,[{name:'subjectAltNames',value:JSON.stringify(['certops.example'])}])]});
    const currentId=observed.items[0].managedCertificateId, wrongId=observed.items[1].managedCertificateId;
    const profileId=(await db.query("INSERT INTO certificate_profiles(workspace_id,name,public_metadata) VALUES($1,'IIS renewal',$2::jsonb) RETURNING id",[workspaceId,JSON.stringify({renewalProfile:{target:{type:'windows-iis',reference:'certops.example',store:'My',binding:{site:'Default Web Site',port:443}},sanPolicy:{sans:['certops.example']}}})])).rows[0].id;
    await db.query("UPDATE certificate_profiles SET status='disabled' WHERE id=$1",[profileId]);
    await db.query('UPDATE managed_certificates SET profile_id=$2 WHERE id=$1',[legacyId,profileId]);
    await db.query('UPDATE certops_management_periods SET renewal_profile_id=$2,automation_enabled=TRUE WHERE managed_certificate_id=$1 AND ended_at IS NULL',[legacyId,profileId]);
    const periods=(await db.query('SELECT id,managed_certificate_id FROM certops_management_periods WHERE workspace_id=$1 AND ended_at IS NULL',[workspaceId])).rows;
    const period=id=>periods.find(p=>p.managed_certificate_id===id).id;
    const params={dbPool:db,workspaceId,legacyId,currentId,legacyPeriodId:period(legacyId),currentPeriodId:period(currentId),agentId:agentRowId,expectedFingerprintSha256:fingerprint,expectedDnsName:'certops.example',actorUserId:userId};
    const choices=await listIisReassociationCandidates({client:db,workspaceId,legacyId});
    assert.equal(choices.length,1);
    assert.equal(choices[0].currentId,currentId);
    assert.equal(choices[0].port,443);
    await assert.rejects(reassociateWindowsStore({...params,currentId:wrongId,currentPeriodId:period(wrongId)}),{code:'CERTOPS_WINDOWS_REASSOCIATION_REFUSED'});
    await assert.rejects(reassociateWindowsStore({...params,expectedFingerprintSha256:'f'.repeat(64)}),{code:'CERTOPS_WINDOWS_REASSOCIATION_REFUSED'});
    await assert.rejects(reassociateWindowsStore({...params,expectedDnsName:'wrong.example'}),{code:'CERTOPS_WINDOWS_REASSOCIATION_REFUSED'});
    await db.query("UPDATE certificate_instances SET captured_at=NOW()-interval '25 hours' WHERE managed_certificate_id=$1",[currentId]);
    await assert.rejects(reassociateWindowsStore(params),{code:'CERTOPS_WINDOWS_REASSOCIATION_REFUSED'});
    await db.query('UPDATE certificate_instances SET captured_at=NOW() WHERE managed_certificate_id=$1',[currentId]);
    const job=(await db.query("INSERT INTO certificate_jobs(workspace_id,subject_type,subject_id,operation,status) VALUES($1,'managed_certificate',$2,'renew','claimed') RETURNING id",[workspaceId,legacyId])).rows[0];
    await assert.rejects(reassociateWindowsStore(params),{code:'CERTOPS_WINDOWS_REASSOCIATION_REFUSED'});
    await db.query("UPDATE certificate_jobs SET status='cancelled' WHERE id=$1",[job.id]);
    const issuer=(await db.query("INSERT INTO certificate_issuers(workspace_id,kind,name) VALUES($1,'adcs','Test CA') RETURNING id",[workspaceId])).rows[0].id;
    const enrollment=(await db.query("INSERT INTO certificate_enrollments(workspace_id,certificate_id,issuer_id,issuer_version,state,snapshot_bytes,snapshot_sha256,deploy_target) VALUES($1,$2,$3,1,'pending_issuance',$4,$5,'{}'::jsonb) RETURNING id",[workspaceId,legacyId,issuer,Buffer.from('{}'),'a'.repeat(64)])).rows[0].id;
    await assert.rejects(reassociateWindowsStore(params),{code:'CERTOPS_WINDOWS_REASSOCIATION_REFUSED'});
    await db.query("UPDATE certificate_enrollments SET state='installed' WHERE id=$1",[enrollment]);
    await db.query('UPDATE certops_management_periods SET renewal_profile_id=$2,automation_enabled=TRUE WHERE id=$1',[period(wrongId),profileId]);
    await assert.rejects(reassociateWindowsStore(params),{code:'CERTOPS_WINDOWS_REASSOCIATION_REFUSED'});
    await db.query('UPDATE certops_management_periods SET renewal_profile_id=NULL,automation_enabled=FALSE WHERE id=$1',[period(wrongId)]);
    const result=await reassociateWindowsStore(params);
    assert.equal(result.managedCertificateId,currentId);
    const audit=(await db.query(`SELECT action,metadata FROM audit_events WHERE workspace_id=$1
      AND action IN ('CERTOPS_MANAGEMENT_STOPPED','CERTOPS_MANAGEMENT_STARTED','CERTOPS_WINDOWS_STORE_REASSOCIATED')`,[workspaceId])).rows;
    const started=audit.find(row=>row.action==='CERTOPS_MANAGEMENT_STARTED' && row.metadata.periodId===result.periodId);
    assert.equal(started.metadata.managedCertificateId,currentId);
    assert.equal(started.metadata.renewalProfileId,profileId);
    assert.equal(started.metadata.automationEnabled,true);
    assert.equal(started.metadata.fingerprintSha256,fingerprint);
    const stopped=audit.find(row=>row.action==='CERTOPS_MANAGEMENT_STOPPED' && row.metadata.periodId===period(legacyId));
    assert.equal(stopped.metadata.managedCertificateId,legacyId);
    assert.equal(stopped.metadata.renewalProfileId,profileId);
    assert.equal(stopped.metadata.automationEnabled,true);
    const reassociated=audit.find(row=>row.action==='CERTOPS_WINDOWS_STORE_REASSOCIATED');
    assert.equal(reassociated.metadata.currentId,currentId);
    assert.equal(reassociated.metadata.legacyId,legacyId);
    assert.equal(reassociated.metadata.profileId,profileId);
    assert.equal(reassociated.metadata.fingerprintSha256,fingerprint);
    const rows=(await db.query('SELECT managed_certificate_id,renewal_profile_id FROM certops_management_periods WHERE workspace_id=$1 AND ended_at IS NULL',[workspaceId])).rows;
    assert.equal(rows.find(r=>r.managed_certificate_id===currentId).renewal_profile_id,profileId);
    assert.equal(rows.find(r=>r.managed_certificate_id===wrongId).renewal_profile_id,null);
    const listed = await listRenewalProfiles({ db, workspaceId });
    const moved = listed.items.find(item => item.id === profileId);
    assert.equal(moved.certificateCount, 1);
    assert.deepEqual(moved.certificates.map(item => item.id), [currentId]);
    assert.equal((await db.query('SELECT status FROM certificate_profiles WHERE id=$1',[profileId])).rows[0].status,'disabled');
  });
});
