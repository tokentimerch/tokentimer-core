"use strict";
/** Real Linux CSR-based ACME key reuse. Run after rotation controls and before
 * agent retirement. The parent owns the agent, TLS listener, jobs and all local
 * files; this helper registers each admitted job before waiting for completion.
 * Only the public profile API changes policy. No inventory dates are rewritten. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const scope = "real-linux-manual-and-default-scheduler-csr-key-reuse";
const scenarioName = "real ACME: manual and default scheduler renewals reuse the same local key";
const fields = ["publicProfilePolicyChanged", "manualRenewalSucceeded", "defaultSqlNowRenewalSucceeded", "claimBoundVerification", "unchangedPrivateCustody", "privateMaterialStayedLocal", "unchangedSpki", "distinctCaLeavesAndSerials", "advancingExpiry", "trustedTlsEachGeneration", "dnsCleanEachGeneration", "stableReuseProfile"];
const requiredSources = ["tests/e2e/helpers/certops-acme-key-reuse.js", "tests/e2e/acme-real-journey.js", "packages/agent/src/index.js", "packages/agent/src/keys/index.js", "packages/agent/src/acme/index.js", "packages/agent/src/signing/index.js", "apps/api/services/certops/renewalProfileAdmin.js", "apps/api/services/certops/renewalProfile.js", "apps/api/services/certops/renewalScheduler.js", "apps/api/services/certops/agentDispatch.js"];
function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof));
  assert.deepEqual(Object.keys(proof).sort(), [...fields, "scope", "client", "fingerprints", "serials", "spkiFingerprint", "jobIds", "sourceProfileId", "sourceProfileFingerprint"].sort());
  assert.equal(proof.scope, scope); assert.ok(["certbot", "acme.sh"].includes(proof.client));
  for (const field of fields) assert.equal(proof[field], true, field);
  for (const name of ["fingerprints", "serials"]) {
    assert.ok(Array.isArray(proof[name])); assert.equal(proof[name].length, 3);
    for (const value of proof[name]) assert.match(value, name === "serials" ? /^[A-F0-9]{1,64}$/ : /^[a-f0-9]{64}$/);
    assert.equal(new Set(proof[name]).size, 3);
  }
  assert.match(proof.spkiFingerprint, /^[a-f0-9]{64}$/);
  assert.match(proof.sourceProfileFingerprint, /^[a-f0-9]{64}$/);
  assert.match(proof.sourceProfileId, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i);
  assert.ok(Array.isArray(proof.jobIds)); assert.equal(proof.jobIds.length, 2);
  for (const id of proof.jobIds) assert.match(id, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i);
  assert.equal(new Set(proof.jobIds.map(id => id.toLowerCase())).size, 2); return true;
}
async function qualifyKeyReuse({ pool, workspaceId, agent, publicSession, certificateId, certPath, keyPath, ownedJobIds, waitUntil, verifyDnsCleanup, verifyNames, servedFingerprint, repoRoot, acmeKind }) {
  assert.equal(process.platform, "linux"); assert.ok(["certbot", "acme.sh"].includes(acmeKind));
  const query = (sql, args = []) => pool.query(sql, args);
  const profile = async () => (await query("SELECT cp.id, cp.public_metadata, cp.renew_before_days, cp.status, cp.updated_at FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2", [workspaceId, certificateId])).rows[0];
  const original = await profile(); assert.ok(original); assert.equal(original.status, "active");
  assert.equal(original.public_metadata.renewalProfile.keyRotationPolicy.rotateOnRenew, true, "Run reuse only after the journey's positive rotation controls");
  const expected = structuredClone(original.public_metadata.renewalProfile); expected.keyRotationPolicy.rotateOnRenew = false;
  const changed = await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/profiles/${original.id}`, "PATCH", { renewalProfile: expected });
  assert.equal(changed.status, 200); const stable = await profile(); assert.deepEqual(stable.public_metadata.renewalProfile, expected);
  const privateBytes = fs.readFileSync(keyPath), privateKey = crypto.createPrivateKey(privateBytes);
  const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
  const spki = leaf => sha(leaf.publicKey.export({ type: "spki", format: "der" }));
  const leaves = [], jobs = [];
  const observe = async () => {
    const stat = fs.lstatSync(keyPath); assert.equal(stat.isFile(), true); assert.equal(stat.isSymbolicLink(), false);
    assert.equal(stat.mode & 0o777, 0o600); assert.equal(stat.uid, process.getuid()); assert.equal(stat.nlink, 1);
    assert.ok(fs.readFileSync(keyPath).equals(privateBytes), "Actual local private key bytes must remain unchanged");
    const leaf = new crypto.X509Certificate(fs.readFileSync(certPath)); verifyNames(leaf);
    assert.ok(leaf.checkPrivateKey(privateKey)); assert.equal(await servedFingerprint(), leaf.fingerprint256);
    await verifyDnsCleanup(); if (leaves.length) {
      assert.equal(spki(leaf), spki(leaves[0])); assert.ok(Date.parse(leaf.validTo) > Date.parse(leaves.at(-1).validTo));
      for (const prior of leaves) { assert.notEqual(leaf.fingerprint256, prior.fingerprint256); assert.notEqual(leaf.serialNumber, prior.serialNumber); }
    }
    leaves.push(leaf);
  };
  await observe();
  const complete = async job => {
    await waitUntil(async () => {
      assert.equal(agent.exitCode, null); assert.equal(agent.signalCode, null);
      const row = (await query("SELECT status,payload,claim_id,source,mode,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, job.id])).rows[0];
      assert.ok(row); if (["failed", "rejected", "cancelled", "blocked", "orphaned_unknown_effect"].includes(row.status)) throw new Error("Real key-reuse renewal terminated unsuccessfully");
      if (row.status !== "succeeded") return false;
      assert.equal(row.mode, "real"); assert.equal(row.payload.keyRotation, false); assert.equal(row.source, job.source); assert.ok(row.claim_id);
      assert.deepEqual(row.payload.renewalProfile, expected, "Claimed execution must retain the complete stable source profile snapshot");
      assert.equal(row.payload.acmeKind, acmeKind); assert.equal(row.payload.commandRef, expected.acme.commandRef); assert.equal(row.payload.caEndpoint, expected.ca.endpoint);
      assert.deepEqual([...row.payload.sans].sort(), [...expected.sanPolicy.sans].sort()); assert.equal(row.payload.certPath, certPath);
      assert.equal(row.result_metadata.keyRotated, false);
      assert.ok((await query("SELECT 1 FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.claim_id=j.claim_id AND e.evidence_type='validation.passed' AND e.metadata->>'step'='verify'", [workspaceId, job.id])).rows.length);
      const publicData = JSON.stringify([row, (await query("SELECT metadata,redacted_output FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [workspaceId, job.id])).rows]);
      const bodySentinel = privateBytes.toString("utf8").split(/\r?\n/).find(line => line && !line.startsWith("-----"));
      assert.ok(bodySentinel && bodySentinel.length >= 32);
      assert.equal([privateBytes.toString("utf8"), privateBytes.toString("base64"), bodySentinel, "PRIVATE KEY-----"].some(secret => publicData.includes(secret)), false, "Actual private material must remain absent from persisted public job and evidence data");
      return true;
    }, 180000);
    await observe(); assert.deepEqual(await profile(), stable);
  };
  // Let the real CA's second-resolution notAfter advance; this is actual time,
  // not a scheduler clock override or manufactured inventory eligibility.
  await new Promise(resolve => setTimeout(resolve, 1500));
  const manual = await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/jobs`, "POST", { operation: "renew", subjectType: "managed_certificate", subjectId: String(certificateId), idempotencyKey: crypto.randomUUID() });
  assert.equal(manual.status, 201); ownedJobIds.push(manual.body.job.id); jobs.push({ id: manual.body.job.id, source: "api" }); await complete(jobs[0]);
  await new Promise(resolve => setTimeout(resolve, 1500));
  const due = (await query("SELECT mc.not_after, mc.not_after <= NOW() + (COALESCE(cp.renew_before_days,30) || ' days')::interval AS due FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2 AND cp.status='active' AND EXISTS (SELECT 1 FROM certops_management_periods p WHERE p.workspace_id=mc.workspace_id AND p.managed_certificate_id=mc.id AND p.ended_at IS NULL AND p.automation_enabled=TRUE)", [workspaceId, certificateId])).rows[0];
  assert.equal(due?.due, true, "Actual SQL NOW must select the naturally due managed certificate");
  const scheduler = require(path.join(repoRoot, "apps/api/services/certops/renewalScheduler.js"));
  const key = scheduler.renewalIdempotencyKey(certificateId, due.not_after);
  assert.equal((await query("SELECT 1 FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key=$2", [workspaceId, key])).rows.length, 0);
  // Capture jobs even when the sweep reports an error, so parent cleanup owns
  // any committed admission rather than losing it on the assertion below.
  let sweep;
  try { sweep = await scheduler.runRenewalSchedulerSweep({ dbPool: pool, env: process.env }); }
  finally {
    const admitted = (await query("SELECT id,source FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND idempotency_key=$3", [workspaceId, String(certificateId), key])).rows;
    for (const job of admitted) { ownedJobIds.push(job.id); jobs.push(job); }
  }
  assert.equal(sweep.errors.length, 0); assert.equal(jobs.length, 2); assert.equal(jobs[1].source, "automation"); await complete(jobs[1]);
  const proof = { scope, client: acmeKind, ...Object.fromEntries(fields.map(field => [field, true])), fingerprints: leaves.map(leaf => sha(leaf.raw)), serials: leaves.map(leaf => leaf.serialNumber), spkiFingerprint: spki(leaves[0]), jobIds: jobs.map(job => job.id), sourceProfileId: stable.id, sourceProfileFingerprint: sha(JSON.stringify(stable)) };
  verifyProof(proof); return proof;
}
module.exports = { qualifyKeyReuse, verifyProof, scope, scenarioName, fields, requiredSources };
