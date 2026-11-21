"use strict";

// Lab-only driver; the caller supplies an independently configured native
// operation counter and the established disposable-lab fixture. Never infer
// absent key generation/acceptance from a job result or from the CA count.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");
const { buildEnrollmentContainerName } = require("../../../packages/agent/src/windows-cert-store");
const { recoveryWaitBudget } = require("./certops-adcs-uncertain-abandon");
const { qualifyImmediateStoreRecovery } = require("./certops-adcs-store-recovery-proof");
const { startNativeStoreObserver } = require("./certops-adcs-store-native-observer");
const { inspectStoreOnlyCertificate } = require("../../../packages/agent/src/windows-cert-store/store-only");

function validateNativeCounts(counts, previous = null) {
  assert.equal(counts?.coverageComplete, true, "Native operation capture must cover the whole recovery");
  assert.match(counts.captureId, /^[a-f0-9]{32}$/);
  for (const name of ["submissions", "keygens", "accepts"]) assert.ok(Number.isSafeInteger(counts[name]) && counts[name] >= 0);
  if (previous) {
    assert.equal(counts.captureId, previous.captureId);
    for (const name of ["submissions", "keygens", "accepts"]) assert.ok(counts[name] >= previous[name]);
  }
  return counts;
}

function validateInitialNativeCounts(counts, captureId) {
  validateNativeCounts(counts);
  assert.equal(counts.captureId, captureId);
  assert.equal(counts.submissions, 1, "Expected one CA submission before interruption");
  assert.equal(counts.keygens, 1, "Expected one key generation before interruption");
  assert.equal(counts.accepts, 1, "Expected one native acceptance before interruption");
  return counts;
}

async function qualifyNativeStoreRecovery(context) {
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(context.serviceOwned, true);
  const { fixture, api, agentRowId, issuerId, configDir, workDir, ps, until, jobFinished,
    prepareRun, startNativeOperationCapture, readNativeOperationCounts } = context;
  for (const fn of [ps, until, jobFinished, prepareRun, startNativeOperationCapture, readNativeOperationCounts]) assert.equal(typeof fn, "function", "A native operation counter and lab control hooks are required");
  const root = path.resolve(__dirname, "../../..");
  const receipt = path.join(workDir, "store-accept-target.json");
  const query = (sql, args = []) => fixture.pool.query(sql, args);
  let observer, jobId, certificateId, enrollmentId, initial, recoveryJobId, beforeCounts, capture;
  try {
    return await qualifyImmediateStoreRecovery({
      async inspectAndInterrupt({ dnsName }) {
        // The control plane requires the exact fresh selector before it will
        // create the job. Configure this unique name and obtain its heartbeat
        // and preflight before starting observation or issuing to the CA.
        await prepareRun({ dnsName, agentRowId, issuerId });
        // Capture must begin before key generation and CA submission; a
        // counter started after the fault cannot establish uniqueness.
        capture = await startNativeOperationCapture({ dnsName, agentRowId });
        assert.equal(capture?.started, true, "Native operation capture must start before issuance");
        assert.match(capture.captureId, /^[a-f0-9]{32}$/);
        observer = startNativeStoreObserver({ workDir, configDir, root });
        await observer.ready;
        const created = await fixture.request(`${api}/jobs`, "POST", {
          operation: "issue", mode: "real", idempotencyKey: `native-store-${dnsName}`,
          assignedAgentId: agentRowId,
          payload: { issuerId, target: { type: "windows-cert-store", reference: dnsName, store: "My" }, automationEnabled: false },
        });
        assert.equal(created.status, 201);
        jobId = created.body.job.id;
        const rows = (await query(`SELECT j.enrollment_id,j.subject_id,e.snapshot_sha256 FROM certificate_jobs j
          JOIN certificate_enrollments e ON e.workspace_id=j.workspace_id AND e.id=j.enrollment_id
          WHERE j.workspace_id=$1 AND j.id=$2`, [fixture.workspaceId, jobId])).rows;
        assert.equal(rows.length, 1); enrollmentId = rows[0].enrollment_id; certificateId = rows[0].subject_id;
        fs.writeFileSync(receipt, JSON.stringify({ enrollmentId, jobId, snapshotSha256: rows[0].snapshot_sha256,
          containerName: buildEnrollmentContainerName(enrollmentId), domain: dnsName }), { flag: "wx" });
        const fault = await observer.result;
        await observer.stopAndDrain(); assert.equal(observer.hasLiveChild(), false);
        assert.equal(fault.enrollmentId, enrollmentId); assert.equal(fault.jobId, jobId);
        initial = readEnrollmentJournal(configDir, enrollmentId); assert.equal(initial.kind, "valid");
        beforeCounts = await readNativeOperationCounts({ enrollmentId, jobId, containerName: fault.containerName });
        validateInitialNativeCounts(beforeCounts, capture.captureId);
        return fault;
      },
      async restartAndRecover({ fault }) {
        const row = (await query("SELECT lease_expires_at,lease_renewed_at,NOW() AS measured_at FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, jobId])).rows[0];
        assert.ok(row?.lease_renewed_at);
        const budget = recoveryWaitBudget(row.lease_expires_at, row.measured_at);
        const worker = await import(pathToFileURL(path.join(root, "apps/worker/src/certops-worker.js")).href);
        await until(async () => {
          const client = await fixture.pool.connect();
          try { await worker.reapExpiredLeases({ client, hardGraceMs: 60000, offlineAfterMs: 60000, log: { debug() {}, info() {}, warn() {}, error() {} } }); }
          finally { client.release(); }
          const rows = (await query("SELECT status,needs_operator_reconciliation FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, jobId])).rows;
          return rows[0]?.status === "orphaned_unknown_effect" && rows[0]?.needs_operator_reconciliation === true;
        }, budget.recoveryWaitBudgetMs);
        const recovery = await fixture.request(`${api}/enrollments/${enrollmentId}/recover`, "POST", { orphanedJobId: jobId,
          acknowledgeUnknownEffect: true, reason: "Native store certificate and key independently inspected after service interruption" });
        assert.equal(recovery.status, 201); recoveryJobId = recovery.body.jobId;
        ps("Start-Service TokenTimerAgent -ErrorAction Stop");
        await jobFinished(recoveryJobId);
        const final = readEnrollmentJournal(configDir, enrollmentId); assert.equal(final.kind, "valid"); assert.equal(final.journal.state, "installed");
        for (const name of ["containerName", "snapshotSha256", "csrSha256", "csrSpkiSha256", "leafSha256"]) assert.equal(final.journal[name], initial.journal[name]);
        assert.equal(final.artifacts.leafPem, initial.artifacts.leafPem); assert.equal(final.artifacts.csrPem, initial.artifacts.csrPem);
        const native = await inspectStoreOnlyCertificate({ certificatePem: final.artifacts.leafPem, containerName: final.journal.containerName });
        assert.equal(native.status, "complete"); assert.equal(native.fingerprintSha256, fault.fingerprintSha256);
        const after = await readNativeOperationCounts({ enrollmentId, jobId, containerName: fault.containerName });
        validateNativeCounts(after, beforeCounts);
        return { containerName: final.journal.containerName, fingerprintSha256: fault.fingerprintSha256,
          csrSpkiSha256: final.journal.csrSpkiSha256, newSubmissions: after.submissions - beforeCounts.submissions,
          newKeys: after.keygens - beforeCounts.keygens, repeatedAccepts: after.accepts - beforeCounts.accepts };
      },
      async readInventory({ fault }) {
        const rows = (await query("SELECT status,fingerprint_sha256 FROM managed_certificates WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, certificateId])).rows;
        const issued = (await query("SELECT id FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_CERTIFICATE_ISSUED' AND metadata->>'managedCertificateId'=$2", [fixture.workspaceId, certificateId])).rows;
        const service = (await query("SELECT id FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND evidence_type='validation.passed' AND metadata->>'step'='verify'", [fixture.workspaceId, recoveryJobId])).rows;
        assert.equal(rows.length, 1); assert.equal(rows[0].status, "active");
        assert.equal(rows[0].fingerprint_sha256, fault.fingerprintSha256);
        return { provisioningRegistrations: rows.length, promotions: issued.length, fingerprintSha256: rows[0].fingerprint_sha256, serviceVerified: service.length > 0 };
      },
    });
  } finally {
    if (observer) {
      await observer.stopAndDrain();
      if (observer.hasLiveChild()) throw new Error("Preserve native state: observer drainage was not proven");
    }
    if (fs.existsSync(receipt)) {
      const owned = JSON.parse(fs.readFileSync(receipt, "utf8"));
      assert.equal(owned.enrollmentId, enrollmentId); assert.equal(owned.jobId, jobId);
      fs.unlinkSync(receipt);
    }
  }
}
module.exports = { qualifyNativeStoreRecovery, validateNativeCounts, validateInitialNativeCounts };
