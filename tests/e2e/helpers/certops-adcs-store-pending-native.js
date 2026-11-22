"use strict";

// A domain-member qualification helper for the no-IIS Store destination. The
// surrounding harness owns the disposable service, issuer, observer identities,
// and exact cleanup. SQL reads evidence. Only the deployed worker schedules jobs.
const assert = require("node:assert/strict");
const { createHash, X509Certificate } = require("node:crypto");
const { buildEnrollmentContainerName } = require("../../../packages/agent/src/windows-cert-store");
const { inspectStoreOnlyCertificate } = require("../../../packages/agent/src/windows-cert-store/store-only");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");
const {
  createRunDnsName, observeCaRequest, observePendingCaRequest, verifyPendingRecovery,
} = require("./certops-adcs-store-recovery-proof");
const {
  requireActiveObservationInterruption, verifyCandidateHost, validateCaptureStart, validateNativeCounts, stopNativeCapture,
} = require("./certops-adcs-store-native-driver");

const SHA256 = /^[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const JOURNAL_IDENTITY = ["requestId", "containerName", "snapshotSha256", "csrSha256", "csrSpkiSha256"];
const PENDING_TEMPLATE = "TTQualificationPending";
const SERVICE = "$s=Get-CimInstance Win32_Service -Filter \"Name='TokenTimerAgent'\" -ErrorAction Stop";
const SERVICE_PROCESS = SERVICE + "; if ($s.State -ne 'Running' -or !$s.ProcessId) { return '{}' }; " +
  "$p=Get-CimInstance Win32_Process -Filter ('ProcessId=' + $s.ProcessId) -ErrorAction Stop; " +
  "$owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop; " +
  "@{pid=[int]$s.ProcessId;sid=$owner.Sid;created=$p.CreationDate.ToString('o')} | ConvertTo-Json -Compress";
const BINDING_STATE = "if ((Get-WindowsFeature -Name Web-Server -ErrorAction Stop).Installed) { throw 'IIS role detected' }; " +
  "$state=& netsh.exe http show sslcert; if ($LASTEXITCODE -ne 0) { throw 'Cannot read HTTP.sys certificate bindings' }; $state";

function verifyPendingJournalIdentity(original, observed) {
  for (const field of JOURNAL_IDENTITY) {
    assert.equal(observed[field], original[field], "Pending request journal identity changed at " + field);
  }
}

function verifyPendingOperationCounts(pending, afterRestart, installed) {
  validateNativeCounts(pending);
  validateNativeCounts(afterRestart, pending);
  validateNativeCounts(installed, afterRestart);
  for (const counts of [pending, afterRestart, installed]) {
    assert.equal(counts.submissions, 1, "Expected just one CA submission");
    assert.equal(counts.keygens, 1, "Expected just one CNG key generation");
  }
  assert.equal(pending.accepts, 0);
  assert.equal(afterRestart.accepts, 0);
  assert.equal(installed.accepts, 1, "Expected just one native Store acceptance");
}

function serialIdentity(value) {
  assert.match(value, /^[0-9a-f]+$/i);
  return value.replace(/^0+(?=.)/, "").toLowerCase();
}

/**
 * Reuses the Store driver context for the pinned package, capture, fixture,
 * Windows PowerShell and bounded until(predicate, timeoutMs).
 * - preparePendingRun({dnsName, agentRowId, template}) confirms a dedicated
 *   manager-pending issuer and refreshes that member's exact selector/check.
 *   Returns {issuerId}. It must not submit a request.
 * - caObserverExec runs the canonical CA read command as the independent reader.
 * - approvePendingRequest({dnsName, requestId}) runs the scoped CA officer action.
 * - recordOwnedEnrollment({dnsName, enrollmentId, certificateId, jobId}) records
 *   cleanup ownership before a restart or approval. The harness retains the
 *   service, journals, capture and CA state on uncertain failure for its cleanup.
 */
async function qualifyPendingStoreRecovery(context) {
  requireActiveObservationInterruption();
  assert.equal(process.platform, "win32");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(context.serviceOwned, true);
  const {
    fixture, api, agentRowId, configDir, ps, until, preparePendingRun, createNativeOperationCapture,
    readNativeOperationCounts, caObserverExec, approvePendingRequest, recordOwnedEnrollment,
  } = context;
  for (const fn of [ps, until, preparePendingRun, createNativeOperationCapture, readNativeOperationCounts,
    caObserverExec, approvePendingRequest, recordOwnedEnrollment]) assert.equal(typeof fn, "function");
  assert.match(fixture.workspaceId, UUID);
  assert.match(agentRowId, UUID);
  assert.equal(api, "/api/v1/workspaces/" + fixture.workspaceId + "/certops");
  const query = (sql, values) => fixture.pool.query(sql, values);
  await verifyCandidateHost(context);
  const bindingsBefore = await ps(BINDING_STATE);
  assert.ok(typeof bindingsBefore === "string" && bindingsBefore.trim(), "Missing HTTP.sys binding baseline");

  const dnsName = createRunDnsName();
  const capture = await createNativeOperationCapture({ dnsName, agentRowId });
  assert.equal(typeof capture?.start, "function");
  assert.equal(typeof capture.stop, "function");
  let failure;
  let submitted;
  let installedCounts;
  try {
    await capture.start();
    const baseline = validateCaptureStart(capture);
    const { issuerId } = await preparePendingRun({ dnsName, agentRowId, template: PENDING_TEMPLATE });
    assert.match(issuerId, UUID);
    const ready = validateNativeCounts(await capture.read(), baseline);
    for (const field of ["submissions", "keygens", "accepts"]) assert.equal(ready[field], baseline[field]);

    const target = { type: "windows-cert-store", reference: dnsName, store: "My" };
    submitted = true;
    const created = await fixture.request(api + "/jobs", "POST", {
      operation: "issue", mode: "real", idempotencyKey: "native-store-pending-" + dnsName,
      assignedAgentId: agentRowId, payload: { issuerId, target, automationEnabled: false },
    });
    assert.equal(created.status, 201);
    const jobId = created.body.job.id;
    assert.match(jobId, UUID);
    const initial = (await query(
      "SELECT enrollment_id, subject_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
      [fixture.workspaceId, jobId],
    )).rows[0];
    const enrollmentId = initial.enrollment_id;
    const certificateId = initial.subject_id;
    for (const id of [enrollmentId, certificateId]) assert.match(id, UUID);
    await recordOwnedEnrollment({ dnsName, enrollmentId, certificateId, jobId });
    const readEnrollment = async () => {
      const { rows } = await query(
        "SELECT state, request_id, next_poll_at, current_job_id, snapshot_sha256, deploy_target " +
        "FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2", [fixture.workspaceId, enrollmentId],
      );
      assert.equal(rows.length, 1);
      return rows[0];
    };
    const pending = await until(async () => {
      const row = await readEnrollment();
      return row.state === "pending_issuance" && row.request_id ? row : null;
    }, 180000);
    assert.equal(pending.current_job_id, jobId);
    assert.deepEqual(pending.deploy_target, target);
    const { rows: pendingJobs } = await query(
      "SELECT status, claimed_by_agent_id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2",
      [fixture.workspaceId, jobId],
    );
    assert.deepEqual(pendingJobs, [{ status: "awaiting_issuer", claimed_by_agent_id: agentRowId }]);
    const original = readEnrollmentJournal(configDir, enrollmentId);
    assert.equal(original.kind, "valid");
    const containerName = buildEnrollmentContainerName(enrollmentId);
    assert.equal(original.journal.containerName, containerName);
    assert.equal(original.journal.snapshotSha256, pending.snapshot_sha256);
    const requestId = String(pending.request_id);
    assert.equal(String(original.journal.requestId), requestId);
    for (const field of ["csrSha256", "csrSpkiSha256", "snapshotSha256"]) assert.match(original.journal[field], SHA256);

    const observeRequest = () => observePendingCaRequest({ dnsName, id: requestId, execFileImpl: caObserverExec });
    const readCounts = () => readNativeOperationCounts({ enrollmentId, jobId, containerName });
    const caPending = await observeRequest();
    assert.equal(caPending.disposition, 9);
    const pendingCounts = validateNativeCounts(await readCounts(), baseline);
    assert.equal(pendingCounts.submissions, 1);
    assert.equal(pendingCounts.keygens, 1);
    assert.equal(pendingCounts.accepts, 0);
    const beforeRestart = JSON.parse(await ps(SERVICE_PROCESS));
    assert.ok(Number.isSafeInteger(beforeRestart.pid) && beforeRestart.pid > 0);
    assert.equal(beforeRestart.sid, "S-1-5-18");
    await ps(SERVICE + "; if ($s.ProcessId -ne " + beforeRestart.pid +
      ") { throw 'Owned service process changed' }; Restart-Service -Name TokenTimerAgent -ErrorAction Stop");
    const afterRestart = await until(async () => {
      const process = JSON.parse(await ps(SERVICE_PROCESS));
      return process.pid > 0 && process.pid !== beforeRestart.pid ? process : null;
    }, 60000);
    assert.equal(afterRestart.sid, "S-1-5-18");
    assert.ok(Date.parse(afterRestart.created) > Date.parse(beforeRestart.created));
    await verifyCandidateHost(context);
    const restarted = readEnrollmentJournal(configDir, enrollmentId);
    assert.equal(restarted.kind, "valid");
    verifyPendingJournalIdentity(original.journal, restarted.journal);
    const caAfterRestart = await observeRequest();
    assert.equal(caAfterRestart.disposition, 9, "CA disposition changed during restart");
    const restartedCounts = validateNativeCounts(await readCounts(), pendingCounts);
    for (const field of ["submissions", "keygens", "accepts"]) assert.equal(restartedCounts[field], pendingCounts[field]);
    const stillPending = await readEnrollment();
    assert.equal(stillPending.state, "pending_issuance");
    assert.equal(stillPending.current_job_id, jobId);
    assert.equal(String(stillPending.request_id), requestId);
    const pollAt = new Date(stillPending.next_poll_at).getTime();
    const now = Date.now();
    assert.ok(pollAt > now && pollAt - now <= 900000, "Expected the real Store poll window before approval");

    await approvePendingRequest({ dnsName, requestId });
    const installed = await until(async () => {
      const row = await readEnrollment();
      assert.equal(String(row.request_id), requestId);
      assert.ok(!["denied", "expired", "cancelled", "rejected_invalid", "install_failed"].includes(row.state));
      return row.state === "installed" ? row : null;
    }, pollAt - now + 300000);
    assert.notEqual(installed.current_job_id, jobId);
    assert.deepEqual(installed.deploy_target, target);
    assert.equal(installed.snapshot_sha256, pending.snapshot_sha256);
    const { rows: continuations } = await query(
      "SELECT id, status, claim_id, assigned_agent_id, claimed_by_agent_id FROM certificate_jobs " +
      "WHERE workspace_id=$1 AND enrollment_id=$2 AND operation='continue-enrollment'",
      [fixture.workspaceId, enrollmentId],
    );
    assert.equal(continuations.length, 1);
    assert.equal(continuations[0].id, installed.current_job_id);
    assert.equal(continuations[0].status, "succeeded");
    assert.equal(continuations[0].assigned_agent_id, agentRowId);
    assert.equal(continuations[0].claimed_by_agent_id, agentRowId);
    assert.match(continuations[0].claim_id, UUID);

    const final = readEnrollmentJournal(configDir, enrollmentId);
    assert.equal(final.kind, "valid");
    assert.equal(final.journal.state, "installed");
    verifyPendingJournalIdentity(original.journal, final.journal);
    const leaf = new X509Certificate(final.artifacts.leafPem);
    assert.equal(leaf.checkHost(dnsName), dnsName);
    assert.equal(createHash("sha256").update(leaf.publicKey.export({ type: "spki", format: "der" })).digest("hex"),
      original.journal.csrSpkiSha256);
    const native = await inspectStoreOnlyCertificate({ certificatePem: final.artifacts.leafPem, containerName });
    assert.equal(native.status, "complete", "Expected the installed non-exportable key in LocalMachine\\My");
    const caIssued = await observeCaRequest({ dnsName, fingerprintSha256: native.fingerprintSha256, execFileImpl: caObserverExec });
    assert.equal(serialIdentity(caIssued.serialNumber), serialIdentity(native.serialNumber));

    const finalCounts = await readCounts();
    verifyPendingOperationCounts(pendingCounts, restartedCounts, finalCounts);
    verifyPendingRecovery({
      originalRequestId: requestId, afterRestartRequestId: restarted.journal.requestId,
      retrievedRequestId: installed.request_id, caPending, caIssued,
      newSubmissions: finalCounts.submissions - pendingCounts.submissions, sameKey: true,
    });
    assert.equal(await ps(BINDING_STATE), bindingsBefore, "HTTP.sys bindings changed during Store-only recovery");
    const verification = await query(
      "SELECT id FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND claim_id=$3 " +
      "AND created_by_agent_id=$4 AND evidence_type='validation.passed' AND metadata->>'step'='store-verify'",
      [fixture.workspaceId, installed.current_job_id, continuations[0].claim_id, agentRowId],
    );
    assert.ok(verification.rows.length, "Missing claim-bound Store verification evidence");
    const inventory = await query(
      "SELECT status, fingerprint_sha256 FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
      [fixture.workspaceId, certificateId],
    );
    assert.deepEqual(inventory.rows, [{ status: "active", fingerprint_sha256: native.fingerprintSha256 }]);
    const promotions = await query(
      "SELECT id FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_CERTIFICATE_ISSUED' " +
      "AND metadata->>'managedCertificateId'=$2", [fixture.workspaceId, certificateId],
    );
    assert.equal(promotions.rows.length, 1);
    installedCounts = finalCounts;
    return {
      dnsName, enrollmentId, certificateId, jobId, continuationJobId: installed.current_job_id,
      requestId, serialNumber: native.serialNumber, fingerprintSha256: native.fingerprintSha256,
      candidateArchiveSha256: context.candidateArchiveSha256,
      csrSpkiSha256: original.journal.csrSpkiSha256, captureId: finalCounts.captureId,
      nativeSubmissions: finalCounts.submissions, nativeKeyGenerations: finalCounts.keygens, nativeAccepts: finalCounts.accepts,
      promotions: promotions.rows.length,
    };
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    try {
      // The caller retains observation if a submitted job may still have effects.
      if (!failure || !submitted) await stopNativeCapture(capture, installedCounts);
    } catch (error) {
      if (failure) throw new AggregateError([failure, error], "Pending recovery or native observation drainage failed");
      throw error;
    }
  }
}

module.exports = { qualifyPendingStoreRecovery, verifyPendingJournalIdentity, verifyPendingOperationCounts };
