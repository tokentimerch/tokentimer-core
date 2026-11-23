"use strict";

// A domain-member qualification helper for the no-IIS Store destination. The
// surrounding harness owns the disposable service, issuer, observer identities,
// and exact cleanup. SQL reads evidence. Only the deployed worker schedules jobs.
const assert = require("node:assert/strict");
const { createHash, X509Certificate } = require("node:crypto");
const { verifyNamedStoreIdentity } = require("./certops-adcs-store-named-observation");
const { buildEnrollmentContainerName } = require("../../../packages/agent/src/windows-cert-store");
const { inspectStoreOnlyCertificate } = require("../../../packages/agent/src/windows-cert-store/store-only");
const { readEnrollmentJournal } = require("../../../packages/agent/src/issuers/adcs-enrollment");
const {
  createRunDnsName, observeCaRequest, observePendingCaRequest, verifyPendingRecovery,
} = require("./certops-adcs-store-recovery-proof");
const {
  requireActiveObservationInterruption, verifyCandidateHost, validateCaptureStart, validateNativeCounts,
  validateCaObservationStart, validateCaObservationWindow, verifyPreIssueCheckpoint,
  stopNativeCapture, stopCaObservation, createPublicEvidenceRecorder,
  verifyOwnedServiceDrainage,
  startObservedStoreService, captureEvidenceDetails, OBSERVATION_RUN_ID,
} = require("./certops-adcs-store-native-driver");

const SHA256 = /^[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const JOURNAL_IDENTITY = ["requestId", "containerName", "snapshotSha256", "csrSha256", "csrSpkiSha256"];
const PENDING_TEMPLATE = "TTQualificationPending";
const BINDING_STATE = "if ((Get-WindowsFeature -Name Web-Server -ErrorAction Stop).Installed) { throw 'IIS role detected' }; " +
  "$state=& netsh.exe http show sslcert; if ($LASTEXITCODE -ne 0) { throw 'Cannot read HTTP.sys certificate bindings' }; $state";

function verifyPendingJournalIdentity(original, observed) {
  for (const field of JOURNAL_IDENTITY) {
    assert.equal(observed[field], original[field], "Pending request journal identity changed at " + field);
  }
}

function verifyPendingOperationCounts(pending, afterRestart, installed) {
  const checkedPending = validateNativeCounts(pending);
  const checkedRestarted = validateNativeCounts(afterRestart, checkedPending);
  const checkedInstalled = validateNativeCounts(installed, checkedRestarted);
  for (const counts of [checkedPending, checkedRestarted, checkedInstalled]) {
    assert.equal(counts.submissions, 1, "Expected just one CA submission");
    assert.equal(counts.keygens, 1, "Expected just one CNG key generation");
  }
  assert.equal(checkedPending.accepts, 0);
  assert.equal(checkedRestarted.accepts, 0);
  assert.equal(checkedInstalled.accepts, 1, "Expected just one native Store acceptance");
  return checkedInstalled;
}

function validatePendingCaWindow(window, observation, requestId) {
  assert.equal(window?.coverageComplete, true, "Independent pending CA window must prove complete coverage");
  assert.equal(window.observationId, observation.observationId);
  assert.equal(window.caPublicKeySha256, observation.caPublicKeySha256);
  assert.equal(window.baselineRequestId, observation.baselineRequestId);
  assert.equal(window.lossFree, true);
  assert.equal(window.noPurgeProven, true);
  assert.equal(window.noRestoreProven, true);
  assert.equal(window.globalCount, 1, "Expected exactly one request in the independent pending CA window");
  assert.equal(window.subjectRequestCount, 1);
  assert.equal(window.matchingIssuedCount, 0, "The pending CA request issued before approval");
  assert.equal(window.unknownIssuedCount, 0);
  assert.equal(window.disposition, 9, "The CA request must remain pending before approval");
  assert.match(requestId, /^[1-9][0-9]{0,9}$/);
  assert.ok(Number(requestId) > observation.baselineRequestId && Number(requestId) <= 2147483647);
  assert.equal(String(window.requestId), requestId, "Independent CA window contains a different pending RequestId");
}

async function drainPendingObservations({ capture, caObservation, issuedWindow, installedCounts,
  stopAndVerifyOwnedService, candidateArchiveSha256, serviceProcess }) {
  const serviceDrainageSha256 = await verifyOwnedServiceDrainage({
    stopAndVerifyOwnedService, candidateArchiveSha256, serviceProcess, captureId: capture?.captureId ?? null,
  });
  // Keep both sources live until the owned service is quiescent, then keep the
  // CA source live until the native capture reports its final drained counts.
  const counts = capture ? await stopNativeCapture(capture, installedCounts) : null;
  const window = caObservation ? await stopCaObservation(caObservation, issuedWindow) : null;
  return { counts, window, serviceDrainageSha256 };
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
 * - createIndependentCaObservation creates a stopped complete CA observer.
 * - readIndependentCaObservation reads that same observation window with
 *   the pending request ID before approval and the leaf fingerprint after it.
 * - stopAndVerifyOwnedService stops only the identified service and reads back
 *   independent, durable evidence of SCM stop and zero surviving descendants.
 * - startAndVerifyObservedService arms a fresh observation run before starting
 *   SCM and reads back proof that the same independent capture kept running.
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
    readNativeOperationCounts, createIndependentCaObservation, readIndependentCaObservation, expectedCaKeySha256,
    caObserverExec, approvePendingRequest, recordOwnedEnrollment, stopAndVerifyOwnedService, startAndVerifyObservedService,
  } = context;
  for (const fn of [ps, until, preparePendingRun, createNativeOperationCapture, readNativeOperationCounts,
    createIndependentCaObservation, readIndependentCaObservation, caObserverExec, approvePendingRequest,
    recordOwnedEnrollment, stopAndVerifyOwnedService, startAndVerifyObservedService]) assert.equal(typeof fn, "function");
  assert.match(fixture.workspaceId, UUID);
  assert.match(agentRowId, UUID);
  assert.equal(api, "/api/v1/workspaces/" + fixture.workspaceId + "/certops");
  const query = (sql, values) => fixture.pool.query(sql, values);
  const recordEvidence = createPublicEvidenceRecorder(context);
  const installedService = await verifyCandidateHost(context);
  let { observationRunId, serviceProcess } = installedService;
  assert.match(observationRunId, OBSERVATION_RUN_ID);
  const initialObservationRunId = observationRunId;
  const bindingsBefore = await ps(BINDING_STATE);
  assert.ok(typeof bindingsBefore === "string" && bindingsBefore.trim(), "Missing HTTP.sys binding baseline");

  const dnsName = createRunDnsName();
  let capture, caObservation, failure, submitted, installedCounts, issuedWindow, drained, receipt;
  try {
    caObservation = await createIndependentCaObservation({ dnsName });
    assert.equal(typeof caObservation?.start, "function");
    assert.equal(typeof caObservation.stop, "function");
    await caObservation.start();
    validateCaObservationStart(caObservation, expectedCaKeySha256);
    capture = await createNativeOperationCapture({ dnsName, agentRowId });
    assert.equal(typeof capture?.start, "function");
    assert.equal(typeof capture.stop, "function");
    await capture.start();
    const baseline = validateCaptureStart(capture, context.candidateArchiveSha256, context.observationScope);
    const { issuerId } = await preparePendingRun({ dnsName, agentRowId, template: PENDING_TEMPLATE });
    assert.match(issuerId, UUID);
    const ready = await verifyPreIssueCheckpoint(capture, caObservation, baseline);
    await recordEvidence("baseline", {
      candidateSha256: context.candidateArchiveSha256, dnsName, captureId: capture.captureId,
      observationId: caObservation.observationId, observationRunId, caPublicKeySha256: caObservation.caPublicKeySha256,
      baselineRequestId: caObservation.baselineRequestId, submissions: 0, keygens: 0, accepts: 0,
      ...captureEvidenceDetails(ready),
    });

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
    const readCounts = async () => {
      const counts = await readNativeOperationCounts({ enrollmentId, jobId, containerName });
      verifyNamedStoreIdentity(counts, { containerName, requestId });
      return counts;
    };
    const checkPendingWindow = async () => {
      const window = await readIndependentCaObservation({ dnsName, requestId, observation: caObservation });
      validatePendingCaWindow(window, caObservation, requestId);
    };
    const recordPending = (phase, counts, drainage = {}) => recordEvidence(phase, {
      candidateSha256: context.candidateArchiveSha256, dnsName, captureId: capture.captureId,
      observationId: caObservation.observationId, observationRunId, caPublicKeySha256: caObservation.caPublicKeySha256,
      baselineRequestId: caObservation.baselineRequestId, enrollmentId, jobId, requestId,
      csrSpkiSha256: original.journal.csrSpkiSha256, submissions: counts.submissions, keygens: counts.keygens,
      accepts: counts.accepts, ...captureEvidenceDetails(counts), ...drainage,
    });
    const caPending = await observeRequest();
    assert.equal(caPending.disposition, 9);
    await checkPendingWindow();
    const pendingCounts = validateNativeCounts(await readCounts(), ready);
    assert.equal(pendingCounts.submissions, 1);
    assert.equal(pendingCounts.keygens, 1);
    assert.equal(pendingCounts.accepts, 0);
    await recordPending("pending-before-restart", pendingCounts);
    const beforeRestart = requireStoreServiceProcess(await readStoreServiceProcess(ps));
    assert.equal(beforeRestart.pid, serviceProcess.pid, "Owned service changed before the planned restart");
    assert.equal(beforeRestart.created, serviceProcess.created, "Owned process identity changed before the planned restart");
    const restartDrainageSha256 = await verifyOwnedServiceDrainage({
      stopAndVerifyOwnedService, candidateArchiveSha256: context.candidateArchiveSha256,
      captureId: capture.captureId, serviceProcess: beforeRestart,
    });
    const restartedService = await startObservedStoreService(context, capture.captureId, observationRunId, beforeRestart);
    serviceProcess = restartedService.process;
    observationRunId = restartedService.observationRunId;
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
    await checkPendingWindow();
    await recordPending("pending-after-restart", restartedCounts, {
      serviceDrainageSha256: restartDrainageSha256, serviceStartSha256: restartedService.serviceStartSha256,
    });

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
    issuedWindow = await readIndependentCaObservation({
      dnsName, fingerprintSha256: native.fingerprintSha256, observation: caObservation,
    });
    validateCaObservationWindow(issuedWindow, caObservation, native.fingerprintSha256);
    assert.equal(String(issuedWindow.requestId), requestId, "Independent CA window contains a different issued RequestId");
    assert.equal(serialIdentity(issuedWindow.serialNumber), serialIdentity(native.serialNumber));

    const finalCounts = verifyPendingOperationCounts(pendingCounts, restartedCounts, await readCounts());
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
    receipt = {
      dnsName, enrollmentId, certificateId, jobId, continuationJobId: installed.current_job_id,
      requestId, serialNumber: native.serialNumber, fingerprintSha256: native.fingerprintSha256,
      candidateArchiveSha256: context.candidateArchiveSha256,
      csrSpkiSha256: original.journal.csrSpkiSha256, captureId: finalCounts.captureId,
      observationId: caObservation.observationId, initialObservationRunId, observationRunId, baselineRequestId: caObservation.baselineRequestId,
      nativeSubmissions: finalCounts.submissions, nativeKeyGenerations: finalCounts.keygens, nativeAccepts: finalCounts.accepts,
      promotions: promotions.rows.length,
    };
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    try {
      // The caller retains observation if a submitted job may still have effects.
      if ((!failure || !submitted) && (capture || caObservation)) {
        drained = await drainPendingObservations({ capture, caObservation, issuedWindow, installedCounts,
          stopAndVerifyOwnedService, candidateArchiveSha256: context.candidateArchiveSha256, serviceProcess });
      }
    } catch (error) {
      if (failure) throw new AggregateError([failure, error], "Pending recovery or native observation drainage failed");
      throw error;
    }
  }
  const { counts: drainedCounts, window: drainedWindow, serviceDrainageSha256 } = drained;
  assert.equal(serialIdentity(drainedWindow.serialNumber), serialIdentity(receipt.serialNumber));
  const observationDetails = captureEvidenceDetails(drainedCounts);
  const evidence = await recordEvidence("observations-drained", {
    candidateSha256: receipt.candidateArchiveSha256, dnsName, captureId: receipt.captureId,
    observationId: receipt.observationId, initialObservationRunId: receipt.initialObservationRunId,
    observationRunId: receipt.observationRunId,
    caPublicKeySha256: drainedWindow.caPublicKeySha256,
    baselineRequestId: receipt.baselineRequestId, requestId: receipt.requestId, serialNumber: receipt.serialNumber,
    enrollmentId: receipt.enrollmentId, jobId: receipt.jobId, fingerprintSha256: receipt.fingerprintSha256,
    csrSpkiSha256: receipt.csrSpkiSha256, submissions: drainedCounts.submissions, keygens: drainedCounts.keygens,
    accepts: drainedCounts.accepts, promotions: receipt.promotions, ...observationDetails, serviceDrainageSha256,
  });
  return { ...receipt, ...observationDetails, serviceDrainageSha256,
    evidenceReceiptId: evidence.receiptId, evidenceReceiptSha256: evidence.sha256 };
}

module.exports = { qualifyPendingStoreRecovery, verifyPendingJournalIdentity, verifyPendingOperationCounts,
  validatePendingCaWindow, drainPendingObservations };
