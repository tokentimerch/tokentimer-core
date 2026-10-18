"use strict";

// This composition uses an existing owned revocation endpoint. It does not
// install a role, substitute a chain verdict, or advance a native clock. The
// caller owns the exact helper-program fault and all native cleanup guards.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { verifyInstalledEvidence } = require("./certops-adcs-live-enroll-acl");
const {
  readEnrollmentJournal,
} = require("../../../packages/agent/src/issuers/adcs-enrollment");
const {
  buildEnrollmentContainerName,
  readIssuedContainerRecord,
} = require("../../../packages/agent/src/windows-cert-store");
const identity = require("./certops-adcs-deferred-identity");

function verifyDeferredJob(job, jobId, agentRowId) {
  assert.equal(job.id, jobId);
  assert.equal(job.status, "failed");
  assert.equal(job.executor_kind, "agent");
  assert.equal(job.attempt_count, 1);
  assert.equal(job.claimed_by_agent_id, agentRowId);
  assert.match(job.claim_id, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i);
  assert.equal(job.needs_operator_reconciliation, false);
  assert.equal(job.consumed_nonces, 1);
  return job.claim_id;
}

function verifyContinuationJob(job, jobId, agentRowId, originalClaimId) {
  assert.equal(job.id, jobId);
  assert.equal(job.status, "succeeded");
  assert.equal(job.executor_kind, "agent");
  assert.equal(job.claimed_by_agent_id, agentRowId);
  assert.equal(job.attempt_count, 1);
  assert.match(job.claim_id, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i);
  assert.notEqual(job.claim_id.toLowerCase(), originalClaimId.toLowerCase());
  assert.equal(job.consumed_nonces, 1);
  assert.equal(job.needs_operator_reconciliation, false);
}

function verifyContinuation(selected, enrollmentId, originalJobId) {
  assert.equal(
    selected.length,
    1,
    "Unrelated enrollment dispatch is not permitted",
  );
  const matches = selected.filter((row) => row.enrollmentId === enrollmentId);
  assert.equal(
    matches.length,
    1,
    "Exactly one owned revocation continuation required",
  );
  assert.match(
    matches[0].jobId,
    /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i,
  );
  assert.notEqual(matches[0].jobId.toLowerCase(), originalJobId.toLowerCase());
  return matches[0].jobId;
}

function verifyGeneratedRecord(
  issued,
  enrollmentId,
  originalJobId,
  certificateId,
) {
  assert.match(certificateId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i);
  assert.equal(
    issued?.status,
    "generated",
    "Original unaccepted CNG ownership record required",
  );
  assert.ok(
    issued.containerName === buildEnrollmentContainerName(enrollmentId),
    "Deferred CNG ownership mismatch",
  );
  assert.equal(issued.jobId, originalJobId);
  assert.equal(issued.certificateId, certificateId);
  assert.equal(issued.acceptedThumbprint, null);
  assert.equal(issued.acceptedStore, null);
}

async function continueDeferredIssuedLeaf({
  fixture,
  enrollmentId,
  originalJobId,
  agentRowId,
  configDir,
  until,
  jobFinished,
  observeIssued,
  assertUnacceptedAndOutgoing,
  removeOwnedFault,
}) {
  for (const id of [
    fixture.workspaceId,
    enrollmentId,
    originalJobId,
    agentRowId,
  ])
    assert.match(id, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i);
  for (const fn of [
    until,
    jobFinished,
    observeIssued,
    assertUnacceptedAndOutgoing,
    removeOwnedFault,
  ])
    assert.equal(typeof fn, "function");
  const read = async () => {
    const rows = (
      await fixture.pool.query(
        "SELECT state,request_id,current_job_id,next_poll_at,certificate_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2",
        [fixture.workspaceId, enrollmentId],
      )
    ).rows;
    assert.equal(rows.length, 1);
    return rows[0];
  };
  const readJob = async (jobId) => {
    const rows = (
      await fixture.pool.query(
        "SELECT j.id,j.status,j.executor_kind,j.claim_id,j.claimed_by_agent_id,j.attempt_count,j.needs_operator_reconciliation,(SELECT count(*)::int FROM certops_consumed_nonces n WHERE n.workspace_id=j.workspace_id AND n.job_id=j.id AND n.issued_to_agent_id=$3 AND n.consumed_at IS NOT NULL) AS consumed_nonces FROM certificate_jobs j WHERE j.workspace_id=$1 AND j.id=$2",
        [fixture.workspaceId, jobId, agentRowId],
      )
    ).rows;
    assert.equal(rows.length, 1);
    return rows[0];
  };
  const deferred = await until(async () => {
    const row = await read();
    return identity.isDeferredPollReady(row) ? row : null;
  });
  const originalJob = await until(async () => {
    const row = await readJob(originalJobId);
    return row.status === "failed" ? row : null;
  });
  const originalClaimId = verifyDeferredJob(
    originalJob,
    originalJobId,
    agentRowId,
  );
  const beforeJournal = readEnrollmentJournal(configDir, enrollmentId);
  const before = identity.observe({
    row: deferred,
    journal: beforeJournal,
    nativeRequest: await observeIssued(beforeJournal),
    jobId: originalJobId,
    state: "validation_deferred",
  });
  // A deferred public leaf must not be mistaken for an accepted store leaf.
  const issued = readIssuedContainerRecord({
    stateDir: configDir,
    containerName: buildEnrollmentContainerName(enrollmentId),
  });
  verifyGeneratedRecord(
    issued,
    enrollmentId,
    originalJobId,
    deferred.certificate_id,
  );
  await assertUnacceptedAndOutgoing(beforeJournal);
  await removeOwnedFault();
  // Only dispatch eligibility uses the supported scheduler input. Certificate,
  // revocation, journal deadline and native CA clocks remain actual clocks.
  const selected =
    await require("../../../apps/api/services/certops/certificateEnrollments").scheduleDueEnrollments(
      {
        client: fixture.pool,
        now: new Date(Date.parse(deferred.next_poll_at) + 1000),
      },
    );
  const continuationJobId = verifyContinuation(
    selected,
    enrollmentId,
    originalJobId,
  );
  await jobFinished(continuationJobId);
  const afterJournal = readEnrollmentJournal(configDir, enrollmentId);
  const after = identity.observe({
    row: await read(),
    journal: afterJournal,
    nativeRequest: await observeIssued(afterJournal),
    jobId: continuationJobId,
    state: "installed",
  });
  identity.verifyRecovery(before, after);
  const terminalJob = await readJob(continuationJobId);
  verifyContinuationJob(
    terminalJob,
    continuationJobId,
    agentRowId,
    originalClaimId,
  );
  const evidence = (
    await fixture.pool.query(
      "SELECT e.claim_id,e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.evidence_type='validation.passed' AND e.claim_id=j.claim_id AND e.metadata->>'step'='verify'",
      [fixture.workspaceId, continuationJobId],
    )
  ).rows;
  verifyInstalledEvidence(
    terminalJob,
    evidence,
    new crypto.X509Certificate(afterJournal.artifacts.leafPem),
  );
  return {
    originalJobId,
    originalClaimId,
    continuationJobId,
    continuationClaimId: terminalJob.claim_id,
    requestId: after.requestId,
  };
}

module.exports = {
  verifyDeferredJob,
  verifyContinuationJob,
  verifyContinuation,
  verifyGeneratedRecord,
  continueDeferredIssuedLeaf,
};
