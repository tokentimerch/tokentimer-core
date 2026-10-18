"use strict";
// Pure admission guards only. These rows do not qualify a native OCSP journey.
const test = require("node:test");
const assert = require("node:assert/strict");
const h = require("../tests/e2e/helpers/certops-adcs-ocsp-deferred");
const jobId = "11111111-1111-4111-8111-111111111111";
const agentId = "22222222-2222-4222-8222-222222222222";
const claimId = "33333333-3333-4333-8333-333333333333";
const enrollmentId = "44444444-4444-4444-8444-444444444444";
const nextJobId = "55555555-5555-4555-8555-555555555555";

test("unaccepted generated receipt belongs to the exact original job and managed certificate", () => {
  const containerName =
    require("../packages/agent/src/windows-cert-store").buildEnrollmentContainerName(
      enrollmentId,
    );
  const row = {
    status: "generated",
    containerName,
    jobId,
    certificateId: agentId,
    acceptedThumbprint: null,
    acceptedStore: null,
  };
  h.verifyGeneratedRecord(row, enrollmentId, jobId, agentId);
  assert.throws(() =>
    h.verifyGeneratedRecord(
      { ...row, certificateId: null },
      enrollmentId,
      jobId,
      null,
    ),
  );
  for (const changed of [
    { jobId: nextJobId },
    { certificateId: claimId },
    { status: "enrolled_by_agent" },
    { acceptedStore: "My" },
    { acceptedThumbprint: "a".repeat(40) },
  ])
    assert.throws(() =>
      h.verifyGeneratedRecord(
        { ...row, ...changed },
        enrollmentId,
        jobId,
        agentId,
      ),
    );
});

test("deferred OCSP requires the actual failed signed agent claim without orphan classification", () => {
  const row = {
    id: jobId,
    status: "failed",
    executor_kind: "agent",
    attempt_count: 1,
    claimed_by_agent_id: agentId,
    claim_id: claimId,
    needs_operator_reconciliation: false,
    consumed_nonces: 1,
  };
  assert.equal(h.verifyDeferredJob(row, jobId, agentId), claimId);
  for (const changed of [
    { status: "running" },
    { status: "succeeded" },
    { claimed_by_agent_id: claimId },
    { claim_id: null },
    { executor_kind: "server" },
    { needs_operator_reconciliation: true },
    { consumed_nonces: 0 },
  ])
    assert.throws(() =>
      h.verifyDeferredJob({ ...row, ...changed }, jobId, agentId),
    );
});

test("installed continuation needs its own authenticated agent claim and one consumed result nonce", () => {
  const row = {
    id: nextJobId,
    status: "succeeded",
    executor_kind: "agent",
    claimed_by_agent_id: agentId,
    attempt_count: 1,
    claim_id: enrollmentId,
    consumed_nonces: 1,
    needs_operator_reconciliation: false,
  };
  h.verifyContinuationJob(row, nextJobId, agentId, claimId);
  for (const changed of [
    { claim_id: claimId },
    { claimed_by_agent_id: jobId },
    { status: "failed" },
    { attempt_count: 2 },
    { consumed_nonces: 0 },
    { consumed_nonces: 2 },
    { needs_operator_reconciliation: true },
  ])
    assert.throws(() =>
      h.verifyContinuationJob(
        { ...row, ...changed },
        nextJobId,
        agentId,
        claimId,
      ),
    );
});

test("continuation is a distinct job for precisely the owned enrollment, without unrelated admissions", () => {
  const selected = [{ enrollmentId, jobId: nextJobId }];
  assert.equal(h.verifyContinuation(selected, enrollmentId, jobId), nextJobId);
  for (const changed of [
    [],
    [{ enrollmentId, jobId }],
    [{ enrollmentId: agentId, jobId: nextJobId }],
    [...selected, { enrollmentId: agentId, jobId: claimId }],
    [...selected, ...selected],
  ])
    assert.throws(() => h.verifyContinuation(changed, enrollmentId, jobId));
});
