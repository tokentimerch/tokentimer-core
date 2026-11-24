"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  _test: { jobSummary, jobDetail, jobLogEntry, redactClaimIdForNonAdmins },
} = require(path.resolve(__dirname, "../../apps/api/routes/certops.js"));

const CLAIM_ID = "22222222-2222-4222-8222-222222222222";

function claimedJob(overrides = {}) {
  return {
    id: "job-1",
    workspaceId: "11111111-1111-4111-8111-111111111111",
    operation: "renew",
    status: "claimed",
    source: "api",
    subjectType: "managed_certificate",
    subjectId: "cert-1",
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    claimId: CLAIM_ID,
    claimedByAgentId: "agent-1",
    leaseExpiresAt: "2026-01-01T00:10:00.000Z",
    attemptCount: 1,
    maxAttempts: 3,
    ...overrides,
  };
}

describe("CertOps job-detail claimId visibility", () => {
  it("keeps claimId for an admin workspace role", () => {
    const req = { authz: { workspaceRole: "admin" } };
    const projection = redactClaimIdForNonAdmins(req, jobDetail(claimedJob()));

    assert.equal(projection.claimId, CLAIM_ID);
  });

  it("strips claimId for a workspace_manager role", () => {
    const req = { authz: { workspaceRole: "workspace_manager" } };
    const projection = redactClaimIdForNonAdmins(req, jobDetail(claimedJob()));

    assert.equal(projection.claimId, undefined);
  });

  it("strips claimId for a viewer role", () => {
    const req = { authz: { workspaceRole: "viewer" } };
    const projection = redactClaimIdForNonAdmins(req, jobDetail(claimedJob()));

    assert.equal(projection.claimId, undefined);
  });

  it("strips claimId when the caller has no resolved workspace role", () => {
    const req = { authz: {} };
    const projection = redactClaimIdForNonAdmins(req, jobDetail(claimedJob()));

    assert.equal(projection.claimId, undefined);
  });

  it("keeps claimId for internal worker calls, which carry implicit admin", () => {
    const req = { isWorkerCall: true, authz: {} };
    const projection = redactClaimIdForNonAdmins(req, jobDetail(claimedJob()));

    assert.equal(projection.claimId, CLAIM_ID);
  });

  it("is a no-op when the job has no claimId yet (unclaimed job)", () => {
    const req = { authz: { workspaceRole: "viewer" } };
    const projection = redactClaimIdForNonAdmins(
      req,
      jobDetail(claimedJob({ claimId: null })),
    );

    assert.equal(projection.claimId, null);
  });

  it("leaves every other job-detail field untouched for a non-admin", () => {
    const req = { authz: { workspaceRole: "viewer" } };
    const detail = jobDetail(claimedJob());
    const projection = redactClaimIdForNonAdmins(req, detail);

    for (const [key, value] of Object.entries(detail)) {
      if (key === "claimId") continue;
      assert.equal(projection[key], value, `${key} must be unchanged`);
    }
  });

  it("applies the same claim visibility to agent result metadata in the timeline", () => {
    const entry = { metadata: {
      claimId: CLAIM_ID,
      deploymentDestinationValidation: { claimId: CLAIM_ID, version: 1 },
      deploymentDestinationDispatch: { operation: { ownerClaimId: CLAIM_ID, operationId: "operation-1" } },
      deploymentDestinationObservation: { claimId: CLAIM_ID, receipt: { version: 1 } },
    } };
    const viewer = jobLogEntry({ authz: { workspaceRole: "viewer" } }, entry);
    const admin = jobLogEntry({ authz: { workspaceRole: "admin" } }, entry);
    assert.ok(!JSON.stringify(viewer.metadata).includes(CLAIM_ID));
    assert.equal(viewer.metadata.deploymentDestinationDispatch.operation.operationId, "operation-1");
    assert.deepEqual(viewer.metadata.deploymentDestinationObservation.receipt, { version: 1 });
    assert.equal(admin.metadata, entry.metadata);
    assert.equal(entry.metadata.deploymentDestinationObservation.claimId, CLAIM_ID);
  });
});

describe("CertOps job projection approval attribution", () => {
  it("jobSummary carries approvedByUserId/approvedAt when present on the job", () => {
    const approved = jobSummary(
      claimedJob({
        status: "approved",
        approvedByUserId: "user-42",
        approvedAt: "2026-01-01T00:05:00.000Z",
      }),
    );

    assert.equal(approved.approvedByUserId, "user-42");
    assert.equal(approved.approvedByDisplayName, null);
    assert.equal(approved.approvedAt, "2026-01-01T00:05:00.000Z");
  });

  it("jobSummary carries approvedByDisplayName when the service resolved one", () => {
    const approved = jobSummary(
      claimedJob({
        status: "approved",
        approvedByUserId: 9,
        approvedByDisplayName: "Alice Admin",
        approvedAt: "2026-01-01T00:05:00.000Z",
      }),
    );

    assert.equal(approved.approvedByUserId, 9);
    assert.equal(approved.approvedByDisplayName, "Alice Admin");
  });

  it("jobSummary surfaces null approvedByUserId/approvedAt rather than dropping the keys", () => {
    const pending = jobSummary(
      claimedJob({
        status: "pending_approval",
        approvedByUserId: null,
        approvedAt: null,
      }),
    );

    assert.equal(pending.approvedByUserId, null);
    assert.equal(pending.approvedByDisplayName, null);
    assert.equal(pending.approvedAt, null);
  });

  it("jobDetail (which spreads jobSummary) also carries approvedByUserId/approvedAt", () => {
    const detail = jobDetail(
      claimedJob({
        status: "approved",
        approvedByUserId: "user-42",
        approvedAt: "2026-01-01T00:05:00.000Z",
      }),
    );

    assert.equal(detail.approvedByUserId, "user-42");
    assert.equal(detail.approvedByDisplayName, null);
    assert.equal(detail.approvedAt, "2026-01-01T00:05:00.000Z");
  });

  it("jobSummary carries assignedAgentId, pendingReason, and reconciliation fields for the jobs list", () => {
    const listed = jobSummary(
      claimedJob({
        status: "pending",
        assignedAgentId: "agent-row-1",
        claimedByAgentId: null,
        needsOperatorReconciliation: false,
        reconciliationReason: null,
        errorMessage: null,
        pendingReason: {
          code: "awaiting_claim",
          message: "Waiting for the assigned agent to poll and claim this job.",
        },
      }),
    );

    assert.equal(listed.assignedAgentId, "agent-row-1");
    assert.equal(listed.pendingReason.code, "awaiting_claim");
    assert.equal(listed.needsOperatorReconciliation, false);
    assert.equal(listed.errorMessage, null);
  });

  it("jobDetail on a job with null approval fields surfaces them as null, not undefined", () => {
    const detail = jobDetail(
      claimedJob({
        status: "rejected",
        approvedByUserId: null,
        approvedAt: null,
      }),
    );

    assert.equal(detail.approvedByUserId, null);
    assert.equal(detail.approvedByDisplayName, null);
    assert.equal(detail.approvedAt, null);
  });
});

it("redacts nested destination claim identity on unclaimed job views", () => {
  const detail = {
    claimId: null,
    payload: { deploymentDestinationExecution: { validationClaimId: "source-claim", validationJobId: "source-job" } },
    resultMetadata: { deploymentDestinationValidation: { claimId: "result-claim", receipt: { version: 1 } } },
  };
  const view = redactClaimIdForNonAdmins({ authz: { workspaceRole: "viewer" } }, detail);
  assert.equal(view.payload.deploymentDestinationExecution.validationClaimId, undefined);
  assert.equal(view.resultMetadata.deploymentDestinationValidation.claimId, undefined);
  assert.equal(view.payload.deploymentDestinationExecution.validationJobId, "source-job");
  assert.equal(detail.payload.deploymentDestinationExecution.validationClaimId, "source-claim");
  assert.equal(detail.resultMetadata.deploymentDestinationValidation.claimId, "result-claim");
});

it("hides the destination owner claim on live and terminal job views below admin", () => {
  const operation = {
    version: 1,
    operationId: "a".repeat(64),
    mutationDomainSha256: "b".repeat(64),
    ownerClaimId: CLAIM_ID,
  };
  const dispatch = { bindingSha256: "c".repeat(64), operation };
  for (const [status, claimId] of [["running", CLAIM_ID], ["blocked", null]]) {
    const detail = jobDetail(claimedJob({
      status, claimId, operation: "execute-deployment-destination",
      resultMetadata: { deploymentDestinationDispatch: dispatch, otherEvidence: { version: 1 } },
    }));
    for (const workspaceRole of ["viewer", "workspace_manager"]) {
      const view = redactClaimIdForNonAdmins({ authz: { workspaceRole } }, detail);
      assert.equal(view.claimId, status === "running" ? undefined : null);
      assert.deepEqual(JSON.parse(JSON.stringify(view.resultMetadata)), {
        deploymentDestinationDispatch: {
          bindingSha256: dispatch.bindingSha256,
          operation: {
            version: operation.version,
            operationId: operation.operationId,
            mutationDomainSha256: operation.mutationDomainSha256,
          },
        },
        otherEvidence: { version: 1 },
      });
      assert.equal(detail.resultMetadata.deploymentDestinationDispatch.operation.ownerClaimId, CLAIM_ID);
    }
    const admin = redactClaimIdForNonAdmins({ authz: { workspaceRole: "admin" } }, detail);
    assert.equal(admin.resultMetadata.deploymentDestinationDispatch.operation.ownerClaimId, CLAIM_ID);
    assert.equal(admin, detail);
  }
});

it("conceals historical observation claim IDs on viewer job details", () => {
  const detail = {
    payload: { deploymentDestinationObservation: { ownerClaimId: "source-claim", operationId: "source-operation" } },
    resultMetadata: { deploymentDestinationObservation: { claimId: "fresh-claim", receipt: { version: 1 } } },
  };
  const view = redactClaimIdForNonAdmins({ authz: { workspaceRole: "viewer" } }, detail);
  assert.equal(view.payload.deploymentDestinationObservation.ownerClaimId, undefined);
  assert.equal(view.resultMetadata.deploymentDestinationObservation.claimId, undefined);
  assert.equal(view.payload.deploymentDestinationObservation.operationId, "source-operation");
  assert.equal(detail.payload.deploymentDestinationObservation.ownerClaimId, "source-claim");
  assert.equal(redactClaimIdForNonAdmins({ authz: { workspaceRole: "admin" } }, detail), detail);
});
