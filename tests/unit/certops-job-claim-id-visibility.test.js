"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const {
  _test: { jobDetail, redactClaimIdForNonAdmins },
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
});
