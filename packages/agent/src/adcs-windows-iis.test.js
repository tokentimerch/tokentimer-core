"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  resultForAdcsOutcome,
  shouldRetainCngKey,
} = require("./adcs-windows-iis");

const ENROLLMENT = {
  enrollmentId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  attempt: 1,
};

describe("resultForAdcsOutcome", () => {
  it("maps pending to awaiting_issuer with enrollmentResult", () => {
    const result = resultForAdcsOutcome(
      { outcome: "pending", requestId: 4242 },
      ENROLLMENT,
    );
    assert.equal(result.status, "awaiting_issuer");
    assert.deepEqual(result.enrollmentResult, {
      enrollmentId: ENROLLMENT.enrollmentId,
      attempt: 1,
      state: "pending_issuance",
      requestId: 4242,
    });
  });

  it("maps refused to rejected with enrollmentResult", () => {
    const result = resultForAdcsOutcome(
      {
        outcome: "refused",
        rejectionReason: "issuer_not_allowlisted",
        detail: "CA pin missing",
        errorCode: "ADCS_CA_PIN_MISSING",
      },
      ENROLLMENT,
    );
    assert.equal(result.status, "rejected");
    assert.equal(result.rejectionReason, "issuer_not_allowlisted");
    assert.equal(result.enrollmentResult.state, "refused");
  });

  it("maps denied and uncertain to failed", () => {
    assert.equal(
      resultForAdcsOutcome({ outcome: "denied", detail: "denied" }, ENROLLMENT)
        .status,
      "failed",
    );
    assert.equal(
      resultForAdcsOutcome(
        { outcome: "uncertain", detail: "maybe" },
        ENROLLMENT,
      ).status,
      "failed",
    );
  });
});

describe("shouldRetainCngKey", () => {
  it("retains the key when a later continue-enrollment may need it", () => {
    for (const outcome of ["pending", "not_submitted", "uncertain", "issued"]) {
      assert.equal(shouldRetainCngKey(outcome), true, outcome);
    }
    assert.equal(shouldRetainCngKey("denied"), false);
    assert.equal(shouldRetainCngKey("failed"), false);
  });
});
