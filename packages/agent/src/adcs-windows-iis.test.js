"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");

const {
  resultForAdcsOutcome,
  resultForValidationOutcome,
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

  it("maps denied with a contract-shaped caHresult", () => {
    const result = resultForAdcsOutcome(
      {
        outcome: "denied",
        detail: "denied",
        caHresult: "0x80094012",
        requestId: 4242,
      },
      ENROLLMENT,
    );
    assert.equal(result.status, "failed");
    assert.equal(result.enrollmentResult.state, "denied");
    assert.equal(result.enrollmentResult.caHresult, "0x80094012");
    assert.equal(result.enrollmentResult.requestId, 4242);
  });

  it("does not claim denied without a contract-shaped caHresult", () => {
    const result = resultForAdcsOutcome(
      { outcome: "denied", detail: "denied" },
      ENROLLMENT,
    );
    assert.equal(result.enrollmentResult.state, "submission_uncertain");
  });

  it("maps submit uncertain to submission_uncertain", () => {
    const result = resultForAdcsOutcome(
      { outcome: "uncertain", detail: "maybe" },
      ENROLLMENT,
    );
    assert.equal(result.status, "failed");
    assert.equal(result.enrollmentResult.state, "submission_uncertain");
    assert.equal(result.enrollmentResult.errorCode, "ADCS_DISPOSITION_UNKNOWN");
  });

  it("keeps pending_issuance when retrieve is uncertain for a known RequestId", () => {
    const result = resultForAdcsOutcome(
      { outcome: "uncertain", detail: "retrieve flaky" },
      ENROLLMENT,
      { knownRequestId: 4242 },
    );
    assert.equal(result.status, "failed");
    assert.deepEqual(result.enrollmentResult, {
      enrollmentId: ENROLLMENT.enrollmentId,
      attempt: 1,
      state: "pending_issuance",
      requestId: 4242,
    });
  });
});

describe("shouldRetainCngKey", () => {
  it("retains the key when a later continue-enrollment may need it", () => {
    for (const outcome of ["pending", "uncertain", "issued", "validation_deferred"]) {
      assert.equal(shouldRetainCngKey(outcome), true, outcome);
    }
    // not_submitted never reached the CA; free the container so renew can retry.
    assert.equal(shouldRetainCngKey("not_submitted"), false);
    assert.equal(shouldRetainCngKey("denied"), false);
    assert.equal(shouldRetainCngKey("failed"), false);
    assert.equal(shouldRetainCngKey("rejected_invalid"), false);
  });
});

describe("resultForValidationOutcome", () => {
  it("maps deferred validation while retaining enrollment identity", () => {
    const result = resultForValidationOutcome(
      { state: "validation_deferred", detail: "offline CRL" },
      ENROLLMENT,
      99,
    );
    assert.equal(result.status, "failed");
    assert.equal(result.enrollmentResult.state, "validation_deferred");
    assert.equal(result.enrollmentResult.requestId, 99);
  });

  it("maps rejected_invalid with ADCS_CERTIFICATE_INVALID", () => {
    const result = resultForValidationOutcome(
      {
        state: "rejected_invalid",
        errorCode: "ADCS_CERTIFICATE_INVALID",
        detail: "bad SAN",
      },
      ENROLLMENT,
    );
    assert.equal(result.enrollmentResult.state, "rejected_invalid");
    assert.equal(result.enrollmentResult.errorCode, "ADCS_CERTIFICATE_INVALID");
  });
});
