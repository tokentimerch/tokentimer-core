"use strict";
// Supporting request/proof checks only. No browser, native key or CA is run.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const helper = require("../tests/e2e/helpers/certops-adcs-browser-cancel");
const ids = ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"];
function fixture() { return { scope: helper.SCOPE, enrollmentId: ids[0], jobId: ids[1], priorEnrollmentId: ids[2], priorJobId: ids[3], priorRequestId: "17", fingerprint: "a".repeat(64), cancelPosts: 1, otherMutations: 0, capacityBeforeCancel: 5, capacityAfterCancel: 4, initialSixConcurrencyQualified: false, caSubmissionCancellationQualified: false, ...Object.fromEntries(helper.FLAGS.map(flag => [flag, true])) }; }
test("GUI Cancel proof is separate from initial concurrency and CA-submitted cancellation", () => {
  assert.equal(helper.verifyProof(fixture()), true);
  for (const [key, value] of Object.entries(fixture())) {
    const missing = fixture(); delete missing[key]; assert.throws(() => helper.verifyProof(missing));
    assert.throws(() => helper.verifyProof({ ...fixture(), [key]: typeof value === "boolean" ? !value : "wrong" }));
  }
  for (const patch of [{ scope: "cancel-submitted-ca-request" }, { initialSixConcurrencyQualified: true }, { caSubmissionCancellationQualified: true }, { priorRequestId: "4294967296" }, { priorEnrollmentId: ids[0] }, { priorJobId: ids[1] }, { capacityBeforeCancel: 4 }, { capacityAfterCancel: 5 }, { cancelPosts: 2 }, { otherMutations: 1 }, { rawCngKey: "forbidden" }]) assert.throws(() => helper.verifyProof({ ...fixture(), ...patch }));
});
test("Cancel request must be one exact same-origin enrollment POST without body", () => {
  const expected = { origin: "https://10.64.0.6", workspaceId: ids[2], enrollmentId: ids[0] };
  const url = `${expected.origin}/api/v1/workspaces/${expected.workspaceId}/certops/enrollments/${expected.enrollmentId}/cancel`;
  const request = (overrides = {}) => ({ method: () => "POST", url: () => url, postData: () => null, ...overrides });
  assert.equal(helper.verifyRequest(request(), expected), true);
  for (const patch of [{ method: () => "DELETE" }, { url: () => url.replace("10.64.0.6", "foreign.example") }, { url: () => url + "?unexpected=1" }, { url: () => url + "#fragment" }, { url: () => url.replace(ids[0], ids[1]) }, { postData: () => "{}" }, { postData: () => "private-sentinel" }]) assert.throws(() => helper.verifyRequest(request(patch), expected));
});

test("Fallback withdrawal refuses unknown, claimed or attempted work", () => {
  const row = { current_job_id: ids[1], state: "requested", job_status: "pending_approval", claim_id: null, claimed_by_agent_id: null, attempt_count: 0, request_id: null };
  assert.equal(helper.canWithdrawRequested(row, ids[1]), true);
  assert.equal(helper.canWithdrawRequested(undefined, ids[1]), false);
  for (const [key, value] of Object.entries(row)) assert.equal(helper.canWithdrawRequested({ ...row, [key]: value === null ? "claimed" : "other" }, ids[1]), false, key);
});
