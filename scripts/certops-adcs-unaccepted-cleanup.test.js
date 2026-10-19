"use strict";
/** Pure ownership/refusal controls, no Windows mutation. */
const { test } = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path");
const helper = require("../tests/e2e/helpers/certops-adcs-unaccepted-cleanup");
const certificateId = "11111111-1111-1111-1111-111111111111", id = "22222222-2222-2222-2222-222222222222", run = "123456abcd";
test("unaccepted ownership is registered before actual enrollment identity is known", () => {
  const receipts = [], receipt = helper.register(receipts, { certificateId, domain: `certops-adcs-${run}-cancel.example.test` }, run);
  assert.equal(receipts[0], receipt); assert.throws(() => helper.assertComplete(receipts)); assert.throws(() => helper.validateReceipt(receipt, []));
  assert.throws(() => helper.register(receipts, { certificateId, domain: receipt.domain }, run));
  assert.throws(() => helper.register([], { certificateId, domain: `certops-adcs-${run}-other.example.test` }, run));
});
test("unaccepted key cleanup refuses accepted, foreign, live and incomplete public ownership", () => {
  const receipt = helper.register([], { certificateId, domain: `certops-adcs-${run}-cancel.example.test` }, run); receipt.enrollmentIds.push(id);
  const row = { id, certificate_id: certificateId, state: "rejected_invalid", active_jobs: 0 };
  assert.equal(helper.validateReceipt(receipt, [row]), `tokentimer-enr-${id}`);
  for (const patch of [{ state: "installed" }, { state: "install_failed" }, { state: "pending_issuance" }, { state: "submission_uncertain" }, { active_jobs: 1 }, { active_jobs: "0" }, { certificate_id: id }, { id: certificateId }]) assert.throws(() => helper.validateReceipt(receipt, [{ ...row, ...patch }]));
  assert.throws(() => helper.validateReceipt(receipt, [row, row])); assert.throws(() => helper.validateReceipt(receipt, []));
  receipt.cleanupCompleted = true; assert.throws(() => helper.assertComplete([receipt])); receipt.removedEnrollmentIds.push(id); assert.doesNotThrow(() => helper.assertComplete([receipt]));
});
test("parent verifies unknown acceptance before broad deletion and retains public recovery ownership", () => {
  const source = fs.readFileSync(path.resolve(__dirname, "../tests/e2e/certops-adcs-real-e2e.test.js"), "utf8");
  assert.ok(source.indexOf("unacceptedCleanup.cleanup({") < source.indexOf("for (const thumbprint of ownedThumbprints)"));
  assert.match(source, /for \(const thumbprint of ownedThumbprints\).*nativeCleanupGuard\.assertStateRemovable\(\);unacceptedCleanup\.assertComplete\(ownedUnacceptedEnrollments\)/);
  assert.match(source, /for\(const item of \[\.\.\.cases,\.\.\.pendingCases.*nativeCleanupGuard\.assertStateRemovable\(\);unacceptedCleanup\.assertComplete\(ownedUnacceptedEnrollments\)/);
  assert.match(source, /assertNativeStateReleased\(\);return fixture\.cleanup\(\)/); assert.match(source, /assertNativeStateReleased\(\);return ownedFixture\.cleanup\(\)/);
  assert.ok(source.indexOf("nativeCleanupGuard.assertStateRemovable();unacceptedCleanup.assertComplete(ownedUnacceptedEnrollments);webHostingJourney.assertRegisteredCleanupComplete", source.indexOf("const assertNativeStateReleased")) > 0);
});
