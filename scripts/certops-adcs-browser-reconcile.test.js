"use strict";
// Controlled HTTP/native-proof adversaries only; no browser, CA, certificate,
// service or enrollment operation occurs, and no native qualification is claimed.
const test = require("node:test"), assert = require("node:assert/strict");
const gui = require("../tests/e2e/helpers/certops-adcs-browser-reconcile"), native = require("../tests/e2e/helpers/certops-adcs-uncertain-operator-ambiguity");
const enrollmentId = "11111111-1111-1111-1111-111111111111", workspaceId = "22222222-2222-2222-2222-222222222222";
const expected = { origin: "https://10.64.0.6", workspaceId, enrollmentId, selectedRequestId: "17" };
function request(change = {}) { const value = { method: "POST", url: `${expected.origin}/api/v1/workspaces/${workspaceId}/certops/enrollments/${enrollmentId}/reconcile`, body: { requestId: 17 }, ...change }; return { method: () => value.method, url: () => value.url, postDataJSON: () => value.body }; }
function nativeProof() { return { scope: native.SCOPE, fixtureOrigin: gui.ORIGIN, resolvedIssuingCaAddress: "10.64.0.4", leaseRemainingAtFaultMs: 1000, recoveryWaitBudgetMs: 91000, actualLeaseWaitMs: 62000, caRequestsAtFault: 0, caRequestsAfterOperatorSubmissions: 2, caRequestsAfterAmbiguousRecovery: 2, caRequestsAfterExplicitRecovery: 2, requestIds: ["17", "18"], fingerprints: ["a".repeat(64), "b".repeat(64)], serialNumbers: ["aa", "bb"], csrSpkiSha256: "c".repeat(64), csrSha256: "d".repeat(64), selectedRequestId: "17", unusedRequestId: "18", enrollmentId, containerName: `tokentimer-enr-${enrollmentId}`, jobIds: ["33333333-3333-3333-3333-333333333333", "44444444-4444-4444-4444-444444444444", "55555555-5555-5555-5555-555555555555"], reconcileSearchFrom: 17, scanWindowSize: 16, ...Object.fromEntries(native.FLAGS.map(flag => [flag, true])) }; }
function proof() { return { scope: gui.SCOPE, fixtureOrigin: gui.ORIGIN, enrollmentId, selectedRequestId: "17", unusedRequestId: "18", selectedFingerprint: "a".repeat(64), continuationJobId: "55555555-5555-5555-5555-555555555555", reconcilePosts: 1, invalidRequestPosts: 0, ...Object.fromEntries(gui.FLAGS.map(flag => [flag, true])) }; }
test("mutation accounting includes every CertOps write even for another action or workspace", () => {
  for (const method of ["POST", "PUT", "PATCH", "DELETE"]) for (const url of [request().url(), `${expected.origin}/api/v1/workspaces/${enrollmentId}/certops/settings`, "https://foreign.example.test/api/v1/workspaces/foreign/certops/jobs"]) assert.equal(gui.isCertOpsWrite(request({ method, url })), true);
  for (const method of ["GET", "HEAD", "OPTIONS"]) assert.equal(gui.isCertOpsWrite(request({ method })), false);
  assert.equal(gui.isCertOpsWrite(request({ url: expected.origin + "/api/session" })), false);
});
test("actual reconcile request oracle refuses recovery, foreign targets, extra data and wrong selected IDs without logging bodies", () => {
  assert.equal(gui.verifyRequest(request(), expected), true);
  for (const change of [{ method: "GET" }, { url: request().url().replace("/reconcile", "/recover") }, { url: request().url() + "?requestId=17" }, { url: request().url() + "?token=private-sentinel-never-print" }, { url: request().url().replace("https://", "https://private-sentinel-never-print@") }, { url: request().url().replace(expected.origin, "https://foreign.example.test") }, { url: request().url().replace(enrollmentId, workspaceId) }, { body: { requestId: 18 } }, { body: { requestId: "17" } }, { body: { acknowledgeUnknownEffect: true } }, { body: { requestId: 17, credential: "private-sentinel-never-print" } }]) {
    let error; try { gui.verifyRequest(request(change), expected); } catch (caught) { error = caught; } assert.ok(error); assert.equal(String(error).includes("private-sentinel-never-print"), false);
  }
});
test("browser native completion requires the complete independently verified operator ambiguity proof", () => {
  const acted = { enrollmentId, selectedRequestId: "17" };
  assert.deepEqual(gui.verifyNativeCompletion(nativeProof(), acted), { unusedRequestId: "18", selectedFingerprint: "a".repeat(64), continuationJobId: "55555555-5555-5555-5555-555555555555" });
  for (const flag of native.FLAGS) { const bad = nativeProof(); bad[flag] = false; assert.throws(() => gui.verifyNativeCompletion(bad, acted), flag); }
  assert.throws(() => gui.verifyNativeCompletion(nativeProof(), { ...acted, selectedRequestId: "18" }));
  const bad = nativeProof(); bad.fixtureOrigin = "deterministic-real-response-loss"; assert.throws(() => gui.verifyNativeCompletion(bad, acted));
});
test("browser proof preserves one exact RequestId action, cleanup and narrow source origin", () => {
  assert.equal(gui.verifyProof(proof()), true);
  for (const flag of gui.FLAGS) for (const value of [false, 1, "true", undefined]) { const bad = proof(); bad[flag] = value; assert.throws(() => gui.verifyProof(bad), flag); }
  for (const [field, value] of [["fixtureOrigin", "real-response-loss"], ["selectedRequestId", "0"], ["selectedRequestId", "4294967296"], ["unusedRequestId", "17"], ["reconcilePosts", 2], ["invalidRequestPosts", 1]]) { const bad = proof(); bad[field] = value; assert.throws(() => gui.verifyProof(bad), field); }
  const bad = proof(); bad.browserStorageState = {}; assert.throws(() => gui.verifyProof(bad));
  assert.equal(gui.verifyCrossProof(proof(), nativeProof()), true);
  for (const [field, value] of [["selectedRequestId", "18"], ["unusedRequestId", "19"], ["selectedFingerprint", "b".repeat(64)], ["continuationJobId", "66666666-6666-6666-6666-666666666666"]]) { const different = proof(); different[field] = value; assert.throws(() => gui.verifyCrossProof(different, nativeProof()), field); }
});
test("browser completion cannot run if the owning native fixture fails its final restoration", async () => {
  const bridge = require("../tests/e2e/helpers/certops-adcs-uncertain-abandon"), original = bridge.qualifyUncertainScenario;
  let completed = false;
  bridge.qualifyUncertainScenario = () => Promise.reject(new Error("Controlled native restoration refusal"));
  try {
    await assert.rejects(native.qualifyOperatorCreatedAmbiguity({ reconcileActor: { reconcileEnrollment() {}, observeNativeCompletion() { completed = true; } } }), /Controlled native restoration refusal/);
    assert.equal(completed, false);
    await assert.rejects(native.qualifyOperatorCreatedAmbiguity({ reconcileActor: { reconcileEnrollment() {} } }));
  } finally { bridge.qualifyUncertainScenario = original; }
});
