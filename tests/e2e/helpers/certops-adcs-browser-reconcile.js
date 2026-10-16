"use strict";
/** Supported RequestId Reconcile UI on genuine operator-created CA ambiguity.
 * The existing native fixture owns both same-CSR requests, original orphan,
 * protected key, exact installation and unused-request revocation. This actor
 * never presents acknowledged API recovery as a nonexistent UI capability. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const session = require("./certops-adcs-browser-session");
const native = require("./certops-adcs-uncertain-operator-ambiguity");
const REQUIRED_SCENARIOS = Object.freeze(["adcs-real-browser-owned-requestid-reconcile", "adcs-real-browser-reconcile-native-installed-and-unused-revoked"]);
const REQUIRED_SOURCES = Object.freeze([...new Set([...session.REQUIRED_SOURCES, ...native.REQUIRED_SOURCES, "tests/e2e/helpers/certops-adcs-browser-reconcile.js", "apps/dashboard/src/pages/certops/CertOpsAdcs.jsx", "apps/dashboard/src/components/certops/certopsEnrollmentsApi.js", "apps/api/routes/certops-enrollments.js", "apps/api/services/certops/certificateEnrollments.js"])]);
const FLAGS = Object.freeze(["actualUncertainRequestIdForm", "invalidRequestIdDidNotMutate", "exactOwnedRequestIdPosted", "exactPublicReconcileAcknowledged", "browserAndTrustDrained", "nativeSelectedRequestInstalled", "nativeSameProtectedMachineKey", "nativeClaimBoundVerification", "nativeExactReconcileAudit", "unusedOwnedRequestRevoked", "unusedLeafNeverAccepted", "originalOrphanPreserved"]);
const SCOPE = "browser-requestid-reconcile-real-operator-created-same-csr-ambiguity";
const ORIGIN = "operator-created-two-real-system-submissions-of-the-same-public-csr";
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function requestId(value) { assert.equal(typeof value, "string"); assert.match(value, /^[1-9][0-9]{0,9}$/); assert.ok(Number(value) <= 0xffffffff); return Number(value); }
function isCertOpsWrite(request) { return ["POST", "PUT", "PATCH", "DELETE"].includes(request.method()) && /^\/api\/v1\/workspaces\/[^/]+\/certops(?:\/|$)/.test(new URL(request.url()).pathname); }
function verifyRequest(request, { origin, workspaceId, enrollmentId, selectedRequestId }) {
  assert.match(workspaceId, UUID); assert.match(enrollmentId, UUID);
  let url, body; try { url = new URL(request.url()); body = request.postDataJSON(); } catch { throw new Error("Reconcile request URL or JSON invalid"); }
  assert.ok(request.method() === "POST", "Unexpected Reconcile method"); assert.ok(url.origin === origin && !url.username && !url.password, "Unexpected Reconcile origin");
  assert.ok(url.pathname === `/api/v1/workspaces/${workspaceId}/certops/enrollments/${enrollmentId}/reconcile` && !url.search && !url.hash, "Unexpected Reconcile target");
  // Request bodies must never appear in assertion diffs or native artifacts.
  assert.ok(body && typeof body === "object" && !Array.isArray(body) && Object.keys(body).join() === "requestId", "Unexpected reconcile request shape");
  assert.ok(body.requestId === requestId(selectedRequestId), "Browser must post the independently selected owned RequestId"); return true;
}
function verifyProof(value) {
  assert.deepEqual(Object.keys(value).sort(), ["scope", "fixtureOrigin", "enrollmentId", "selectedRequestId", "unusedRequestId", "selectedFingerprint", "continuationJobId", "reconcilePosts", "invalidRequestPosts", ...FLAGS].sort());
  assert.equal(value.scope, SCOPE); assert.equal(value.fixtureOrigin, ORIGIN); assert.match(value.enrollmentId, UUID); assert.match(value.continuationJobId, UUID);
  requestId(value.selectedRequestId); requestId(value.unusedRequestId); assert.notEqual(value.selectedRequestId, value.unusedRequestId); assert.match(value.selectedFingerprint, /^[a-f0-9]{64}$/);
  assert.equal(value.reconcilePosts, 1); assert.equal(value.invalidRequestPosts, 0); for (const flag of FLAGS) assert.equal(value[flag], true, flag); return true;
}
function verifyNativeCompletion(value, acted) {
  native.verifyProof(value);
  assert.equal(value.enrollmentId, acted.enrollmentId); assert.equal(value.selectedRequestId, acted.selectedRequestId);
  assert.equal(value.fixtureOrigin, ORIGIN); assert.equal(value.caRequestsAfterExplicitRecovery, 2);
  return { unusedRequestId: value.unusedRequestId, selectedFingerprint: value.fingerprints[value.requestIds.indexOf(value.selectedRequestId)], continuationJobId: value.jobIds[2] };
}
function verifyCrossProof(value, nativeValue) {
  verifyProof(value); const expected = verifyNativeCompletion(nativeValue, value);
  for (const field of ["unusedRequestId", "selectedFingerprint", "continuationJobId"]) assert.equal(value[field], expected[field], "Browser reconciliation must match the actual native fixture");
  return true;
}
function createBrowserReconcileActor(context) {
  const { gate, fixture } = context, root = path.resolve(__dirname, "../../..");
  let acted, facts;
  return {
    async reconcileEnrollment(enrollmentId, selectedRequestId) {
      assert.equal(process.platform, "win32"); assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1"); assert.equal(process.env.CERTOPS_ADCS_BROWSER, "1");
      assert.match(enrollmentId, UUID); requestId(selectedRequestId); assert.equal(acted, undefined);
      gate.report.fixtureSources ??= [];
      for (const file of REQUIRED_SOURCES) { const sha256 = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex"), prior = gate.report.fixtureSources.filter(row => row.file === file); if (prior.length) { assert.equal(prior.length, 1); assert.equal(prior[0].sha256, sha256); } else gate.report.fixtureSources.push({ file, sha256 }); }
      await gate.scenario(REQUIRED_SCENARIOS[0], async () => {
        await session.withOwnedAdcsBrowserPage(context, async (page, { origin }) => {
          const short = enrollmentId.slice(0, 8), input = page.getByRole("textbox", { name: `RequestId for ${short}`, exact: true }), button = page.getByRole("button", { name: `Reconcile ${short}`, exact: true });
          await input.waitFor(); await button.waitFor(); assert.equal(await input.count(), 1); assert.equal(await button.count(), 1);
          let posts = 0, wrongRequest = false;
          const expected = { origin, workspaceId: fixture.workspaceId, enrollmentId, selectedRequestId };
          const prefix = `/api/v1/workspaces/${fixture.workspaceId}/certops/enrollments/`;
          page.on("request", request => { if (isCertOpsWrite(request)) { posts++; try { verifyRequest(request, expected); } catch { wrongRequest = true; } } });
          // Exercise the actual supported form's numeric boundary before the
          // owned valid ID. Native state and route responses remain untouched.
          await input.fill("0"); await button.click();
          await page.getByText("RequestId must be an integer from 1 to 4294967295.", { exact: true }).first().waitFor(); assert.equal(posts, 0);
          await input.fill(selectedRequestId);
          const [response] = await Promise.all([page.waitForResponse(response => response.request().method() === "POST" && new URL(response.url()).origin === origin && new URL(response.url()).pathname === prefix + enrollmentId + "/reconcile"), button.click()]);
          assert.equal(response.status(), 204); verifyRequest(response.request(), expected); assert.equal(posts, 1); assert.equal(wrongRequest, false);
          facts = { scope: SCOPE, fixtureOrigin: ORIGIN, enrollmentId, selectedRequestId, reconcilePosts: posts, invalidRequestPosts: 0, actualUncertainRequestIdForm: true, invalidRequestIdDidNotMutate: true, exactOwnedRequestIdPosted: true, exactPublicReconcileAcknowledged: true };
        });
        facts.browserAndTrustDrained = true; acted = { enrollmentId, selectedRequestId };
      }, { evidenceLevel: "real-host", oracle: "actual trusted Chromium enrollment RequestId form refuses zero without a mutation, then posts exactly the independently selected real owned RequestId and receives public204; exact browser and trust ownership drain" });
    },
    async observeNativeCompletion(value) {
      assert.ok(acted && facts); const observed = verifyNativeCompletion(value, acted);
      await gate.scenario(REQUIRED_SCENARIOS[1], () => {
        Object.assign(facts, observed, { nativeSelectedRequestInstalled: true, nativeSameProtectedMachineKey: true, nativeClaimBoundVerification: true, nativeExactReconcileAudit: true, unusedOwnedRequestRevoked: true, unusedLeafNeverAccepted: true, originalOrphanPreserved: true });
        verifyCrossProof(facts, value); gate.report.nativeBrowserReconcile = facts;
      }, { evidenceLevel: "real-host", oracle: "existing full genuine same-CSR ambiguity proof verifies selected CA RequestId/leaf, unchanged protected machine key, claim-bound trusted IIS TLS, exact public reconcile audit, unused-request revocation/complete-store absence and preserved original orphan" });
    },
  };
}
module.exports = { REQUIRED_SCENARIOS, REQUIRED_SOURCES, FLAGS, SCOPE, ORIGIN, verifyProof, verifyRequest, verifyNativeCompletion, verifyCrossProof, isCertOpsWrite, createBrowserReconcileActor };
