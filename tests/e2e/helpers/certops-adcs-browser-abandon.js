"use strict";
/** Genuine dashboard Abandon/Keep/Free-the-key on the parent's real uncertain
 * AD CS enrollment. Native completion is observed by the existing fault helper;
 * no CA response, enrollment state, route response or cleanup fact is invented. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const {
  withOwnedAdcsBrowserPage,
  REQUIRED_SOURCES: SESSION_SOURCES,
} = require("./certops-adcs-browser-session");
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-real-browser-uncertain-abandon-confirmation",
  "adcs-real-browser-abandon-native-key-cleanup",
]);
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    "tests/e2e/helpers/certops-adcs-browser-abandon.js",
    "tests/e2e/helpers/certops-adcs-uncertain-abandon.js",
    "tests/e2e/helpers/certops-adcs-browser-journey.js",
    "tests/e2e/certops-adcs-real-e2e.test.js",
    "apps/dashboard/src/pages/certops/CertOpsAdcs.jsx",
    "apps/dashboard/src/components/certops/certopsEnrollmentsApi.js",
    "apps/api/routes/certops-enrollments.js",
    "apps/api/services/certops/certificateEnrollments.js",
    "infra/certops-adcs/browser-api-trust.ps1",
    "infra/certops-adcs/browser-windows-tools.ps1",
    "package.json",
    "pnpm-lock.yaml",
    ...SESSION_SOURCES,
  ]),
]);
const FLAGS = Object.freeze([
  "actualUncertainEnrollmentVisible",
  "keepDidNotMutate",
  "explicitConfirmationRequired",
  "exactPublicAbandonAcknowledged",
  "browserAndTrustDrained",
  "actualProductionContinuation",
  "journalAndDatabaseAbandoned",
  "exactUnacceptedKeyAbsent",
  "noAcceptedLeaf",
  "zeroNativeCaRequests",
  "onePublicAudit",
  "originalUnknownEffectPreserved",
]);
const SCOPE =
  "browser-confirmed-real-uncertain-abandon-and-native-unaccepted-key-cleanup";
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function verifyProof(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "enrollmentId",
      "cleanupJobId",
      "abandonPosts",
      "keepPosts",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  assert.match(value.enrollmentId, uuid);
  assert.match(value.cleanupJobId, uuid);
  assert.equal(value.abandonPosts, 1);
  assert.equal(value.keepPosts, 0);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
function verifyNativeCompletion(value, enrollmentId) {
  assert.match(enrollmentId, uuid);
  assert.equal(value.enrollmentId, enrollmentId);
  assert.match(value.cleanupJobId, uuid);
  assert.equal(value.journalState, "abandoned");
  assert.equal(value.enrollmentState, "abandoned");
  assert.equal(value.keyPresent, false);
  assert.equal(value.acceptedLeafCount, 0);
  assert.equal(value.actualCaRequests, 0);
  assert.equal(value.auditCount, 1);
  assert.equal(value.originalJobStatus, "orphaned_unknown_effect");
  assert.equal(value.needsOperatorReconciliation, true);
  return true;
}
function createBrowserAbandonActor(context) {
  const { gate, fixture } = context,
    root = path.resolve(__dirname, "../../..");
  let actedId, facts;
  return {
    async abandonEnrollment(enrollmentId) {
      assert.match(enrollmentId, uuid);
      assert.equal(actedId, undefined);
      if (context.beforeAbandon) await context.beforeAbandon(enrollmentId);
      for (const file of REQUIRED_SOURCES) {
        gate.report.fixtureSources ??= [];
        const sha256 = crypto
            .createHash("sha256")
            .update(fs.readFileSync(path.join(root, file)))
            .digest("hex"),
          prior = gate.report.fixtureSources.find((row) => row.file === file);
        if (prior) assert.equal(prior.sha256, sha256);
        else gate.report.fixtureSources.push({ file, sha256 });
      }
      await withOwnedAdcsBrowserPage(context, async (page, { origin }) => {
        const short = enrollmentId.slice(0, 8),
          abandon = page.getByRole("button", {
            name: `Abandon ${short}`,
            exact: true,
          }),
          confirm = page.getByRole("button", {
            name: `Confirm abandon ${short}`,
            exact: true,
          });
        let posts = 0,
          otherMutations = 0;
        const endpoint = `/api/v1/workspaces/${fixture.workspaceId}/certops/enrollments/${enrollmentId}/abandon`;
        page.on("request", (request) => {
          const url = new URL(request.url());
          if (
            ["POST", "PUT", "PATCH", "DELETE"].includes(request.method()) &&
            /^\/api\/v1\/workspaces\/[^/]+\/certops(?:\/|$)/.test(url.pathname)
          ) {
            if (
              request.method() === "POST" &&
              url.origin === origin &&
              url.pathname === endpoint
            )
              posts++;
            else otherMutations++;
          }
        });
        facts = { scope: SCOPE, enrollmentId, abandonPosts: 1, keepPosts: 0 };
        await gate.scenario(
          REQUIRED_SCENARIOS[0],
          async () => {
            await abandon.waitFor();
            assert.equal(await abandon.count(), 1);
            assert.equal(await confirm.count(), 0);
            await abandon.click();
            await confirm.waitFor();
            assert.equal(posts, 0);
            assert.equal(otherMutations, 0);
            const row = confirm.locator(
              'xpath=ancestor::div[.//button[normalize-space()="Keep"]][1]',
            );
            await row
              .getByRole("button", { name: "Keep", exact: true })
              .click();
            await abandon.waitFor();
            assert.equal(await confirm.count(), 0);
            assert.equal(posts, 0);
            assert.equal(otherMutations, 0);
            facts.keepDidNotMutate = facts.explicitConfirmationRequired = true;
            await abandon.click();
            const [response] = await Promise.all([
              page.waitForResponse(
                (response) =>
                  response.request().method() === "POST" &&
                  new URL(response.url()).origin === origin &&
                  new URL(response.url()).pathname === endpoint,
              ),
              confirm.click(),
            ]);
            assert.equal(response.status(), 204);
            assert.equal(posts, 1);
            assert.equal(otherMutations, 0);
            facts.actualUncertainEnrollmentVisible =
              facts.exactPublicAbandonAcknowledged = true;
            actedId = enrollmentId;
          },
          {
            evidenceLevel: "real-host",
            oracle:
              "actual dashboard uncertain enrollment, Keep sends no mutation, explicit Free-the-key confirmation invokes exactly one real public abandon route acknowledged204",
          },
        );
      });
      facts.browserAndTrustDrained = true;
    },
    async observeNativeCompletion(observed) {
      verifyNativeCompletion(observed, actedId);
      assert.ok(facts);
      await gate.scenario(
        REQUIRED_SCENARIOS[1],
        () => {
          Object.assign(facts, {
            cleanupJobId: observed.cleanupJobId,
            ...Object.fromEntries(FLAGS.slice(5).map((flag) => [flag, true])),
          });
          verifyProof(facts);
          gate.report.nativeBrowserAbandon = facts;
        },
        {
          evidenceLevel: "real-host",
          oracle:
            "existing actual production continuation independently proves abandoned journal/database, exact unaccepted key absence, zero CA requests, no accepted leaf, one audit and original unknown-effect job retained",
        },
      );
    },
  };
}
module.exports = {
  REQUIRED_SCENARIOS,
  REQUIRED_SOURCES,
  FLAGS,
  SCOPE,
  verifyProof,
  verifyNativeCompletion,
  createBrowserAbandonActor,
};
