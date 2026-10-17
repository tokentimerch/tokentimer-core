"use strict";
/** Prevent a successful report envelope from promoting local-only contract
 * evidence. These fixtures do not execute a browser, host, provider or CA. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const crypto = require("node:crypto");
const matrix = require("../docs/certops/release-qualification-matrix.json");
const metadata = require("../docs/certops/qualification-suites.json");
const { verifyMatrix } = require("./certops-release-qualification");
const { verifyReport } = require("./certops-qualification-report");
const candidateSha = "a".repeat(40);
const now = "2026-10-17T00:00:00.000Z";
const digests = new Map();
function digest(file) {
  if (!digests.has(file)) digests.set(file, crypto.createHash("sha256").update(fs.readFileSync(require("node:path").join(__dirname, "..", file))).digest("hex"));
  return { file, sha256: digests.get(file) };
}
function envelope(suite, extra = {}) {
  const slot = matrix.slots.find(item => item.kind === "host" && item.suite === suite);
  assert.ok(slot, `Committed slot required: ${suite}`);
  const report = {
    schemaVersion: 1, suite, strict: true, status: "passed",
    startedAt: now, finishedAt: now, candidateSha,
    evidenceLevel: metadata.suiteEvidenceLevels[suite],
    requiredCapabilities: metadata.requiredCapabilities[suite],
    capabilities: Object.fromEntries(metadata.requiredCapabilities[suite].map(key => [key, { available: true }])),
    requiredScenarios: metadata.suites[suite], missingCapabilities: [], missingScenarios: [],
    scenarios: metadata.suites[suite].map(id => ({ id, status: "passed", startedAt: now, finishedAt: now, evidenceLevel: metadata.scenarioEvidenceLevels[suite][id] })),
    cleanup: { status: "passed" }, qualificationEnvironment: { ...slot.environment, measurement: "native" },
    fixtureSource: digest(slot.source), fixtureSources: (slot.requiredSources || []).map(digest),
    artifactQualification: "workflow-checkout-source", ...extra,
  };
  assert.deepEqual(verifyReport(report, undefined, { expectedSha: candidateSha }), []);
  return { slot, artifact: { kind: "host", suite, environment: slot.environment, report } };
}
function check(suite, extra) {
  const { slot, artifact } = envelope(suite, extra);
  return verifyMatrix([artifact], { candidateSha, specification: { schemaVersion: 1, slots: [slot] } });
}
const ids = [
  ...require("./_registration/adcs-coverage.json").suites.map(item => item.id).filter(id => id !== "adcs-browser-enrollment"),
  ...require("./_registration/cross-coverage.json").suites.map(item => item.id),
  ...require("./_registration/windows-coverage.json").contracts.map(item => item.suiteId),
];
for (const suite of ids) test(`passed envelope cannot qualify local contract ${suite}`, () => {
  assert.match(check(suite).join("\n"), /Local-contract-only suite has no native qualifying producer/);
});
test("valid browser, DNS and Windows local proofs remain nonqualifying", () => {
  const browser = require("../tests/e2e/helpers/certops-adcs-browser-enrollment");
  const dns = require("../tests/e2e/helpers/certops-dns-interruption");
  const dump = require("../tests/e2e/helpers/certops-windows-crash-dump");
  const dumpProof = { scope: dump.SCOPE, evidenceLevel: dump.EVIDENCE_LEVEL, runId: "a".repeat(32), crashDumpContainmentQualified: false, ...Object.fromEntries(dump.CLOSED.map(key => [key, false])) };
  dump.verifyProof(dumpProof);
  for (const [suite, extra] of [
    ["adcs-browser-enrollment", { nativeAdcsBrowserEnrollment: browser.acceptJourney(browser.JOURNEY.map(step => ({ step }))) }],
    ["dns-interruption", { nativeDnsInterruption: dns.localProof() }],
    ["windows-crash-dump-containment-contract", { crashDumpContainment: dumpProof }],
  ]) assert.ok(check(suite, extra).length);
});
test("native eligible suite with complete generic evidence still passes", () => {
  assert.deepEqual(check("job-decisions-api"), []);
});
test("pending or relabeled installed proofs cannot bypass producer eligibility", () => {
  for (const suite of ids.slice(-2)) {
    for (const extra of [
      { nativeExecutionQualified: false, nativeCell: "pending" },
      { nativeExecutionQualified: true, nativeCell: "qualified" },
    ]) assert.ok(check(suite, extra).length);
  }
});
test("canonical-root native slot rejects a transplanted valid local proof", () => {
  const helper = require("../tests/e2e/helpers/certops-windows-fixed-root");
  const runId = "ab".repeat(16);
  const manifest = helper.createRunManifest({ runId, root: `C:\\qualification\\tt-root-${runId}` });
  const { proof } = helper.preserveExistingFixedRoot(manifest, { exists: true, root: helper.FIXED_INSTALL_ROOT, fileId: "42" });
  helper.verifyLocalContract(proof);
  assert.match(check("windows-canonical-root-lifecycle", { nativeCanonicalRoot: proof }).join("\n"), /Native canonical-root lifecycle proof required/);
});
test("second-rename native slot rejects a transplanted valid local proof", () => {
  const helper = require("../tests/e2e/helpers/certops-windows-second-rename");
  const runId = "cd".repeat(16);
  const manifest = helper.createRunManifest({ runId, root: `C:\\qualification\\tt-ren-${runId}` });
  const { proof } = helper.applySecondRenameFailure(manifest);
  helper.verifyLocalContract(proof);
  assert.match(check("windows-activation-second-rename", { nativeSecondRename: proof }).join("\n"), /Native second-rename activation proof required/);
});

test("issuer report labels without native proof cannot qualify", () => {
  for (const nativeCell of ["pending", "qualified"]) assert.ok(check("native-adcs-issuer-reassignment", {nativeCell}).length);
});
