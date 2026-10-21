"use strict";
/**
 * Qualification notes: native success with deferred result delivery
 *
 * Reuse member/CA/no new VM/preflight. Owned loopback gateway validates original API HTTPS,
 * forwards original bytes, holds claims until selected job registered, evidence through/selected
 * result HTTP 503. Fresh leaf/key/claim evidence/My/IIS/HTTP.sys/trusted TLS precede durable
 * successful outbox. Observe actual attempt/nextRetryAt, no edits. Retain exact
 * host/Node/descendant native handles before ordinary SCM stop, natural zero exits/drain; config
 * identity/hash/DACL/credential/pins unchanged. Restart real retry at persisted deadline -> same
 * claim/attempt/one consumed nonce, same journal/CSR/key/leaf/independent RequestId/CA count
 * (compare reported IDs if present). Second ordinary stop restores config bytes via original
 * retained handle; authenticate original API/CNG/TLS before closing gateway/guards. Unknown
 * native/config/result/drain preserves whole fixture. Closed projection excludes raw
 * outbox/paths/container/secrets. No future-descendant atomic ownership, background timer, every
 * retry duration, reboot or power-loss claim.
 *
 * Shared setup, evidence and cleanup policy: docs/certops/e2e-qualification.md.
 */
const test = require("node:test"),
  assert = require("node:assert/strict");
const subject = require("../tests/e2e/helpers/certops-adcs-result-outbox");
const fs = require("node:fs"),
  path = require("node:path");
const uuid = (n) => `10000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
function proof() {
  return {
    scope: subject.SCOPE,
    enrollmentId: uuid(1),
    jobId: uuid(2),
    claimId: uuid(3),
    requestId: 42,
    fingerprints: ["1".repeat(64), "2".repeat(64)],
    caRequestCounts: [10, 11, 11],
    recordedAttempts: 1,
    retryDelayMs: 15000,
    atomicTreeContainmentQualified: false,
    backgroundTimerQualified: false,
    ...Object.fromEntries(subject.FLAGS.map((flag) => [flag, true])),
  };
}
test("AD CS result restart proof refuses missing facts, extra CA requests and unsupported promotions", () => {
  assert.equal(subject.verifyProof(proof()), true);
  for (const key of Object.keys(proof())) {
    const value = proof();
    delete value[key];
    assert.throws(() => subject.verifyProof(value));
  }
  for (const patch of [
    { caRequestCounts: [10, 11, 12] },
    { retryDelayMs: 100 },
    { recordedAttempts: 0 },
    { requestId: null },
    { backgroundTimerQualified: true },
    { atomicTreeContainmentQualified: true },
    { privateCredential: "sentinel" },
  ])
    assert.throws(() => subject.verifyProof({ ...proof(), ...patch }));
  for (const flag of subject.FLAGS)
    for (const wrong of [false, 1])
      assert.throws(() => subject.verifyProof({ ...proof(), [flag]: wrong }));
});
test("recorded durable retry uses actual production attempt exponent and no fixture due-time rewrite", () => {
  const entry = {
    id: "outbox-" + "a".repeat(24),
    result: { jobId: uuid(2), claimId: uuid(3), status: "succeeded" },
    evidence: [],
    attempts: 1,
    lastAttemptAt: "2026-10-15T10:00:00.000Z",
    nextRetryAt: "2026-10-15T10:00:15.000Z",
  };
  assert.equal(
    subject.verifyPersisted(entry, uuid(2), uuid(3)),
    Date.parse(entry.nextRetryAt),
  );
  for (const patch of [
    { attempts: 2 },
    { nextRetryAt: entry.lastAttemptAt },
    { attempts: 0 },
    { result: { ...entry.result, status: "failed" } },
    { result: { ...entry.result, claimId: uuid(4) } },
  ])
    assert.throws(() =>
      subject.verifyPersisted({ ...entry, ...patch }, uuid(2), uuid(3)),
    );
});
module.exports = { proof };
test("native admission and broad parent cleanup are fenced by the same sticky owner", () => {
  const root = path.resolve(__dirname, "..");
  const parent = fs.readFileSync(
    path.join(root, "tests/e2e/certops-adcs-real-e2e.test.js"),
    "utf8",
  );
  assert.ok(parent.includes("qualifyResultOutbox({gate,fixture,api,"));
  assert.ok(
    parent.includes(
      "resultOutboxJourney.SCENARIO,...webHostingJourney.REQUIRED_SCENARIOS",
    ),
  );
  const final = parent.slice(
    parent.indexOf('await gate.scenario("adcs-real-owned-cleanup"'),
  );
  assert.ok(
    final.indexOf("resultOutboxJourney.assertCleanupSafe(workDir)") >= 0,
  );
  assert.ok(
    final.indexOf("resultOutboxJourney.assertCleanupSafe(workDir)") <
      final.indexOf("if (serviceOwned)"),
  );
  const store = require("../tests/e2e/helpers/certops-adcs-webhosting-renewal");
  assert.throws(
    () =>
      store.backgroundCleanupPlan(
        { resultOutboxPendingVerification: true },
        [],
        () => null,
      ),
    /signed result restart/,
  );
  assert.equal(
    new Set(subject.REQUIRED_SOURCES).size,
    subject.REQUIRED_SOURCES.length,
  );
  for (const source of subject.REQUIRED_SOURCES)
    assert.ok(fs.statSync(path.join(root, source)).isFile());
});
