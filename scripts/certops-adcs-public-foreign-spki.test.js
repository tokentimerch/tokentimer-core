"use strict";
/** Offline contracts and the actual pure candidate validator; no CA execution. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const h = require("../tests/e2e/helpers/certops-adcs-public-foreign-spki");
const uuid = (n) => `${String(n).padStart(8, "0")}-1111-1111-1111-111111111111`;
function proof() {
  return {
    scope: h.SCOPE,
    enrollmentId: uuid(1),
    failedJobId: uuid(2),
    foreignRequestId: "19",
    selectedRequestId: "17",
    foreignFingerprint: "a".repeat(64),
    selectedFingerprint: "b".repeat(64),
    foreignSpkiSha256: "c".repeat(64),
    originalSpkiSha256: "d".repeat(64),
    foreignCsrSha256: "e".repeat(64),
    reconcileSearchFrom: 16,
    foreignSubjectRequestCount: 1,
    originalSubjectRequestCount: 2,
    ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
  };
}
test("public foreign-SPKI proof requires every source oracle and distinct original recovery", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const field of Object.keys(proof())) {
    const value = proof();
    delete value[field];
    assert.throws(() => h.verifyProof(value));
  }
  for (const flag of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...proof(), [flag]: false }));
  for (const patch of [
    { foreignRequestId: "4294967296" },
    { selectedRequestId: "19" },
    { foreignSpkiSha256: "d".repeat(64) },
    { selectedFingerprint: "a".repeat(64) },
    { foreignSubjectRequestCount: 2 },
    { originalSubjectRequestCount: 3 },
    { reconcileSearchFrom: 20 },
    { privateExtra: "sentinel" },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...patch }));
});
test("actual production candidate validator accepts matching public SPKI and precisely refuses a different key", async () => {
  const {
      retrieveProposedEnrollmentCandidate,
    } = require("../packages/agent/src/issuers/adcs-enrollment-reconcile"),
    { assertIssuanceOutcome } = require("../packages/agent/src/issuers");
  const certificatePem = fs.readFileSync(
      path.resolve(
        __dirname,
        "../packages/agent/src/verify/fixtures/leaf.crt.pem",
      ),
      "utf8",
    ),
    leaf = new crypto.X509Certificate(certificatePem),
    digest = (key) =>
      crypto
        .createHash("sha256")
        .update(key.export({ type: "spki", format: "der" }))
        .digest("hex");
  // This issuer stub isolates the pure production SPKI gate. Native actor must
  // additionally prove real CA/CMS signatures, request ownership and SAN/template.
  const context = {
    issuer: { retrieve: () => Promise.resolve({ outcome: "issued", certificatePem }) },
    requestId: 17,
    reconcileSearchFrom: 16,
    assertIssuanceOutcome,
  };
  assert.equal(
    (
      await retrieveProposedEnrollmentCandidate({
        ...context,
        csrSpkiSha256: digest(leaf.publicKey),
      })
    ).status,
    "unique_candidate",
  );
  const foreign = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  }).publicKey;
  const result = await retrieveProposedEnrollmentCandidate({
    ...context,
    csrSpkiSha256: digest(foreign),
  });
  assert.equal(result.status, "error");
  assert.equal(
    result.error,
    "Proposed RequestId certificate SPKI does not match this enrollment",
  );
  assert.equal(result.certificatePem, undefined);
});
test("unresolved foreign request state cannot authorize parent native/public cleanup", () => {
  assert.equal(h.assertCleanupSafe([]), undefined);
  assert.throws(() => h.assertCleanupSafe([{ resolved: false }]));
  assert.throws(() => h.assertCleanupSafe([{}]));
  assert.throws(() => h.assertCleanupSafe(null));
});
test("source retains actual public signed path, key-before-submit removal and precise failure", () => {
  const source = fs.readFileSync(
      path.resolve(
        __dirname,
        "../tests/e2e/helpers/certops-adcs-public-foreign-spki.js",
      ),
      "utf8",
    ),
    compact = source.replace(/\s/g, "");
  assert.ok(
    compact.indexOf("ownedForeignRequests.push(owner)") <
      compact.indexOf("keys.generateKeyPairToFile("),
  );
  assert.ok(
    compact.indexOf("fs.unlinkSync(keyPath)") <
      compact.indexOf("awaitissuer.submit("),
  );
  assert.match(
    source,
    /Proposed RequestId certificate SPKI does not match this enrollment/,
  );
  assert.match(source, /ADCS_DISPOSITION_UNKNOWN/);
  assert.match(source, /scheduleDueEnrollments\(\s*\{\s*client: fixture.pool/);
  assert.doesNotMatch(
    source,
    /UPDATE\s|DELETE\s|INSERT\s|Set-Date|writeEnrollmentJournal|utimes|Stop-Process/,
  );
  assert.match(source, /sameIdentity\(guard, guardId\)/);
});
