"use strict";
/* Portable fail-closed checks for supporting native enrollment contention facts.
 * No lock, CNG, CA, IIS or SCM operations execute here; real child/native evidence
 * must come from the opted-in host fixture and current source fingerprints. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const {
  verifyContentionFacts,
} = require("../../packages/agent/scripts/host/enrollment-contention-fixture");
const facts = () => ({
  winnerGeneratedRealCsr: true,
  loserLockedBeforeNativeExecution: true,
  retryAcquiredEnrollmentLock: true,
  retryExistingContainerRefused: true,
  sameCsrAndSpki: true,
  sameNonExportableKey: true,
  winnerSignatureVerified: true,
  ownedChildrenStopped: true,
  ownedKeyRemoved: true,
  loserNativeCalls: 0,
  loserCertreqCalls: 0,
  retryCertreqCalls: 0,
  winnerCertreqCalls: 1,
  retryNativeCalls: 1,
});
test("enrollment contention proof cannot hide native loser work or retry keygen", () => {
  assert.equal(verifyContentionFacts(facts()), true);
  for (const change of [
    { loserNativeCalls: 1 },
    { loserCertreqCalls: 1 },
    { retryCertreqCalls: 1 },
    { winnerCertreqCalls: 0 },
    { winnerCertreqCalls: 2 },
    { retryNativeCalls: 0 },
    { retryNativeCalls: Infinity },
  ])
    assert.throws(() => verifyContentionFacts({ ...facts(), ...change }));
});
test("changed custody, missing signature or live children prevent successful proof", () => {
  for (const field of [
    "winnerGeneratedRealCsr",
    "loserLockedBeforeNativeExecution",
    "retryAcquiredEnrollmentLock",
    "retryExistingContainerRefused",
    "sameCsrAndSpki",
    "sameNonExportableKey",
    "winnerSignatureVerified",
    "ownedChildrenStopped",
    "ownedKeyRemoved",
  ])
    assert.throws(
      () => verifyContentionFacts({ ...facts(), [field]: false }),
      field,
    );
});

test("fixture persists returned public CSR after actual helper removed INF/REQ", async () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    os = require("node:os"),
    {
      generateCsrViaCng,
    } = require("../../packages/agent/src/windows-cert-store"),
    {
      persistPublicCsr,
    } = require("../../packages/agent/scripts/host/enrollment-lock-child");
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-contention-csr-"),
  );
  let nativeCalls = 0;
  try {
    const publicFixture =
      "-----BEGIN NEW CERTIFICATE REQUEST-----\nMAMCAQA=\n-----END NEW CERTIFICATE REQUEST-----\n";
    const result = await generateCsrViaCng({
      enrollmentId: "a421611e-b95a-4ae7-8fab-54b491482e0f",
      commonName: "fixture.invalid",
      altNames: ["fixture.invalid"],
      algorithm: "rsa-2048",
      workDir: directory,
      execFileImpl: (file, args, options, callback) => {
        nativeCalls++;
        if (/certreq/.test(file)) fs.writeFileSync(args.at(-1), publicFixture);
        queueMicrotask(() => callback(null, "", ""));
      },
    });
    assert.equal(result.ok, true);
    assert.equal(nativeCalls, 2);
    assert.equal(fs.existsSync(result.reqPath), false);
    assert.equal(fs.existsSync(result.infPath), false);
    assert.deepEqual(fs.readdirSync(directory), []);
    const copy = persistPublicCsr(result, directory);
    assert.equal(fs.readFileSync(copy, "utf8"), result.csrPem);
    assert.match(result.csrPem, /BEGIN CERTIFICATE REQUEST/);
    assert.throws(() => persistPublicCsr(result, directory));
    assert.equal(fs.existsSync(result.reqPath), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
