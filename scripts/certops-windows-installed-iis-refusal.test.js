"use strict";
/** Offline ownership/proof controls; never invokes native services or IIS. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  h = require("../tests/e2e/helpers/certops-windows-installed-iis-refusal");
const value = () => ({
  scope: h.SCOPE,
  jobId: "11111111-1111-1111-1111-111111111111",
  claimId: "22222222-2222-2222-2222-222222222222",
  ...Object.fromEntries(h.FLAGS.map((f) => [f, true])),
});
test("installed refusal proof requires actual public signed failure and all independent effects", () => {
  assert.equal(h.verifyProof(value()), true);
  for (const key of Object.keys(value())) {
    const missing = value();
    delete missing[key];
    assert.throws(() => h.verifyProof(missing));
  }
  for (const key of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...value(), [key]: false }));
  assert.throws(() =>
    h.verifyProof({ ...value(), privateCngContainer: "private" }),
  );
  assert.throws(() =>
    h.verifyProof({ ...value(), scope: "direct-executor-only" }),
  );
});
test("unresolved shadow ownership blocks outer native cleanup and cannot adopt foreign site metadata", () => {
  const receipt = { cleanupCompleted: false };
  assert.throws(() => h.assertCleanupSafe([receipt]));
  receipt.cleanupCompleted = true;
  assert.equal(h.assertCleanupSafe([receipt]), true);
  assert.throws(() =>
    h.assertCleanupSafe([
      { cleanupCompleted: true },
      { cleanupCompleted: false },
    ]),
  );
  const expected = {
      site: "owned",
      path: "C:\\owned",
      port: 8443,
      domain: "owned.example.test",
      thumbprint: "A".repeat(40),
    },
    observed = {
      site: expected.site,
      path: expected.path,
      coordinates: "*:8443:owned.example.test",
      flags: 1,
      store: "My",
      httpStore: "MY",
      thumbprint: expected.thumbprint,
    };
  assert.equal(h.assertOwnedShadow(observed, expected), true);
  for (const key of Object.keys(observed))
    assert.throws(
      () => h.assertOwnedShadow({ ...observed, [key]: "foreign" }, expected),
      key,
    );
});
test("unqualified entry refuses before observing native state or submitting public work", async () => {
  const before = process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
  process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = "0";
  try {
    await assert.rejects(() => h.qualify({}));
  } finally {
    if (before === undefined)
      delete process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST;
    else process.env.CERTOPS_WINDOWS_DISPOSABLE_HOST = before;
  }
});

test("parent checks unresolved shadow guard before native and public recovery cleanup", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    source = fs
      .readFileSync(
        path.join(__dirname, "../tests/e2e/windows-real-journey.js"),
        "utf8",
      )
      .replace(/\r\n/g, "\n"),
    start = source.indexOf(
      'require("./helpers/certops-windows-installed-iis-refusal").assertCleanupSafe(ownedIisRefusalShadows)',
    );
  assert.ok(start > source.indexOf("} finally {"));
  for (const fragment of [
    "for(const resource of ownedHandoffs)",
    "if (serviceOwned) {\n      await cleanup",
    "if (siteOwned) await cleanup",
    "const receipts = path.join(configDir",
    "for (const jobId of ownedJobs)",
  ])
    assert.ok(source.indexOf(fragment, start) > start, fragment);
  const old = { acceptedThumbprint: "A".repeat(40), jobId: "original" },
    receipt = { cleanupCompleted: false, original: old };
  assert.throws(() => h.assertCleanupSafe([receipt]));
  assert.deepEqual(old, {
    acceptedThumbprint: "A".repeat(40),
    jobId: "original",
  });
});
