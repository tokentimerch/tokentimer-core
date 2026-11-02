"use strict";
/** Offline public/native proof and owned public-file controls only. No API,
 * service, certificate, CNG or host process operation executes in these tests. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const h = require("../tests/e2e/helpers/certops-windows-public-retirement");
const proof = () => ({
  scope: h.SCOPE,
  inFlightRetirementQualified: false,
  anonymousStatus: 401,
  viewerStatus: 403,
  managerStatus: 200,
  replayStatus: 200,
  retirementAuditCount: 1,
  noRespawnObservedMs: 5010,
  ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
});
test("public retirement proof cannot substitute service-only or force-retired active work", () => {
  h.verifyProof(proof());
  for (const key of Object.keys(proof())) {
    const bad = proof();
    delete bad[key];
    assert.throws(() => h.verifyProof(bad));
  }
  for (const flag of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...proof(), [flag]: false }));
  for (const patch of [
    { inFlightRetirementQualified: true },
    { retirementAuditCount: 2 },
    { managerStatus: 409 },
    { scope: "service-only-retirement" },
    { rawCredential: "private" },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...patch }));
  for (const value of [4999, 30001, 5000.5, NaN, "5000"])
    assert.throws(() =>
      h.verifyProof({ ...proof(), noRespawnObservedMs: value }),
    );
});
test("actual HTTP admission classification and fresh native retirement86 message remain distinct", () => {
  h.verifyPublicResult({ status: 401 }, 401);
  h.verifyPublicResult(
    { status: 403, body: { code: "INSUFFICIENT_ROLE" } },
    403,
  );
  h.verifyPublicResult({ status: 200 }, 200);
  assert.throws(() =>
    h.verifyPublicResult({ status: 403, body: { code: "CSRF_INVALID" } }, 403),
  );
  assert.throws(() => h.verifyPublicResult({ status: 409 }, 200));
  assert.equal(
    h.retirementObserved(
      "child exited with the retirement code (86); stopping service cleanly",
    ),
    true,
  );
  for (const value of [
    "child exited (1)",
    "retirement code (0)",
    "",
    "agent status retired",
  ])
    assert.equal(h.retirementObserved(value), false);
});
test("unresolved public retirement guard prevents borrowed native state cleanup", () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-public-retirement-"),
  );
  try {
    const guard = path.join(root, h.GUARD);
    fs.writeFileSync(guard, "owned", { flag: "wx" });
    assert.throws(() => h.assertCleanupSafe(root));
    assert.equal(fs.readFileSync(guard, "utf8"), "owned");
    fs.unlinkSync(guard);
    h.assertCleanupSafe(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("retirement guard is registered before any native ownership observation", () => {
  const source = fs.readFileSync(
    path.join(
      __dirname,
      "../tests/e2e/helpers/certops-windows-public-retirement.js",
    ),
    "utf8",
  );
  const guard = source.indexOf("active.add(owner(receipt.root))"),
    observe = source.indexOf(
      "const runtime = JSON.parse(ps(installed.observationScript()))",
    );
  assert.ok(guard > 0 && observe > guard);
});

test("expired leases or pending work cannot masquerade as an idle retirement fixture", () => {
  h.verifyIdleJobs([
    { status: "succeeded" },
    { status: "orphaned_unknown_effect" },
  ]);
  for (const status of [
    "running",
    "claimed",
    "pending",
    "pending_approval",
    "approved",
    "blocked",
    "unknown",
  ])
    assert.throws(() =>
      h.verifyIdleJobs([
        { status, lease_expires_at: "2000-01-01T00:00:00.000Z" },
      ]),
    );
});
const testReporter = require("./certops-stack-reporter");
test("actual bounded reporter requires retirement sidecar for every Windows profile", () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "public-retirement-report-"),
  );
  fs.mkdirSync(path.join(root, "qualification-results"));
  const main =
    "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
  try {
    for (const profile of [
      "rsa-2048",
      "rsa-3072",
      "rsa-4096",
      "ec-p256",
      "ec-p384",
    ]) {
      const scope = "real-agent-windows-acme-iis/" + profile,
        file = path.join(
          root,
          "qualification-results",
          `windows-public-retirement-${profile}.json`,
        );
      assert.throws(() =>
        testReporter.publicRetirementProof(scope, main, root),
      );
      fs.writeFileSync(file, JSON.stringify(proof()));
      assert.deepEqual(
        testReporter.publicRetirementProof(scope, main, root),
        proof(),
      );
      fs.writeFileSync(
        file,
        JSON.stringify({
          ...proof(),
          authorizedManagerPublicRetirement: false,
        }),
      );
      assert.throws(() =>
        testReporter.publicRetirementProof(scope, main, root),
      );
      fs.writeFileSync(
        file,
        JSON.stringify({ ...proof(), privateNativePath: "secret" }),
      );
      assert.throws(() =>
        testReporter.publicRetirementProof(scope, main, root),
      );
    }
    assert.equal(
      testReporter.publicRetirementProof(
        "real-agent-acme-filesystem",
        main,
        root,
      ),
      undefined,
    );
    const parent = fs.readFileSync(
      path.join(__dirname, "../tests/e2e/windows-real-journey.js"),
      "utf8",
    );
    assert.ok(
      parent.indexOf("publicRetirement.assertCleanupSafe(workDir)") <
        parent.indexOf("configEncoding.assertCleanupSafe(workDir)"),
    );
    assert.ok(!parent.includes(".retireAgent({"));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
