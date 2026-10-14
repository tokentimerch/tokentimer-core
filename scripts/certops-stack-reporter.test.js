/**
 * Regression coverage: Windows profile evidence binds actual recovery journey and output-privacy sources.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const test = require("node:test"),
  assert = require("node:assert/strict"),
  crypto = require("node:crypto"),
  fs = require("node:fs"),
  path = require("node:path");
const { supplementalSources } = require("./certops-stack-reporter");
test("Windows profile evidence binds public admission, recovery and output-privacy sources", () => {
  const sources = supplementalSources("real-agent-windows-acme-iis/rsa-2048");
  assert.equal(new Set(sources.map((item) => item.file)).size, sources.length);
  for (const item of sources)
    assert.equal(
      item.sha256,
      crypto
        .createHash("sha256")
        .update(fs.readFileSync(path.resolve(__dirname, "..", item.file)))
        .digest("hex"),
    );
  for (const file of [
    "scripts/certops-installer-pe.test.ps1",
    ...require("../tests/e2e/helpers/certops-windows-key-reuse-refusal")
      .requiredSources,
    ...require("../tests/e2e/helpers/certops-windows-installed-iis-refusal")
      .REQUIRED_SOURCES,
    "tests/e2e/helpers/certops-windows-public-issuance.js",
    "tests/e2e/helpers/certops-windows-installed-handoff.js",
    "tests/e2e/helpers/certops-windows-registration-job.ps1",
    ".github/workflows/certops-windows-e2e.yml",
    "tests/e2e/helpers/certops-api-fixture.js",
    "tests/e2e/helpers/certops-windows-reregistration.js",
    "tests/e2e/helpers/certops-windows-capability-refresh.js",
    "tests/e2e/helpers/certops-windows-output-child.js",
    "tests/e2e/helpers/certops-windows-output-privacy.js",
    "tests/e2e/windows-real-journey.js",
  ])
    assert.ok(
      sources.some((item) => item.file === file),
      `Required Windows admission/recovery source missing: ${file}`,
    );
});
test("unrelated and environment-supplied scope paths cannot select arbitrary source", () => {
  assert.equal(supplementalSources("agent-protocol-api-worker"), undefined);
  assert.equal(supplementalSources("../../secret"), undefined);
});
test("Every committed Linux ACME scope binds current actual journey and Pebble producer", () => {
  for (const scope of [
    "real-agent-acme-filesystem",
    "real-agent-acme-eab-filesystem",
    "real-agent-acmesh-filesystem",
    "real-agent-acmesh-eab-filesystem",
    "real-agent-alpine-certbot",
    "real-agent-alpine-acmesh",
  ]) {
    const sources = supplementalSources(scope);
    assert.deepEqual(
      sources.map((item) => item.file),
      [
        "tests/e2e/acme-real-journey.js",
        "scripts/certops-real-acme.js",
        "tests/e2e/helpers/certops-acme-lease-loss.js",
        "tests/e2e/helpers/certops-acme-command-barrier.js",
        "scripts/certops-stack-reporter.js",
        "tests/e2e/helpers/certops-acme-key-reuse.js",
        "packages/agent/src/index.js",
        "packages/agent/src/keys/index.js",
        "packages/agent/src/acme/index.js",
        "packages/agent/src/signing/index.js",
        "apps/api/services/certops/renewalProfileAdmin.js",
        "apps/api/services/certops/renewalProfile.js",
        "apps/api/services/certops/renewalScheduler.js",
        "apps/api/services/certops/agentDispatch.js",
      ],
    );
    for (const item of sources)
      assert.equal(
        item.sha256,
        crypto
          .createHash("sha256")
          .update(fs.readFileSync(path.resolve(__dirname, "..", item.file)))
          .digest("hex"),
      );
  }
  assert.equal(
    supplementalSources("real-agent-acme-filesystem/../../secret"),
    undefined,
  );
});

test("installed IIS sidecar reporter validates real public file lookup for every key profile", () => {
  const h = require("../tests/e2e/helpers/certops-windows-installed-iis-refusal"),
    { installedIisRefusalProof } = require("./certops-stack-reporter"),
    base = path.resolve(__dirname, "../.build");
  fs.mkdirSync(base, { recursive: true });
  const root = fs.mkdtempSync(path.join(base, "iis-refusal-reporter-"));
  assert.ok(
    path.relative(base, root) && !path.relative(base, root).startsWith(".."),
  );
  fs.mkdirSync(path.join(root, "qualification-results"));
  const proof = {
      scope: h.SCOPE,
      jobId: "11111111-1111-1111-1111-111111111111",
      claimId: "22222222-2222-2222-2222-222222222222",
      ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
    },
    name =
      "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence";
  try {
    for (const profile of [
      "rsa-2048",
      "rsa-3072",
      "rsa-4096",
      "ec-p256",
      "ec-p384",
    ]) {
      const scope = `real-agent-windows-acme-iis/${profile}`,
        file = path.join(
          root,
          "qualification-results",
          `windows-installed-iis-refusal-${profile}.json`,
        );
      assert.throws(() => installedIisRefusalProof(scope, name, root));
      fs.writeFileSync(file, JSON.stringify(proof), { flag: "wx" });
      assert.deepEqual(installedIisRefusalProof(scope, name, root), proof);
      for (const change of [
        { claimBoundFailureAudit: false },
        { scope: "direct-executor" },
        { privateCngReceipt: "must-not-qualify" },
      ]) {
        fs.writeFileSync(file, JSON.stringify({ ...proof, ...change }));
        assert.throws(() => installedIisRefusalProof(scope, name, root));
      }
      fs.unlinkSync(file);
    }
    assert.equal(
      installedIisRefusalProof("real-agent-acme-filesystem", name, root),
      undefined,
    );
    assert.throws(() =>
      installedIisRefusalProof(
        "real-agent-windows-acme-iis/unknown",
        name,
        root,
      ),
    );
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
