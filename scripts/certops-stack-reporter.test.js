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
    "tests/e2e/helpers/certops-windows-public-issuance.js",
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
