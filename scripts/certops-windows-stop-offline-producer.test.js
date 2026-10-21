"use strict";
/** Actual producer parser exercised with synthetic public bounded facts only. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const producer = require("./certops-windows-stop-offline"),
  { fixture } = require("./test-support/windows-stop-offline.cjs");
test("stopped/offline producer accepts only complete closed cleanup facts and existing unique causal sources", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-stop-producer-"));
  const file = path.join(root, "facts.json");
  try {
    const facts = fixture();
    fs.writeFileSync(file, JSON.stringify(facts));
    assert.deepEqual(producer.readFacts(file), facts);
    for (const patch of [
      { exactOwnedCleanupCompleted: false },
      { originalOperationAutomaticallyRecovered: true },
      { privateKey: "untrusted" },
      { defaultLeaseMs: 1 },
    ]) {
      fs.writeFileSync(file, JSON.stringify({ ...facts, ...patch }));
      assert.throws(() => producer.readFacts(file));
    }
    fs.writeFileSync(file, Buffer.alloc(16385));
    assert.throws(() => producer.readFacts(file));
    assert.equal(
      new Set(producer.REQUIRED_SOURCES).size,
      producer.REQUIRED_SOURCES.length,
    );
    assert.ok(producer.REQUIRED_SOURCES.length <= 256);
    for (const source of producer.REQUIRED_SOURCES) {
      assert.ok(!source.includes(".."));
      assert.ok(
        fs.statSync(path.resolve(__dirname, "..", source)).isFile(),
        source,
      );
    }
    assert.ok(
      producer.REQUIRED_SOURCES.includes(
        "packages/agent/windows-service-host/console_windows.go",
      ),
    );
    assert.ok(
      producer.REQUIRED_SOURCES.includes("apps/worker/src/certops-worker.js"),
    );
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

test("separate stopped scope binds every shared cleanup and pin dependency after parent integration", () => {
  const matrix = require("./certops-qualification-manifest");
  for (const file of [
    ...require("../tests/e2e/helpers/certops-windows-installed-verify-rollback")
      .REQUIRED_SOURCES,
    ...require("../tests/e2e/helpers/certops-windows-signing-pin-refusal")
      .REQUIRED_SOURCES,
  ])
    assert.ok(producer.REQUIRED_SOURCES.includes(file), file);
  for (const slot of matrix.slots.filter((s) => s.suite === producer.SUITE))
    assert.deepEqual(
      new Set(slot.requiredSources),
      new Set(producer.REQUIRED_SOURCES),
    );
});
