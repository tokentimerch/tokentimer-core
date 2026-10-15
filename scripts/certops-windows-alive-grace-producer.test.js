"use strict";
/** Actual producer parser exercised with synthetic public bounded facts only. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const producer = require("./certops-windows-alive-grace"),
  { fixture } = require("./test-support/windows-alive-grace.cjs");
test("alive/default-grace producer accepts only complete closed cleanup facts and existing unique causal sources", () => {
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

test("separate alive scope binds every shared cleanup and pin dependency after parent integration", () => {
  const matrix = require("../docs/certops/release-qualification-matrix.json");
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

test("alive default-grace timeout nests every finite layer without changing normal or stopped limits", () => {
  const vm = require("node:vm");
  const native = fs.readFileSync(
    path.join(__dirname, "../tests/e2e/certops-agent-e2e.test.js"),
    "utf8",
  );
  const expression = native.match(
    /it\("real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence", \{ timeout: ([^}]+) \}/,
  )[1];
  const evaluate = (env) =>
    vm.runInNewContext(expression, { process: { env } });
  assert.equal(
    evaluate({ CERTOPS_WINDOWS_ALIVE_GRACE_REQUIRED: "1" }),
    6000000,
  );
  assert.equal(evaluate({}), 1920000);
  assert.equal(
    evaluate({ CERTOPS_WINDOWS_STOP_OFFLINE_REQUIRED: "1" }),
    2400000,
  );
  const workflow = fs.readFileSync(
      path.join(
        __dirname,
        "../.github/workflows/certops-windows-alive-grace.yml",
      ),
      "utf8",
    ),
    producerSource = fs.readFileSync(
      path.join(__dirname, "certops-windows-alive-grace.js"),
      "utf8",
    );
  const outer = Number(producerSource.match(/timeout: (6120000)/)[1]) / 60000,
    receipt = Number(workflow.match(/UtcNow\.AddMinutes\((\d+)\)/)[1]),
    task = Number(
      workflow.match(/ExecutionTimeLimit \(New-TimeSpan -Minutes (\d+)\)/)[1],
    ),
    job = Number(workflow.match(/timeout-minutes: (\d+)/)[1]);
  assert.deepEqual([100, outer, receipt, task, job], [100, 102, 107, 108, 120]);
  assert.ok(
    100 > 75 && outer > 100 && receipt > outer && task > receipt && job > task,
  );
});

test("signed native grace evidence binds actual machine route, credential auth and evidence/schema persistence", () => {
  for (const file of [
    "apps/api/routes/certops-agent.js",
    "apps/api/middleware/agent-auth.js",
    "apps/api/services/certops/evidence.js",
    "apps/api/services/certops/protocolSchemaValidation.js",
    "packages/contracts/certops/agent-protocol.schema.json",
  ])
    assert.ok(producer.REQUIRED_SOURCES.includes(file), file);
});
