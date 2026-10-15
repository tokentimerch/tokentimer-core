"use strict";
/** Supporting checks of the actual normal Windows producer and nested limits.
 * No agent, CA, certificate, scheduled task or service is started here. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  vm = require("node:vm");
const root = path.resolve(__dirname, "..");
test("normal Windows real-renewal budget nests every layer and leaves the stopped/offline branch unchanged", async () => {
  const native = fs.readFileSync(
    path.join(root, "tests/e2e/certops-agent-e2e.test.js"),
    "utf8",
  );
  const expression = native.match(
    /it\("real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence", \{ timeout: ([^}]+) \}/,
  )[1];
  const evaluate = (value) =>
    vm.runInNewContext(expression, {
      process: { env: { CERTOPS_WINDOWS_STOP_OFFLINE_REQUIRED: value } },
    });
  assert.equal(evaluate("0"), 32 * 60000);
  assert.equal(evaluate("1"), 40 * 60000);
  const source = fs.readFileSync(
      path.join(root, "scripts/certops-windows-e2e.js"),
      "utf8",
    ),
    sentinel = new Error("captured actual spawn only");
  let options;
  const module = { exports: {} };
  vm.runInNewContext(source, {
    module,
    exports: module.exports,
    process: { platform: "win32", execPath: "node", env: {} },
    require(name) {
      if (name === "node:assert/strict") return assert;
      if (name === "node:fs") return { mkdirSync() {} };
      if (name === "node:child_process")
        return {
          spawnSync(_exe, _args, value) {
            options = value;
            throw sentinel;
          },
        };
      if (name === "./certops-real-acme")
        return { withPebble: (fn) => fn({}) };
      if (name === "./certops-stack-report") return { verify() {} };
      if (name.endsWith("agent-protocol-required-tests.json"))
        return { requiredTests: [] };
      throw Error("Unexpected dependency " + name);
    },
    console,
  });
  await assert.rejects(module.exports.main(), (error) => error === sentinel);
  assert.equal(options.timeout, 34 * 60000);
  const workflow = fs.readFileSync(
    path.join(root, ".github/workflows/certops-windows-e2e.yml"),
    "utf8",
  );
  const receipt = Number(workflow.match(/UtcNow\.AddMinutes\((\d+)\)/)[1]),
    task = Number(
      workflow.match(/ExecutionTimeLimit \(New-TimeSpan -Minutes (\d+)\)/)[1],
    ),
    job = Number(workflow.match(/timeout-minutes: (\d+)/)[1]);
  assert.deepEqual(
    [evaluate("0") / 60000, options.timeout / 60000, receipt, task, job],
    [32, 34, 37, 38, 51],
  );
  assert.ok(
    receipt - options.timeout / 60000 >= 3 &&
      task - receipt >= 1 &&
      job - task >= 13,
  );
  // Exactly two additional 180-second waits, rather than an unbounded multiplier.
  assert.equal(evaluate("0") - 26 * 60000, 2 * 180000);
});
