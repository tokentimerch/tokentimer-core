"use strict";
/** Closed synthetic proof controls. No installed agent, key, store or network
 * action executes; actual native qualification requires the manual host lane. */
const test = require("node:test");
const assert = require("node:assert/strict");
const proof = require("../tests/e2e/helpers/certops-windows-installed-failed-rollback");
const {
  fixture,
} = require("./fixtures/certops-windows-installed-failed-rollback.cjs");
test("installed failed rollback cannot be relabelled successful restoration or automatic recovery", () => {
  assert.equal(proof.verifyProof(fixture()), true);
  for (const key of Object.keys(fixture())) {
    const bad = fixture();
    delete bad[key];
    assert.throws(() => proof.verifyProof(bad), key);
  }
  for (const flag of proof.FLAGS)
    assert.throws(
      () => proof.verifyProof({ ...fixture(), [flag]: false }),
      flag,
    );
  for (const patch of [
    { scope: "native-direct-executor" },
    { rolledBack: true },
    { rollbackFailureQualified: false },
    { originalOperationAutomaticallyRecovered: true },
    { bindFailureQualified: true },
    { transientNewBindingObservationQualified: true },
    { appIdPreservationQualified: true },
    { retryJobStatus: "failed" },
    { unknown: true },
  ])
    assert.throws(() => proof.verifyProof({ ...fixture(), ...patch }));
  for (const field of [
    "jobIds",
    "claimIds",
    "fingerprints",
    "spkiFingerprints",
  ]) {
    const bad = fixture();
    bad[field][1] = bad[field][0];
    assert.throws(() => proof.verifyProof(bad));
  }
});

test("actual producer uses the separate finite native scope and waits for fixture teardown before report completion", async () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    vm = require("node:vm"),
    { createRequire } = require("node:module");
  const file = path.resolve(__dirname, "certops-windows-failed-rollback.js"),
    actualRequire = createRequire(file),
    module = { exports: {} };
  const calls = [];
  const context = {
    module,
    exports: module.exports,
    __filename: file,
    __dirname: path.dirname(file),
    Buffer,
    console,
    process: {
      platform: "win32",
      arch: "x64",
      execPath: process.execPath,
      env: {
        CERTOPS_WINDOWS_FAILED_ROLLBACK_REQUIRED: "1",
        CERTOPS_WINDOWS_KEY_PROFILE: "rsa-2048",
      },
    },
    require(name) {
      if (name === "./certops-windows-installed-producer") {
        const nested = { exports: {} };
        vm.runInNewContext(
          fs.readFileSync(
            path.join(__dirname, "certops-windows-installed-producer.js"),
            "utf8",
          ),
          { ...context, module: nested, exports: nested.exports },
        );
        return nested.exports;
      }
      if (name === "node:fs")
        return {
          ...fs,
          mkdirSync() {},
          existsSync() {
            return false;
          },
        };
      if (name === "node:child_process")
        return {
          spawnSync(_exe, _args, options) {
            calls.push({
              timeout: options.timeout,
              scope: options.env.CERTOPS_REPORT_SCOPE,
            });
            return { status: 0 };
          },
        };
      if (
        name ===
        "../tests/e2e/helpers/certops-windows-installed-verify-rollback"
      )
        return {
          readOwned() {
            return { bytes: Buffer.from(JSON.stringify(fixture())) };
          },
        };
      if (name === "../packages/agent/scripts/host-gate")
        return {
          createHostGate() {
            return {
              report: {
                qualificationEnvironment: { osVersion: "2022" },
                capabilities: {},
              },
              async preflight() {
                await Promise.resolve();
                return true;
              },
              async scenario(_id, run) {
                await run();
              },
              async finish() {
                await Promise.resolve();
                calls.push("finish");
              },
            };
          },
        };
      if (name === "./certops-real-acme")
        return {
          async withPebble(run) {
            await run({});
            calls.push("pebble-closed");
          },
        };
      return actualRequire(name);
    },
  };
  vm.runInNewContext(fs.readFileSync(file, "utf8"), context, {
    filename: file,
  });
  await module.exports.main();
  assert.deepEqual(calls, [
    { timeout: 1320000, scope: "real-agent-windows-failed-rollback/rsa-2048" },
    "pebble-closed",
    "finish",
  ]);
  const workflow = fs.readFileSync(
    path.resolve(
      __dirname,
      "../.github/workflows/certops-windows-failed-rollback.yml",
    ),
    "utf8",
  );
  assert.match(workflow, /timeout-minutes: 40/);
  assert.match(workflow, /UtcNow.AddMinutes\(27\)/);
  assert.match(workflow, /New-TimeSpan -Minutes 28/);
  assert.ok(
    fs
      .readFileSync(
        path.resolve(__dirname, "../tests/e2e/certops-agent-e2e.test.js"),
        "utf8",
      )
      .includes('CERTOPS_WINDOWS_FAILED_ROLLBACK_REQUIRED === "1" ? 1200000'),
  );
});
