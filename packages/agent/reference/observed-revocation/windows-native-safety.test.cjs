"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { cleanupFixture } = require("./windows-native-safety.cjs");

test("native store entry points fail closed without disposable runner authorization", () => {
  for (const file of ["agent-scan-windows-native.cjs", "windows-native-orchestrator.cjs"]) {
    const env = { ...process.env, CERTOPS_REVOCATION_NATIVE_WINDOWS: "0" };
    const child = spawnSync(process.execPath, [path.join(__dirname, file)], { env, encoding: "utf8" });
    assert.notEqual(child.status, 0);
    assert.match(child.stderr, /disposable GitHub-hosted Windows runner/);
  }
});

test("fixture cleanup attempts all owned resources after errors", async () => {
  const calls = [];
  await assert.rejects(cleanupFixture({ created: true, close: async () => { calls.push("close"); throw Error("database"); }, remove: () => calls.push("remove"), cleanupDir: () => calls.push("directory") }), /database/);
  assert.deepEqual(calls, ["close", "remove", "directory"]);
  calls.length = 0;
  await assert.rejects(cleanupFixture({ created: true, close: async () => calls.push("close"), remove: () => { calls.push("remove"); throw Error("store"); }, cleanupDir: () => calls.push("directory") }), /store/);
  assert.deepEqual(calls, ["close", "remove", "directory"]);
  calls.length = 0;
  await cleanupFixture({ created: false, close: async () => calls.push("close"), remove: () => calls.push("remove"), cleanupDir: () => calls.push("directory") });
  assert.deepEqual(calls, ["close", "directory"]);
});
