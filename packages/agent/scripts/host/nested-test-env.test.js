"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { nestedTestEnv } = require("./nested-test-env");

if (process.env.CERTOPS_NESTED_TEST_FIXTURE === "1") {
  test("nested reporter sentinel", () => {});
} else {
  test("nested test runner emits real TAP while preserving strict qualification", () => {
    assert.ok(process.env.NODE_TEST_CONTEXT, "test must run within the Node test runner");
    const env = nestedTestEnv({ ...process.env, CERTOPS_NESTED_TEST_FIXTURE: "1", CERTOPS_QUALIFICATION_STRICT: "1" });
    assert.equal(env.CERTOPS_QUALIFICATION_STRICT, "1");
    assert.equal(env.NODE_TEST_CONTEXT, undefined);
    const child = spawnSync(process.execPath, ["--test", "--test-reporter=tap", "--test-name-pattern", "nested reporter sentinel", __filename], { env, encoding: "utf8", timeout: 30000 });
    assert.ifError(child.error);
    assert.equal(child.status, 0, child.stderr);
    assert.match(child.stdout, /^ok \d+ - nested reporter sentinel\s*$/m);
    assert.match(child.stdout, /^# pass 1\s*$/m);
    assert.match(child.stdout, /^# skipped 0\s*$/m);
  });
}
