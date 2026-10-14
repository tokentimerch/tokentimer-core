/**
 * Regression coverage: new or changed skip prerequisites require mapping regeneration.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { generate, check, environmentFor } = require("./certops-skip-qualification");
test("new or changed skip prerequisites require mapping regeneration", () => {
  const site = { file: "tests/fixture.test.js", line: 1, name: "fixture", kind: "dynamic", reason: "no-host" };
  const current = generate([site]);
  assert.deepEqual(check(current, generate([site])), []);
  assert.ok(check(current, generate([site, { ...site, name: "new fixture" }])).length);
  assert.ok(check(current, generate([{ ...site, reason: "unimplemented" }])).length);
  assert.equal(current.sites[0].executionStatus, "not-qualified");
});
test("platform and stack candidate cells remain distinct", () => {
  assert.equal(environmentFor({ file: "packages/agent/src/config/config.test.js", name: "POSIX permissions" }), "linux-filesystem");
  assert.equal(environmentFor({ file: "packages/agent/src/config/config.test.js", name: "ACL win32" }), "windows-elevated");
  assert.equal(environmentFor({ file: "tests/integration/certops.test.js", name: "query" }), "core-postgres-integration");
  assert.equal(environmentFor({ file: "fixture.test.js", name: "unknown dependency" }), "prerequisite-review");
});
test("committed ownership mapping matches actual scanner sites", () => {
  assert.deepEqual(check(require("../docs/certops/skip-qualification.generated.json")), []);
});
