/**
 * Regression coverage: new or changed skip prerequisites require mapping regeneration.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {
  generate,
  check,
  environmentFor,
} = require("./certops-skip-qualification");
test("new or changed skip prerequisites require mapping regeneration", () => {
  const site = {
    file: "tests/fixture.test.js",
    line: 1,
    name: "fixture",
    kind: "dynamic",
    reason: "no-host",
  };
  const current = generate([site]);
  assert.deepEqual(check(current, generate([site])), []);
  assert.ok(
    check(current, generate([site, { ...site, name: "new fixture" }])).length,
  );
  assert.ok(
    check(current, generate([{ ...site, reason: "unimplemented" }])).length,
  );
  assert.equal(current.sites[0].executionStatus, "not-qualified");
});
test("platform and stack candidate cells remain distinct", () => {
  assert.equal(
    environmentFor({
      file: "packages/agent/src/config/config.test.js",
      name: "POSIX permissions",
    }),
    "linux-filesystem",
  );
  assert.equal(
    environmentFor({
      file: "packages/agent/src/config/config.test.js",
      name: "ACL win32",
    }),
    "windows-elevated",
  );
  assert.equal(
    environmentFor({
      file: "tests/integration/certops.test.js",
      name: "query",
    }),
    "core-postgres-integration",
  );
  assert.equal(
    environmentFor({ file: "fixture.test.js", name: "unknown dependency" }),
    "prerequisite-review",
  );
});

test("shared scheduler mutations route only to the exclusive manual stack", () => {
  const files = [
    "certops-scheduler-capacity-e2e.test.js",
    "certops-renewal-toggle-e2e.test.js",
  ];
  const runnerFiles = require("./certops-api-qualification").suites.map(
    ([, file]) => file,
  );
  const result = generate(
    files.map((file) => ({
      file: `tests/e2e/${file}`,
      line: 1,
      name: "exclusive scheduler fixture",
      kind: "dynamic",
      reason: "no-host",
    })),
  );
  for (const site of result.sites) {
    assert.equal(site.environment, "core-exclusive-scheduler-api");
    assert.equal(
      site.workflow,
      ".github/workflows/certops-scheduler-capacity-qualification.yml",
    );
    assert.equal(site.workflowStatus, "file-selected-not-qualified");
    assert.equal(site.executionStatus, "not-qualified");
    assert.ok(!runnerFiles.includes(site.file.split("/").at(-1)));
    assert.ok(
      result.environments[site.environment].capabilities.includes(
        "exclusive-scheduler-stack",
      ),
    );
  }
});
test("committed ownership mapping matches actual scanner sites", () => {
  assert.deepEqual(
    check(require("../docs/certops/skip-qualification.generated.json")),
    [],
  );
});

test("every registered API suite has explicit skip ownership without qualifying execution", () => {
  const sites = require("./certops-api-qualification").suites.map(
    ([, file]) => ({
      file: `tests/e2e/${file}`,
      line: 1,
      name: "inventory fixture",
      kind: "dynamic",
      reason: "no-host",
    }),
  );
  for (const site of generate(sites).sites) {
    assert.equal(site.environment, "core-certificate-api");
    assert.equal(site.executionStatus, "not-qualified");
    assert.equal(site.workflowStatus, "file-selected-not-qualified");
  }
  assert.equal(
    environmentFor({
      file: "tests/e2e/unregistered-fixture.test.js",
      name: "unknown fixture",
      reason: "no-host",
    }),
    "prerequisite-review",
  );
  assert.equal(
    environmentFor({ ...sites[0], reason: "unimplemented" }),
    "unsupported-feature",
  );
});

test("literal installer filesystem prerequisite routes to actual Windows supporting step", () => {
  const site = {
    file: "packages/agent/scripts/host/windows-installed-paths-filesystem.test.js",
    line: 1,
    name: "actual installer filesystem branches preserve literal brackets and wildcard siblings",
    kind: "dynamic",
    reason: "no-host",
  };
  const result = generate([site]).sites[0];
  assert.equal(result.environment, "windows-powershell-filesystem");
  assert.equal(result.workflow, ".github/workflows/certops-windows-e2e.yml");
  assert.equal(result.workflowStatus, "file-selected-not-qualified");
  assert.equal(result.executionStatus, "not-qualified");
});

test("native benign containment prerequisite routes to its actual Windows regression step", () => {
  const site = {
    file: "packages/agent/scripts/host/windows-contained-process.test.js",
    line: 1,
    name: "real owned JobObject preserves suspended identity and drains an actual descendant",
    kind: "dynamic",
    reason: "no-host",
  };
  const result = generate([site]).sites[0];
  assert.equal(result.environment, "windows-native-process-containment");
  assert.equal(result.workflow, ".github/workflows/certops-windows-e2e.yml");
  assert.equal(result.workflowStatus, "file-selected-not-qualified");
  assert.equal(result.executionStatus, "not-qualified");
});
