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
test("every conditional skip has an owning workflow and an available CI prerequisite", () => {
  const current = generate();
  assert.ok(current.sites.length > 0);
  for (const site of current.sites) {
    assert.ok(!["no-host", "no_host"].includes(site.reason), `${site.file}: obsolete missing-host classification`);
    assert.ok(site.workflow && site.workflowJob, `${site.file}: no executable owning job`);
    assert.equal(site.workflowStatus, "file-selected-not-qualified", site.file);
    assert.equal(site.executionStatus, "not-qualified");
    assert.ok(current.environments[site.environment].capabilities.length > 0, site.file);
  }
});
test("missing CI ownership and obsolete missing-host tags fail the inventory gates", () => {
  const { validateRouting } = require("./certops-skip-qualification");
  const current = generate();
  assert.deepEqual(validateRouting(current), []);
  current.sites[0].workflowJob = null;
  assert.ok(validateRouting(current).length);
  for (const reason of ["no-host", "no_host"]) {
    assert.ok(require("./generate-skip-inventory.cjs").validateReasons([{...current.sites[0], reason}]).length);
  }
});

test("distribution provider and native custody skips select their actual executable qualification jobs", () => {
  const cases = [
    ["tests/e2e/windows-material-real.test.js", "native IIS", "windows_material_qualification"],
    ["tests/e2e/windows-material-custody-real.test.js", "native custody", "windows_material_qualification"],
    ["packages/agent/src/windows-material/pkcs12.test.js", "native PKCS12", "windows_agent_quality"],
    ["tests/e2e/material-providers-real.test.js", "real KV v2: exact versions", "material_store_compatibility"],
    ["tests/e2e/material-providers-real.test.js", "real Azure Key Vault Secrets: publication", "lab"],
  ];
  for (const [file, name, job] of cases) {
    const result = generate([{file, name, line: 1, kind: "conditional", reason: "prerequisite"}]);
    const site = result.sites[0];
    assert.equal(site.workflowJob, job, file);
    assert.equal(site.workflowStatus, "file-selected-not-qualified");
    assert.equal(site.executionStatus, "not-qualified");
    assert.ok(result.environments[site.environment].capabilities.length > 0);
  }
});
test("ACME runtime wrapper skip routes to the Linux agent test job", () => {
  const result = generate([{
    file: "packages/agent/src/acme/acme.test.js",
    name: "acme.sh wrapper uses the explicit runtime and never falls back to PATH",
    line: 1, kind: "dynamic", reason: "prerequisite",
  }]);
  const site = result.sites[0];
  assert.equal(site.environment, "linux-filesystem");
  assert.equal(site.workflow, ".github/workflows/ci.yml");
  assert.equal(site.workflowJob, "backend_quality");
  assert.equal(site.workflowStatus, "file-selected-not-qualified");
  assert.equal(site.executionStatus, "not-qualified");
});
test("new or changed skip prerequisites require mapping regeneration", () => {
  const site = {
    file: "tests/fixture.test.js",
    line: 1,
    name: "fixture",
    kind: "dynamic",
    reason: "prerequisite",
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
      reason: "prerequisite",
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
    check(require("../.github/maintainers/certops/skip-qualification.generated.json")),
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
      reason: "prerequisite",
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
      reason: "prerequisite",
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
    reason: "prerequisite",
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
    reason: "prerequisite",
  };
  const result = generate([site]).sites[0];
  assert.equal(result.environment, "windows-native-process-containment");
  assert.equal(result.workflow, ".github/workflows/certops-windows-e2e.yml");
  assert.equal(result.workflowStatus, "file-selected-not-qualified");
  assert.equal(result.executionStatus, "not-qualified");
});
test("stored skip defaults preserve all facts and cannot conceal routing or qualification drift", () => {
  const {compact, expand} = require("./certops-skip-qualification");
  const current = generate(); const stored = compact(current);
  assert.deepEqual(expand(stored), current); assert.deepEqual(check(stored, current), []);
  assert.equal(current.sites[0].reason, "platform");
  for (const field of ["reason", "workflow", "workflowStatus", "executionStatus", "classificationStatus"]) {
    const changed = structuredClone(stored); changed.siteDefaults[field] = "changed";
    assert.ok(check(changed, current).length);
  }
  const missing = {sites: [{kind: "one"}, {}]}; assert.deepEqual(expand(compact(missing)), missing);
  for (const siteDefaults of [null, [], {id: "foreign"}]) assert.throws(() => expand({...stored, siteDefaults}));
});

test("MCP credential skips select real platform jobs without claiming execution", () => {
  const sites = generate().sites.filter(site => site.file.startsWith("packages/mcp/"));
  assert.ok(sites.length > 0);
  for (const site of sites) {
    const windows = /Windows/i.test(site.name);
    assert.equal(site.workflowJob, windows ? "windows_agent_quality" : "operator_interface");
    assert.equal(site.workflowStatus, "file-selected-not-qualified");
    assert.equal(site.executionStatus, "not-qualified");
  }
});
