"use strict";
/**
 * Qualification notes: hierarchy environment cells
 *
 * Manual dispatch selects one four-VM lab: member Windows 2019/2022/2025 with actual
 * en-US/de-DE/fr-FR UI, default 2022/en-US,four/eight-hour lifetime/owned teardown; never
 * automatically nine labs. Nine release cells need separately measured member build/server
 * product/display language + source digests through offline-root/subordinate
 * SYSTEM/CNG/IIS/TLS/safety/HTTP/browser suite. Root/CA appliances stay Server2022; selected UI
 * installs on member+CA. Input labels cannot qualify environments or independent root/CA OS
 * cross-products; protected native runs remain required.
 *
 * Shared setup, evidence and cleanup policy: docs/certops/e2e-qualification.md.
 */
// Environment inventory and actual workflow contract only; no lab execution.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const subject = require("./certops-adcs-hierarchy-profile");
const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");
test("all nine hierarchy member environments are explicit and no unowned selector is accepted", () => {
  const values = subject.environments();
  assert.equal(values.length, 9);
  assert.equal(
    new Set(values.map((value) => `${value.osVersion}/${value.nativeLanguage}`))
      .size,
    9,
  );
  for (const value of values)
    assert.deepEqual(
      subject.profile(value.osVersion, value.nativeLanguage),
      value,
    );
  for (const version of [2019, "2016", "2022 ", null, undefined])
    assert.throws(() => subject.profile(version, "en-US"));
  for (const language of ["en", "en-GB", "en-US ", null, undefined])
    assert.throws(() => subject.profile("2022", language));
});
test("hierarchy workflow dispatch selects one bounded protected lab and retains always cleanup", () => {
  const file =
    ".github/workflows/certops-enterprise-adcs-hierarchy-qualification.yml";
  const workflow = yaml.load(
    fs.readFileSync(path.resolve(__dirname, "..", file), "utf8"),
  );
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.deepEqual(
    workflow.on.workflow_dispatch.inputs.windows_version.options,
    subject.VERSIONS,
  );
  assert.deepEqual(
    workflow.on.workflow_dispatch.inputs.language.options,
    subject.LANGUAGES,
  );
  assert.equal(
    workflow.on.workflow_dispatch.inputs.windows_version.default,
    "2022",
  );
  assert.equal(workflow.on.workflow_dispatch.inputs.language.default, "en-US");
  assert.equal(Object.keys(workflow.jobs).length, 1);
  const job = workflow.jobs.hierarchy;
  assert.equal(job.strategy, undefined);
  assert.equal(job.if, require("./certops-azure-scope-policy").PROVISION_IF);
  assert.equal(job.environment, "certops-adcs-lab");
  assert.equal(job["timeout-minutes"], 165);
  assert.equal(job.env.WINDOWS_VERSION, "${{ inputs.windows_version }}");
  assert.equal(job.env.WINDOWS_LANGUAGE, "${{ inputs.language }}");
  assert.equal(job.env.CERTOPS_WINDOWS_LANGUAGE_ASSETS, "${{ secrets.CERTOPS_WINDOWS_LANGUAGE_ASSETS }}");
  const provision = job.steps.find((step) =>
    /provision-lab\.ps1/.test(step.run || ""),
  );
  assert.match(
    provision.run,
    /-WindowsVersion \$env:WINDOWS_VERSION -Language \$env:WINDOWS_LANGUAGE -HierarchyRole subordinate/,
  );
  assert.ok(
    job.steps.findIndex((step) =>
      /certops-adcs-hierarchy-profile\.js/.test(step.run || ""),
    ) < job.steps.indexOf(provision),
  );
  assert.ok(
    job.steps.some(
      (step) =>
        step.if === "always()" && /remove-owned-lab\.ps1/.test(step.run || ""),
    ),
  );
  assert.deepEqual(
    require("./certops-workflow-security").validateWorkflow(
      workflow,
      path.basename(file),
    ),
    [],
  );
});
test("release hierarchy cells require every actual selected environment and current selection sources", () => {
  const matrix = require("./certops-qualification-manifest");
  const cells = matrix.slots.filter(
    (slot) => slot.suite === "enterprise-adcs-hierarchy-real",
  );
  assert.equal(cells.length, 9);
  for (const environment of subject.environments()) {
    const cell = cells.find(
      (slot) =>
        slot.environment.osVersion === environment.osVersion &&
        slot.environment.nativeLanguage === environment.nativeLanguage,
    );
    assert.ok(cell);
    assert.deepEqual(cell.environment, environment);
    for (const source of subject.REQUIRED_SOURCES)
      assert.ok(cell.requiredSources.includes(source));
  }
});
