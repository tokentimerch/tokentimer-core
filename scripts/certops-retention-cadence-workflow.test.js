"use strict";
/** Local security regressions for the installed-service timer handoff. These
 * inspect committed workflow contracts without provisioning or dispatching. */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const yaml = createRequire(
  require.resolve(
    path.resolve(__dirname, "../node_modules/mocha/package.json"),
  ),
)("js-yaml");
const { validateWorkflow } = require("./certops-workflow-security");
const read = (name) =>
  yaml.load(
    fs.readFileSync(
      path.resolve(__dirname, "../.github/workflows", name),
      "utf8",
    ),
  );
const prepareName = "certops-retention-cadence-prepare.yml";
const locate = (workflow, fragment) =>
  workflow.jobs.prepare.steps.findIndex((step) =>
    (step.run || step.with?.path || "").includes(fragment),
  );

test("installed timer retention requires the complete ordered immutable handoff", () => {
  assert.deepEqual(validateWorkflow(read(prepareName), prepareName), []);
  for (const fragment of [
    "provision-lab.ps1",
    "-azure.js seal",
    "retention-cadence-original.json",
    "-azure.js handoff",
    "retention-cadence-ownership.json",
    "-azure.js abort",
  ]) {
    const workflow = read(prepareName);
    workflow.jobs.prepare.steps.splice(locate(workflow, fragment), 1);
    assert.ok(validateWorkflow(workflow, prepareName).length, fragment);
  }
  for (const change of [
    (workflow) => {
      const steps = workflow.jobs.prepare.steps,
        a = locate(workflow, "retention-cadence-original.json"),
        b = locate(workflow, "-azure.js handoff");
      [steps[a], steps[b]] = [steps[b], steps[a]];
    },
    (workflow) => {
      workflow.jobs.prepare.steps[locate(workflow, "-azure.js handoff")].if =
        "always()";
    },
    (workflow) => {
      workflow.jobs.prepare.steps[
        locate(workflow, "retention-cadence-original.json")
      ].with["if-no-files-found"] = "warn";
    },
    (workflow) => {
      workflow.jobs.prepare.steps[locate(workflow, "-azure.js abort")].if =
        "failure()";
    },
    (workflow) => {
      workflow.jobs.prepare.steps.push({ run: "echo late-failure" });
    },
    (workflow) => {
      workflow.on.schedule = [{ cron: "0 * * * *" }];
    },
    (workflow) => {
      workflow.jobs.prepare.environment = "certops-adcs-cleanup";
    },
    (workflow) => {
      workflow.concurrency.group = "certops-retention24h-owned-azure-lifecycle";
    },
    (workflow) => {
      workflow.jobs.prepare["timeout-minutes"] = 181;
    },
  ]) {
    const workflow = read(prepareName);
    change(workflow);
    assert.ok(validateWorkflow(workflow, prepareName).length);
  }
  assert.ok(
    validateWorkflow(read(prepareName), "certops-unrelated-paid-lab.yml").some(
      (error) => error.includes("independent always cleanup"),
    ),
  );
});

test("installed timer cleanup remains unattended and serialized with the expiry janitor", () => {
  const prepare = read(prepareName);
  assert.ok(
    prepare.jobs.prepare["timeout-minutes"] * 60000 + 300000 <
      require("./certops-retention-cadence-contract").INITIAL,
  );
  for (const mode of ["finalize", "janitor"]) {
    const name = `certops-retention-cadence-${mode}.yml`,
      workflow = read(name);
    assert.deepEqual(validateWorkflow(workflow, name), []);
    assert.equal(
      workflow.concurrency.group,
      read("certops-adcs-lab-janitor.yml").concurrency.group,
    );
    for (const change of [
      (value) => {
        value.jobs[mode].environment = "certops-adcs-lab";
      },
      (value) => {
        value.concurrency.group = "foreign";
      },
      (value) => {
        value.concurrency["cancel-in-progress"] = true;
      },
    ]) {
      const value = structuredClone(workflow);
      change(value);
      assert.ok(validateWorkflow(value, name).length);
    }
  }
});
test("six-hour campaign is explicitly optional AD CS while hosted generic checks retain bounded scope", () => {
  for (const mode of ["prepare", "finalize", "janitor"]) {
    const workflow = read(`certops-retention-cadence-${mode}.yml`);
    assert.match(workflow.name, /^CertOps \/ Optional AD CS \//);
  }
  assert.deepEqual(Object.keys(read(prepareName).on), ["workflow_dispatch"]);
});
