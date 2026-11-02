"use strict";
const test = require("node:test"),
  assert = require("node:assert/strict");
const fs = require("node:fs"),
  path = require("node:path");
const yaml = require("node:module").createRequire(
  require.resolve("mocha/package.json"),
)("js-yaml");
const { validateWorkflow } = require("./certops-workflow-security");
const scope = require("./certops-azure-scope-policy");
const read = (name) =>
  yaml.load(
    fs.readFileSync(path.join(__dirname, "../.github/workflows", name), "utf8"),
  );
test("qualification registration cannot obtain credentials or report a live pass", () => {
  const name = "certops-azure-keyvault-qualification.yml",
    w = read(name);
  assert.deepEqual(validateWorkflow(w, name), []);
  assert.deepEqual(Object.keys(w.on), ["workflow_dispatch"]);
  assert.deepEqual(Object.keys(w.jobs), ["registration-only"]);
  assert.deepEqual(w.permissions, { contents: "read" });
  assert.equal(w.jobs["registration-only"].environment, undefined);
  assert.equal(w.jobs["registration-only"].permissions, undefined);
  assert.match(w.jobs["registration-only"].steps[0].run, /exit 1/);
  assert.doesNotMatch(
    JSON.stringify(w),
    /id-token|AZURE_|secrets\.|uses|provision|az login/,
  );
});
test("independent janitor remains main-only, input-free and available with spending disabled", () => {
  const name = "certops-azure-keyvault-janitor.yml",
    w = read(name);
  assert.deepEqual(validateWorkflow(w, name), []);
  assert.deepEqual(scope.validate(name, w), []);
  assert.doesNotMatch(JSON.stringify(w), /LAB_ENABLED/);
  for (const mutate of [
    (w) => {
      w.jobs.cleanup.if = "always()";
    },
    (w) => {
      w.jobs.cleanup.environment = "certops-azure-keyvault-lab";
    },
    (w) => {
      w.jobs.cleanup.env.AZURE_CLIENT_SECRET = "unexpected";
    },
    (w) => {
      w.on.push = {};
    },
    (w) => {
      delete w.on.schedule;
    },
    (w) => {
      w.on.workflow_dispatch = { inputs: { ref: { type: "string" } } };
    },
    (w) => {
      w.jobs.cleanup.steps[0].with.ref = "feat/certops-distribution-extensions";
    },
    (w) => {
      w.jobs.cleanup.steps[0].with.repository = "foreign/core";
    },
    (w) => {
      w.jobs.cleanup.steps[3].run =
        "node infra/certops-azure-keyvault/lab.js provision";
    },
    (w) => {
      w.jobs.cleanup.steps[3].run = "az group delete --name production";
    },
    (w) => {
      w.jobs.cleanup.steps[3].if = "false";
    },
    (w) => {
      w.jobs.cleanup.steps[4].if = "success()";
    },
    (w) => {
      w.jobs.cleanup.steps.push({ run: "az keyvault secret show" });
    },
    (w) => {
      w.jobs.cleanup["continue-on-error"] = true;
    },
    (w) => {
      w.jobs.cleanup.permissions.contents = "write";
    },
  ]) {
    const bad = structuredClone(w);
    mutate(bad);
    assert.ok(scope.validate(name, bad).length, mutate.toString());
  }
});
