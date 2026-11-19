"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const { test } = require("node:test");
const yaml = createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
const workflow = yaml.load(fs.readFileSync(
  path.join(__dirname, "../.github/workflows/windows-agent-signing-profile-read.yml"),
  "utf8",
));

test("signing profile reads require the reviewed main run and protected environment", () => {
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.deepEqual(workflow.on.workflow_dispatch.inputs, {
    expected_main_sha: { description: "Exact reviewed Core main commit to run", required: true, type: "string" },
  });
  assert.deepEqual(workflow.permissions, {});
  assert.deepEqual(Object.keys(workflow.jobs), ["read-profile"]);
  const job = workflow.jobs["read-profile"];
  assert.equal(job.if, "github.repository == 'tokentimerch/tokentimer-core' && github.ref == 'refs/heads/main' && github.sha == inputs.expected_main_sha");
  assert.equal(job.environment, "windows-agent-signing");
  assert.deepEqual(job.permissions, { "id-token": "write" });
  assert.deepEqual(job.env, {
    SIGNING_ENDPOINT: "${{ vars.AZURE_SIGNING_ENDPOINT }}",
    SIGNING_ACCOUNT: "${{ vars.AZURE_SIGNING_ACCOUNT }}",
    SIGNING_PROFILE: "${{ vars.AZURE_SIGNING_PROFILE }}",
  });
});

test("profile inspection runs only pinned login, fixed reads, and a public-evidence upload", () => {
  const steps = workflow.jobs["read-profile"].steps;
  assert.equal(steps.length, 4);
  assert.match(steps[1].uses, /^azure\/login@[a-f0-9]{40}$/);
  assert.match(steps[3].uses, /^actions\/upload-artifact@[a-f0-9]{40}$/);
  assert.match(steps[0].run, /codesigning\\\.azure\\\.net\$/);
  assert.doesNotMatch(steps.map(step => step.run || "").join("\n"), /\$\{\{|az (?:account get-access-token|role|resource)/);
  const reads = steps[2].run.match(/az rest --method get --url "\$resource\/(?:certchain|eku)\?api-version=2022-06-15-preview"/g);
  assert.deepEqual(reads, [
    'az rest --method get --url "$resource/certchain?api-version=2022-06-15-preview"',
    'az rest --method get --url "$resource/eku?api-version=2022-06-15-preview"',
  ]);
  assert.equal(steps[3].with.path.trim(), [
    "${{ runner.temp }}/windows-signing-public-chain/chain.der",
    "${{ runner.temp }}/windows-signing-public-chain/eku.json",
    "${{ runner.temp }}/windows-signing-public-chain/receipt.json",
  ].join("\n"));
  assert.equal(steps[3].with["if-no-files-found"], "error");
  assert.equal(steps[3].with["retention-days"], 1);
});
