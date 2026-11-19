"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const { test } = require("node:test");

const yaml = createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
const workflow = yaml.load(fs.readFileSync(
  path.join(__dirname, "../.github/workflows/windows-agent-signing-pilot.yml"),
  "utf8",
));
const build = workflow.jobs.build;
const sign = workflow.jobs["sign-amd64"];

test("pilot requires one exact reviewed source and protected main workflow SHA", () => {
  assert.deepEqual(workflow.permissions, {});
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.deepEqual(Object.keys(workflow.jobs), ["build", "sign-amd64"]);
  assert.match(workflow.env.PILOT_SOURCE, /^[a-f0-9]{40}$/);
  const context = "github.repository == 'tokentimerch/tokentimer-core' && github.ref == 'refs/heads/main' && github.sha == inputs.expected_main_sha";
  assert.equal(build.if, context + " && inputs.reviewed_source_sha == '" + workflow.env.PILOT_SOURCE + "'");
  assert.equal(sign.if, build.if);
  assert.deepEqual(build.permissions, { contents: "read" });
  assert.equal(build.environment, undefined);
  const checkout = build.steps.find(step => step.uses?.startsWith("actions/checkout@"));
  assert.deepEqual(checkout.with, { ref: "${{ env.PILOT_SOURCE }}", "persist-credentials": false });
  assert.match(build.steps[0].run, /\.commit\.verification\.verified == true/);
  assert.match(build.steps.find(step => step.id === "package").run, /test "\$\(git rev-parse HEAD\)" = "\$PILOT_SOURCE"/);
});

test("only the protected signer handles pinned main code and the exact same-run input", () => {
  assert.equal(sign.environment, "windows-agent-signing");
  assert.deepEqual(sign.permissions, { contents: "read", "id-token": "write" });
  assert.equal(sign.needs, "build");
  assert.deepEqual(sign.steps[0].with, { ref: "${{ github.sha }}", "persist-credentials": false });
  const download = sign.steps.find(step => step.uses?.startsWith("actions/download-artifact@"));
  assert.equal(download.with["artifact-ids"], "${{ needs.build.outputs.artifact_id }}");
  assert.equal(download.with["digest-mismatch"], "error");
  assert.equal(download.with.name, undefined);
  const packageSign = sign.steps.find(step => step.uses === "./.github/actions/windows-agent-sign");
  assert.equal(packageSign.with.architecture, "amd64");
  assert.ok(sign.steps.indexOf(download) < sign.steps.indexOf(packageSign));
  const inventorySign = sign.steps.find(step => step.uses?.startsWith("azure/artifact-signing-action@"));
  assert.equal(inventorySign.with.files, "${{ steps.inventory.outputs.path }}");
  assert.equal(inventorySign.with["pkcs7-options"], "Embedded");
});

test("signed output leaves the Windows worker only as the encrypted handoff", () => {
  assert.equal(sign.env.PILOT_LAB_RECIPIENT, "${{ vars.WINDOWS_SIGNING_LAB_RECIPIENT }}");
  const uploads = sign.steps.filter(step => step.uses?.startsWith("actions/upload-artifact@"));
  assert.equal(uploads.length, 1);
  assert.equal(uploads[0], sign.steps.at(-1));
  assert.equal(uploads[0].with.path.trim(), [
    "${{ steps.stage.outputs.path }}/sealed/windows-amd64-pilot.zip.age",
    "${{ steps.stage.outputs.path }}/sealed/receipt.json",
  ].join("\n"));
  assert.equal(uploads[0].with["if-no-files-found"], "error");
  assert.equal(uploads[0].if, undefined);
  assert.match(sign.steps.at(-2).run, /-Operation Seal/);
});
