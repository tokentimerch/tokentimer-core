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
  const packageCommands = build.steps.find(step => step.id === "package").run;
  assert.match(packageCommands, /pack-release\.js[^\n]*--windows-store-iis-qualification/);
  assert.match(packageCommands, /windows-store-only-adcs-v1", "windows-store-iis-consumers-v1/);
  assert.match(packageCommands, /assert\.equal\(read\("qualified-capabilities\.generated\.js"\), renderGeneratedModule\(expected\)\)/);
  assert.match(packageCommands, /test "\$\(git rev-parse HEAD\)" = "\$PILOT_SOURCE"/);
  const restore = packageCommands.match(/^git restore --source="\$PILOT_SOURCE" --worktree -- \\\n  packages\/agent\/bin\/tokentimer-observed-revocation-linux-amd64 \\\n  packages\/agent\/bin\/tokentimer-observed-revocation-linux-arm64$/m);
  assert.ok(restore);
  assert.ok(packageCommands.indexOf("node packages/agent/scripts/pack-release.js") < restore.index);
  assert.ok(restore.index < packageCommands.indexOf("node scripts/verify-agent-native-package.js"));
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
  const inventorySign = sign.steps.find(step => step.run?.includes("-Operation SignInventory"));
  assert.equal(inventorySign.env.PILOT_INVENTORY_SHA256, "${{ steps.inventory.outputs.sha256 }}");
  const pilotScript = fs.readFileSync(path.join(__dirname, "windows-signing-pilot.ps1"), "utf8");
  assert.match(pilotScript, /& \$dotnet \(Join-Path \$build 'InventoryCmsSigner\.dll'\) \$publisherPins\[0\]/);
  assert.match(pilotScript, /restore \.\/InventoryCmsSigner\.csproj --configfile \.\/NuGet\.Config --locked-mode/);
  assert.match(pilotScript, /Confirm-WindowsInventoryCms @cmsArguments[\s\S]*Assert-WindowsSigningChain[\s\S]*Confirm-WindowsInventoryCms @cmsArguments/);
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
