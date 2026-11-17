"use strict";
// Preserve the installed-service observation outside the existing supporting
// UX report. The strict operator artifact still needs same-run teardown.
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const { main } = require("../journey.cjs");

async function run() {
  assert.ok(process.platform === "linux" && process.getuid() === 0);
  const output = process.env.TT_WILDCARD_UX_OUTPUT;
  const staged = JSON.parse(fs.readFileSync(path.join(output, "agent-package/harness-input.json"), "utf8"));
  const proof = await main({ nativeOpenBao: {
    packageArtifact: staged.packageArtifact, customerImage: process.env.TT_UX_CUSTOMER_IMAGE,
    apiAddress: "https://127.0.0.1:" + process.env.TT_UX_NATIVE_API_PORT,
    baoAddress: "https://127.0.0.1:" + process.env.TT_UX_NATIVE_BAO_PORT,
  } });
  assert.ok(proof.nativeService && proof.nativeOpenBaoFacts);
  fs.writeFileSync(path.join(output, "native-openbao-observation.json"), JSON.stringify({
    packageArtifact: staged.packageArtifact, runId: process.env.GITHUB_RUN_ID, sourceSha: process.env.GITHUB_SHA, ...proof,
  }) + "\n", { flag: "wx", mode: 0o600 });
}

run().catch(() => { console.error("Native OpenBao journey refused or incomplete"); process.exitCode = 1; });
