"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const { retain } = require("./native-openbao-support.cjs");
const { CAPABILITIES } = require("../../../../scripts/certops-azure-keyvault-package.cjs");
const { candidate, report } = require("../../../../scripts/test-support/final-package-evidence.cjs");

function fixture(t) {
  const outputDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-openbao-close-"));
  t.after(() => fs.rmSync(outputDirectory, { recursive: true, force: true }));
  const project = "tt-wildcard-ux-qual-123", sourceSha = "a".repeat(40), runId = "444";
  const candidateSha = "b".repeat(40), input = candidate(t, candidateSha);
  const identity = { candidateSha, artifactId: "789", runId: "456",
    packageSha256: input.digest, packageVersion: "0.20.0", capabilities: CAPABILITIES };
  const stage = path.join(outputDirectory, "agent-package");
  fs.mkdirSync(path.join(stage, "artifacts"), { recursive: true });
  for (const [name, bytes] of input.entries) fs.writeFileSync(path.join(stage, "artifacts", name), bytes);
  fs.writeFileSync(path.join(stage, "harness-input.json"), JSON.stringify({ packageArtifact: identity }));
  const teardownReceipt = path.join(outputDirectory, "teardown.json");
  fs.writeFileSync(teardownReceipt, JSON.stringify({ project }));
  const observation = path.join(outputDirectory, "native-openbao-observation.json");
  const native = report("openbao-operator-http-real-ca", sourceSha, runId, identity, input.files).nativeService;
  fs.writeFileSync(observation, JSON.stringify({ sourceSha, runId, packageArtifact: identity, nativeService: native,
    nativeOpenBaoFacts: { installed: { leafSha256: "c".repeat(64), chainSha256: "d".repeat(64) },
      provider: { exactRead200: 1, renew200: 1 } } }));
  return { parameters: { outputDirectory, teardownReceipt, project, sourceSha, runId }, observation,
    output: path.join(outputDirectory, "native-openbao-support.json"),
    closed: { project, candidateSha, producerRunId: identity.runId, archiveSha256: identity.packageSha256,
      ownedContainersAbsent: true, ownedVolumesAbsent: true, ownedNetworksAbsent: true } };
}
test("retains only supporting observations after native and project cleanup", async t => {
  const { parameters, output, closed } = fixture(t);
  const result = await retain(parameters, async () => { assert.equal(fs.existsSync(output), false); return closed; });
  assert.equal(result.status, "passed-supporting-only");
  assert.equal(result.fullOperatorE2e, false);
  assert.deepEqual(JSON.parse(fs.readFileSync(output, "utf8")), result);
});
test("withholds evidence for residual networks, stale run or interrupted observations", async t => {
  const { parameters, output, observation, closed } = fixture(t);
  await assert.rejects(retain(parameters, async () => ({ ...closed, ownedNetworksAbsent: false })));
  await assert.rejects(retain({ ...parameters, runId: "999" }, async () => closed));
  fs.unlinkSync(observation);
  assert.equal(await retain(parameters, async () => closed), null);
  assert.equal(fs.existsSync(output), false);
});
