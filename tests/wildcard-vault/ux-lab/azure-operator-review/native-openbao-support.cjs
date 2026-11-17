"use strict";
// Cleanup a selected native OpenBao run and retain bounded supporting evidence.
// Publication admission consumes the independently reviewed final profile only.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { assertHosted, cleanup: cleanupHost } = require("./native-openbao-bootstrap.cjs");
const { main: cleanupDocker } = require("./owned-teardown-run.cjs");
const { verifyIdentity } = require("../../../../scripts/certops-azure-keyvault-package.cjs");
const { extractVerified } = require("../../../../scripts/certops-agent-package");
const { verifyNative } = require("../../../../scripts/certops-final-package-evidence.cjs");

function readJson(file) {
  const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && stat.size > 0 && stat.size < 131072);
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

async function retain({ outputDirectory, teardownReceipt, project, sourceSha, runId },
  close = async receipt => { cleanupHost(); return cleanupDocker(["--execute", receipt]); }) {
  assert.ok(path.isAbsolute(outputDirectory) && path.isAbsolute(teardownReceipt));
  assert.match(project || "", /^tt-wildcard-ux-qual-[a-z0-9-]+$/);
  const owner = readJson(teardownReceipt);
  assert.equal(owner.project, project);
  const closed = await close(teardownReceipt);
  assert.equal(closed.project, project);
  assert.ok(closed.ownedContainersAbsent && closed.ownedVolumesAbsent && closed.ownedNetworksAbsent);
  const observation = path.join(outputDirectory, "native-openbao-observation.json");
  if (!fs.lstatSync(observation, { throwIfNoEntry: false })) return null;

  assert.match(sourceSha, /^[a-f0-9]{40}$/);
  assert.match(runId, /^[1-9][0-9]{0,15}$/);
  const stage = path.join(outputDirectory, "agent-package");
  const identity = verifyIdentity(readJson(path.join(stage, "harness-input.json")).packageArtifact);
  assert.equal(closed.candidateSha, identity.candidateSha);
  assert.equal(closed.producerRunId, identity.runId);
  assert.equal(closed.archiveSha256, identity.packageSha256);
  const observed = readJson(observation);
  assert.equal(observed.sourceSha, sourceSha);
  assert.equal(observed.runId, runId);
  assert.deepEqual(observed.packageArtifact, identity);
  const reference = fs.mkdtempSync(path.join(outputDirectory, ".native-check-"));
  let files;
  try {
    ({ files } = extractVerified({ tarball: path.join(stage, "artifacts/tokentimer-agent-0.20.0.tgz"),
      expectedSha256: identity.packageSha256, destination: path.join(reference, "extracted") }));
  } finally { fs.rmSync(reference, { recursive: true }); }
  verifyNative(observed.nativeService, files);
  const { installed, provider } = observed.nativeOpenBaoFacts;
  for (const hash of [installed.leafSha256, installed.chainSha256]) assert.match(hash, /^[a-f0-9]{64}$/);
  for (const count of [provider.exactRead200, provider.renew200]) assert.ok(Number.isSafeInteger(count) && count > 0);
  const summary = { schemaVersion: 1, sourceSha, runId, project, packageArtifact: identity,
    status: "passed-supporting-only", productionQualified: false, fullOperatorE2e: false,
    nativeService: observed.nativeService,
    installed: { leafSha256: installed.leafSha256, chainSha256: installed.chainSha256 },
    provider: { exactRead200: provider.exactRead200, renew200: provider.renew200 },
    cleanup: { nativeHost: "completed", ownedContainers: "absent", ownedVolumes: "absent", ownedNetworks: "absent" } };
  fs.writeFileSync(path.join(outputDirectory, "native-openbao-support.json"), JSON.stringify(summary) + "\n",
    { flag: "wx", mode: 0o600 });
  return summary;
}

module.exports = { retain };
if (require.main === module) {
  Promise.resolve().then(() => {
    assertHosted();
    return retain({ outputDirectory: process.env.TT_WILDCARD_UX_OUTPUT, teardownReceipt: process.argv[2],
      project: process.env.TT_UX_PROJECT, sourceSha: process.env.GITHUB_SHA, runId: process.env.GITHUB_RUN_ID });
  }).catch(() => { console.error("Native OpenBao cleanup or supporting receipt refused"); process.exitCode = 1; });
}
