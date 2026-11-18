"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { assertHosted, cleanup: cleanupHost } = require("./native-openbao-bootstrap.cjs");
const { main: cleanupDocker } = require("./owned-teardown-run.cjs");
const { dispose } = require("../operator-ca-setup.cjs");
const { runOperatorQualification } = require("./final-evidence-bridge.cjs");
const { verifyIdentity } = require("../../../../scripts/certops-azure-keyvault-package.cjs");
const { extractVerified } = require("../../../../scripts/certops-agent-package");

const profile = "openbao-operator-http-real-ca";
const scenarios = [
  "public-http-configuration", "real-ca-protocol-issuance", "independent-approval", "signed-agent-job-execution",
  "distinct-renewable-role-identities", "cross-role-denials", "exact-provider-version-pin",
  "served-tls-certificate-chain", "interruption-resume-without-republish",
];

function readJson(file) {
  const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && stat.size > 0 && stat.size < 131072);
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

async function closeOwned({ output, ownerFile, owner, project }) {
  const failures = [];
  let docker;
  try { cleanupHost(); }
  catch (error) { failures.push(error); }
  try { docker = await cleanupDocker(["--execute", ownerFile]); }
  catch (error) { failures.push(error); }
  try { dispose(output + "-operator-ca-private", path.join(output, "operator-ca")); }
  catch (error) { failures.push(error); }
  for (const name of ["session-owner.json", "session-approver.json"]) {
    try {
      const file = path.join(output, name);
      const stat = fs.lstatSync(file, { throwIfNoEntry: false });
      if (stat) {
        assert.ok(stat.isFile(), "Expected an owned disposable session");
        fs.unlinkSync(file);
      }
    } catch (error) { failures.push(error); }
  }
  if (failures.length) throw new AggregateError(failures, "Owned operator teardown was incomplete");
  assert.equal(docker.project, project);
  assert.equal(docker.candidateSha, owner.candidateSha);
  assert.equal(docker.producerRunId, owner.producerRunId);
  assert.equal(docker.archiveSha256, owner.archiveSha256);
  assert.ok(docker.ownedContainersAbsent && docker.ownedVolumesAbsent && docker.ownedNetworksAbsent);
  return { database: "completed", provider: "completed", agent: "completed", credentials: "completed", resources: "completed" };
}

async function retain({ output, ownerFile, project, sourceSha, runId }, close = closeOwned) {
  assert.ok(path.isAbsolute(output) && path.isAbsolute(ownerFile));
  assert.match(project, /^tt-wildcard-ux-qual-[a-z0-9-]+$/);
  assert.equal(path.basename(output), project);
  const owner = readJson(ownerFile);
  assert.equal(owner.project, project);
  assert.match(owner.candidateSha, /^[a-f0-9]{40}$/);
  assert.match(owner.archiveSha256, /^[a-f0-9]{64}$/);
  assert.match(owner.producerRunId, /^[1-9][0-9]{0,15}$/);
  let closePromise;
  const closeOnce = () => closePromise ??= Promise.resolve().then(() => close({ output, ownerFile, owner, project }));
  try {
    const stage = path.join(output, "agent-package");
    const packageIdentity = verifyIdentity(readJson(path.join(stage, "harness-input.json")).packageArtifact);
    assert.equal(packageIdentity.candidateSha, owner.candidateSha);
    assert.equal(packageIdentity.runId, owner.producerRunId);
    assert.equal(packageIdentity.packageSha256, owner.archiveSha256);
    const scratch = fs.mkdtempSync(path.join(output, ".operator-package-check-"));
    let files;
    try {
      ({ files } = extractVerified({ tarball: path.join(stage, "artifacts/tokentimer-agent-0.20.0.tgz"),
        expectedSha256: packageIdentity.packageSha256, destination: path.join(scratch, "extracted") }));
    } finally { fs.rmSync(scratch, { recursive: true }); }
    return await runOperatorQualification({
      profile, context: { sourceSha, runId, packageIdentity, files, requireNative: true },
      outputDirectory: output,
      observe() {
        const observed = readJson(path.join(output, "openbao-operator-observation.json"));
        assert.equal(observed.sourceSha, sourceSha);
        assert.equal(observed.runId, runId);
        return { packageArtifact: observed.packageArtifact, facts: observed.facts, nativeService: observed.nativeService,
          scenarios: scenarios.map(id => ({ id, status: "passed" })) };
      },
      async teardown() {
        return { sourceSha, runId, packageArtifact: packageIdentity, cleanup: await closeOnce() };
      },
    });
  } finally {
    await closeOnce();
  }
}

module.exports = { retain };
if (require.main === module) {
  Promise.resolve().then(() => {
    assertHosted();
    const output = process.env.TT_WILDCARD_UX_OUTPUT;
    const candidate = process.env.TT_UX_CANDIDATE_REPO;
    assert.ok(path.isAbsolute(candidate));
    assert.equal(output, path.join(candidate, ".scratch", process.env.TT_UX_PROJECT));
    return retain({ output, ownerFile: process.argv[2], project: process.env.TT_UX_PROJECT,
      sourceSha: process.env.GITHUB_SHA, runId: process.env.GITHUB_RUN_ID });
  }).catch(() => { console.error("OpenBao operator evidence or owned teardown refused"); process.exitCode = 1; });
}
