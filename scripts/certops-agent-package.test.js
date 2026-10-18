"use strict";
// Exercise archive extraction and immutable installed bytes, not a mocked tar
// listing. The packaging regression in packages/agent covers the real Go files.
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), os = require("node:os"), path = require("node:path"), { spawnSync } = require("node:child_process");
const { extractVerified, verifyInstalled, digest, verifyAdcsAcceptance, ADCS_ACCEPTANCE_SCENARIOS } = require("./certops-agent-package");
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-package-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const file of ["package/bin/tokentimer-agent.js", "package/scripts/install-agent.ps1", "package/scripts/install-agent.sh", "package/package.json"]) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), file.endsWith("json") ? "{}" : "fixture-only");
  }
  const archive = path.join(root, "agent.tgz");
  assert.equal(spawnSync("tar", ["-czf", "agent.tgz", "package"], { cwd: root }).status, 0);
  return { root, archive };
}

test("AD CS package receipt rejects missing execution, skipped scenarios and release promotion", () => {
  const candidateSha = "a".repeat(40), artifact = { candidateSha, sha256: "b".repeat(64), buildMode: "qualification-only-not-release" };
  const report = {
    suite: "adcs-package-operator-acceptance", status: "passed", strict: true,
    candidateSha, packageSha256: artifact.sha256, qualificationStatus: "not-qualified", buildMode: artifact.buildMode,
    publishedReleaseQualified: false, certificateDatabaseInjection: false, workerDriven: true,
    cleanup: { status: "passed" }, requiredScenarios: [...ADCS_ACCEPTANCE_SCENARIOS],
    missingScenarios: [], missingCapabilities: [], scenarios: ADCS_ACCEPTANCE_SCENARIOS.map(id => ({ id, status: "passed" })),
  };
  assert.equal(verifyAdcsAcceptance(report, artifact, candidateSha), true);
  for (const change of [
    r => { r.scenarios.pop(); }, r => { r.scenarios[0].status = "skipped"; },
    r => { r.scenarios.push(r.scenarios[0]); }, r => { r.cleanup.status = "failed"; },
    r => { r.packageSha256 = "c".repeat(64); }, r => { r.workerDriven = false; },
    r => { r.certificateDatabaseInjection = true; }, r => { r.publishedReleaseQualified = true; },
    r => { r.missingCapabilities.push("adcs-enroll-v1"); }, r => { r.qualificationStatus = "qualified"; },
  ]) {
    const invalid = structuredClone(report); change(invalid);
    assert.throws(() => verifyAdcsAcceptance(invalid, artifact, candidateSha));
  }
  assert.throws(() => verifyAdcsAcceptance(report, artifact, "d".repeat(40)));
});
test("acceptance verifies archive checksum and all installed bytes, refusing tampering and added files", t => {
  const { root, archive } = fixture(t);
  assert.throws(() => extractVerified({ tarball: archive, expectedSha256: "0".repeat(64), destination: path.join(root, "bad") }));
  assert.equal(fs.existsSync(path.join(root, "bad")), false);
  const extracted = extractVerified({ tarball: archive, expectedSha256: digest(archive), destination: path.join(root, "extracted") });
  const installed = path.join(root, "installed"); fs.cpSync(extracted.root, installed, { recursive: true });
  assert.doesNotThrow(() => verifyInstalled(extracted.files, installed));
  fs.writeFileSync(path.join(installed, "unexpected.js"), "fixture-only");
  assert.throws(() => verifyInstalled(extracted.files, installed));
  fs.unlinkSync(path.join(installed, "unexpected.js"));
  fs.appendFileSync(path.join(installed, "bin/tokentimer-agent.js"), "tampered");
  assert.throws(() => verifyInstalled(extracted.files, installed));
});
test("acceptance refuses reused extraction roots and incomplete packages", t => {
  const { root, archive } = fixture(t), destination = path.join(root, "existing");
  fs.mkdirSync(destination);
  assert.throws(() => extractVerified({ tarball: archive, expectedSha256: digest(archive), destination }));
  fs.unlinkSync(path.join(root, "package/scripts/install-agent.ps1"));
  assert.equal(spawnSync("tar", ["-czf", "agent.tgz", "package"], { cwd: root }).status, 0);
  assert.throws(() => extractVerified({ tarball: archive, expectedSha256: digest(archive), destination: path.join(root, "incomplete") }));
});
test("acceptance rejects hard links before extracting an otherwise valid package", t => {
  const { root, archive } = fixture(t);
  fs.linkSync(path.join(root, "package/bin/tokentimer-agent.js"), path.join(root, "package/bin/linked.js"));
  assert.equal(spawnSync("tar", ["-czf", "agent.tgz", "package"], { cwd: root }).status, 0);
  assert.throws(() => extractVerified({ tarball: archive, expectedSha256: digest(archive), destination: path.join(root, "links") }));
  assert.equal(fs.existsSync(path.join(root, "links")), false);
});
