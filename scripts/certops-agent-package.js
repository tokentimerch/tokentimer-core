"use strict";
// Package acceptance uses the normal release packager in an isolated build tree.
// A lab capability input is explicit provenance, never a released qualification.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const assert = require("node:assert/strict");
const digest = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const ADCS_ACCEPTANCE_SCENARIOS = Object.freeze([
  "adcs-package-checksum-and-extraction", "adcs-package-documented-default-root-install", "adcs-package-local-policy-and-signed-dry-run",
  "adcs-real-browser-issuer-native-preflight", "adcs-real-browser-confirmed-ca-pin", "adcs-real-browser-profile-attachment",
  "adcs-real-browser-automation-native-enrollment", "adcs-real-browser-installed-enrollment-visible", "adcs-real-browser-owned-cleanup",
  "adcs-package-service-restart-preserves-custody", "adcs-package-documented-uninstall-preserves-state",
]);
function verifyAdcsAcceptance(report, artifact, expectedSha) {
  assert.match(expectedSha || "", /^[a-f0-9]{40}$/);
  assert.equal(report.suite, "adcs-package-operator-acceptance");
  assert.equal(report.status, "passed"); assert.equal(report.strict, true);
  assert.equal(report.candidateSha, expectedSha); assert.equal(artifact.candidateSha, expectedSha);
  assert.equal(artifact.buildMode, "qualification-only-not-release");
  assert.equal(report.buildMode, artifact.buildMode);
  assert.match(artifact.sha256, /^[a-f0-9]{64}$/); assert.equal(report.packageSha256, artifact.sha256);
  assert.equal(report.qualificationStatus, "not-qualified"); assert.equal(report.publishedReleaseQualified, false);
  assert.equal(report.certificateDatabaseInjection, false); assert.equal(report.workerDriven, true);
  assert.equal(report.cleanup?.status, "passed");
  assert.deepEqual(report.requiredScenarios, ADCS_ACCEPTANCE_SCENARIOS);
  assert.deepEqual(report.missingScenarios, []); assert.deepEqual(report.missingCapabilities, []);
  for (const id of ADCS_ACCEPTANCE_SCENARIOS) {
    const rows = report.scenarios.filter(row => row.id === id);
    assert.equal(rows.length, 1); assert.equal(rows[0].status, "passed");
  }
  assert.ok(report.scenarios.every(row => row.status === "passed"));
  return true;
}
function run(file, args, options = {}) {
  const result = spawnSync(file, args, { encoding: "utf8", windowsHide: true, timeout: 600000, ...options });
  if (result.error || result.status !== 0) throw new Error(`Package acceptance command failed: ${path.basename(file)}`);
  return result.stdout;
}
function inventory(root) {
  const files = {};
  function visit(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const file = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) throw new Error("Package must not contain links");
      if (entry.isDirectory()) visit(file);
      else if (entry.isFile()) files[path.relative(root, file).split(path.sep).join("/")] = digest(file);
      else throw new Error("Package must contain only regular files and directories");
    }
  }
  visit(root);
  assert.ok(Object.keys(files).length > 0, "Empty package is not accepted");
  return files;
}
function extractVerified({ tarball, expectedSha256, destination }) {
  assert.match(expectedSha256 || "", /^[a-f0-9]{64}$/);
  assert.equal(digest(tarball), expectedSha256, "Agent archive checksum mismatch");
  const entries = run("tar", ["-tzf", tarball]).trim().split(/\r?\n/);
  assert.ok(entries.length > 0);
  for (const entry of entries) {
    assert.ok(entry.startsWith("package/") && !entry.includes("\\") && !entry.includes(":"), "Invalid package path");
    assert.ok(!entry.split("/").includes(".."), "Package traversal refused");
  }
  // Reject links before extraction, rather than discovering an escaped link later.
  for (const line of run("tar", ["-tvzf", tarball]).trim().split(/\r?\n/)) {
    assert.ok(line[0] === "-" || line[0] === "d", "Package links and special files refused");
  }
  fs.mkdirSync(destination);
  run("tar", ["-xzf", tarball, "-C", destination]);
  const root = path.join(destination, "package");
  const files = inventory(root);
  for (const required of ["bin/tokentimer-agent.js", "scripts/install-agent.ps1", "scripts/install-agent.sh", "package.json"]) {
    assert.ok(files[required], `Missing packaged entry: ${required}`);
  }
  return { root, files };
}
function verifyInstalled(files, installedRoot) {
  const stat = fs.lstatSync(installedRoot);
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink(), "Installed package root must be a real directory");
  assert.deepEqual(inventory(installedRoot), files, "Installed files differ from the verified package");
}
function buildCandidate({ sourcePackage, outputRoot, capabilities, candidateSha }) {
  assert.match(candidateSha || "", /^[a-f0-9]{40}$/);
  fs.mkdirSync(outputRoot); // Never reuse an artifact from another run.
  const staging = path.join(outputRoot, "build"), artifacts = path.join(outputRoot, "artifacts");
  fs.cpSync(sourcePackage, staging, { recursive: true, filter: file => !path.relative(sourcePackage, file).split(path.sep).some(part => ["node_modules", "dist", ".git"].includes(part)) });
  const input = path.join(staging, "src/capabilities/qualified-capabilities.json");
  const original = JSON.parse(fs.readFileSync(input, "utf8"));
  const selected = [...new Set([...original.qualified, ...capabilities])];
  fs.writeFileSync(input, JSON.stringify({ qualified: selected }));
  run(process.execPath, [path.join(staging, "scripts/build-qualified-capabilities.js")]);
  run(process.execPath, [path.join(staging, "scripts/pack-release.js"), "--out-dir", artifacts]);
  const names = fs.readdirSync(artifacts).filter(name => name.endsWith(".tgz"));
  assert.equal(names.length, 1, "Expected one candidate agent archive");
  const archive = names[0], sha256 = digest(path.join(artifacts, archive));
  assert.equal(fs.readFileSync(path.join(artifacts, archive + ".sha256"), "utf8").trim(), `${sha256}  ${archive}`);
  const receipt = { candidateSha, archive, sha256, sourceKind: process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout" : "local-worktree", buildMode: "qualification-only-not-release", capabilities: selected, packagerSha256: digest(path.join(sourcePackage, "scripts/pack-release.js")) };
  fs.writeFileSync(path.join(outputRoot, "artifact.json"), JSON.stringify(receipt, null, 2));
  return receipt;
}
module.exports = { buildCandidate, extractVerified, verifyInstalled, inventory, digest, verifyAdcsAcceptance, ADCS_ACCEPTANCE_SCENARIOS };
if (require.main === module) {
  try {
    const [sourcePackage, outputRoot, candidateSha, capabilityList] = process.argv.slice(2);
    if (sourcePackage === "verify-adcs") verifyAdcsAcceptance(JSON.parse(fs.readFileSync(outputRoot, "utf8")), JSON.parse(fs.readFileSync(candidateSha, "utf8")), capabilityList);
    else buildCandidate({ sourcePackage, outputRoot, candidateSha, capabilities: capabilityList.split(",") });
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
