"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const packager = require("./certops-agent-package");
const policy = require("../infra/certops-azure-keyvault/policy");
const TOOLCHAIN = Object.freeze({ nodeVersion: "v24.22.3", npmVersion: "11.19.1", goVersion: "go1.26.10", goFlags: "-buildvcs=false" });

const CAPABILITIES = Object.freeze([
  "windows-cert-store-v1", "iis-binding-v1", "trust-anchor-deploy-v1", "adcs-enroll-v1",
  "material-store-vault-kv2-v1", "certificate-publication-v1", "deploy-from-store-v1",
  "material-store-openbao-kv2-v1", "material-store-azure-key-vault-v1",
]);

function verifyIdentity(value) {
  assert.deepEqual(Object.keys(value).sort(), [
    "artifactId", "capabilities", "candidateSha", "packageSha256", "packageVersion", "runId",
  ].sort());
  for (const field of ["artifactId", "runId"]) assert.match(value[field], /^[1-9][0-9]{0,15}$/);
  assert.match(value.candidateSha, /^[a-f0-9]{40}$/);
  assert.match(value.packageSha256, /^[a-f0-9]{64}$/);
  assert.equal(value.packageVersion, "0.20.0");
  assert.deepEqual(value.capabilities, CAPABILITIES);
  return value;
}

function inspectArchive(file, expectedSha256) {
  assert.match(expectedSha256 || "", /^[a-f0-9]{64}$/);
  assert.ok(fs.lstatSync(file).isFile() && fs.statSync(file).size <= 20 * 1024 * 1024);
  assert.equal(packager.digest(file), expectedSha256);
  const tar = process.platform === "win32" ? path.join(process.env.SystemRoot, "System32/tar.exe") : "tar";
  const options = { encoding: "utf8", timeout: 60000, maxBuffer: 2 * 1024 * 1024 };
  const entries = execFileSync(tar, ["-tzf", file], options).trim().split(/\r?\n/);
  require("./verify-agent-native-package").assertBinaryEntries(entries);
  for (const member of ["package/package.json", "package/src/capabilities/qualified-capabilities.json",
    "package/src/capabilities/qualified-capabilities.generated.js"]) {
    assert.equal(entries.filter(entry => entry === member).length, 1);
  }
  const read = member => execFileSync(tar, ["-xOzf", file, member], { encoding: "utf8", timeout: 60000, maxBuffer: 2 * 1024 * 1024 });
  const pkg = JSON.parse(read("package/package.json"));
  assert.equal(pkg.name, "@tokentimer/agent");
  assert.equal(pkg.version, "0.20.0");
  assert.equal(read("package/src/capabilities/qualified-capabilities.json"), JSON.stringify({ qualified: CAPABILITIES }, null, 2) + "\n");
  assert.equal(read("package/src/capabilities/qualified-capabilities.generated.js"),
    require("../packages/agent/scripts/build-qualified-capabilities").renderGeneratedModule(CAPABILITIES));
}

function materializeCandidate(sourcePackage, staging) {
  const input = "src/capabilities/qualified-capabilities.json";
  const original = JSON.parse(fs.readFileSync(path.join(sourcePackage, input), "utf8"));
  assert.ok(JSON.stringify(original.qualified) === JSON.stringify(CAPABILITIES) ||
    JSON.stringify(original.qualified) === JSON.stringify(CAPABILITIES.slice(0, -1)));
  fs.cpSync(sourcePackage, staging, { recursive: true, filter: file =>
    !path.relative(sourcePackage, file).split(path.sep).some(part => ["node_modules", "dist", ".git"].includes(part)) });
  // Only this reviewed final manifest changes in the isolated build copy.
  fs.writeFileSync(path.join(staging, input), JSON.stringify({ qualified: CAPABILITIES }, null, 2) + "\n");
  fs.writeFileSync(path.join(staging, "src/capabilities/qualified-capabilities.generated.js"),
    require("../packages/agent/scripts/build-qualified-capabilities").renderGeneratedModule(CAPABILITIES));
}

function inspectReceipt(directory, candidateSha, expectedSha256, sourceKind) {
  assert.match(candidateSha || "", /^[a-f0-9]{40}$/);
  assert.match(expectedSha256 || "", /^[a-f0-9]{64}$/);
  const archive = "tokentimer-agent-0.20.0.tgz";
  assert.ok(fs.lstatSync(directory).isDirectory() && !fs.lstatSync(directory).isSymbolicLink());
  assert.deepEqual(fs.readdirSync(directory).sort(), ["artifact.json", archive, archive + ".sha256"].sort());
  for (const file of fs.readdirSync(directory)) assert.ok(fs.lstatSync(path.join(directory, file)).isFile());
  assert.ok(fs.statSync(path.join(directory, "artifact.json")).size < 16384);
  assert.ok(fs.statSync(path.join(directory, archive + ".sha256")).size < 256);
  const receipt = JSON.parse(fs.readFileSync(path.join(directory, "artifact.json"), "utf8"));
  assert.deepEqual(Object.keys(receipt).sort(), ["schemaVersion", "candidateSha", "sourceKind", "buildMode",
    "capabilitySource", "archive", "packageVersion", "capabilities", "packagerSha256", "nodeVersion",
    "npmVersion", "goVersion", "goFlags", "runnerImage", "sha256"].sort());
  assert.equal(receipt.schemaVersion, 1);
  assert.equal(receipt.candidateSha, candidateSha);
  assert.equal(receipt.sourceKind, sourceKind);
  assert.equal(receipt.buildMode, "azure-release-candidate");
  assert.equal(receipt.capabilitySource, "isolated-final-manifest");
  assert.equal(receipt.archive, archive);
  assert.equal(receipt.packageVersion, "0.20.0");
  assert.deepEqual(receipt.capabilities, CAPABILITIES);
  assert.equal(receipt.packagerSha256, packager.digest(path.resolve(__dirname, "../packages/agent/scripts/pack-release.js")));
  for (const [name, value] of Object.entries(TOOLCHAIN)) assert.equal(receipt[name], value);
  assert.deepEqual(Object.keys(receipt.runnerImage).sort(), ["os", "version"]);
  assert.match(receipt.runnerImage.os, /^[A-Za-z0-9_.-]{1,64}$/);
  assert.match(receipt.runnerImage.version, /^[A-Za-z0-9_.-]{1,64}$/);
  const file = path.join(directory, archive);
  assert.equal(receipt.sha256, expectedSha256);
  assert.equal(fs.readFileSync(file + ".sha256", "utf8").trim(), `${expectedSha256}  ${archive}`);
  inspectArchive(file, expectedSha256);
  return { archive: file, receipt };
}

function inspect(directory, candidateSha, expectedSha256) {
  return inspectReceipt(directory, candidateSha, expectedSha256, "workflow-checkout");
}

function createArchive(output, candidateSha, sourceKind) {
  assert.equal(process.platform, "linux");
  const run = (command, args) => execFileSync(command, args, { encoding: "utf8", timeout: 600000 }).trim();
  assert.equal(run("git", ["rev-parse", "HEAD"]), candidateSha);
  assert.equal(run("git", ["status", "--porcelain"]), "");
  assert.equal(process.env.GOTOOLCHAIN, "local");
  assert.equal(process.version, TOOLCHAIN.nodeVersion);
  assert.equal(run("npm", ["--version"]), TOOLCHAIN.npmVersion);
  assert.equal(run("go", ["env", "GOVERSION"]), TOOLCHAIN.goVersion);
  assert.equal(run("go", ["env", "GOFLAGS"]), TOOLCHAIN.goFlags);
  fs.mkdirSync(output);
  const staging = path.join(output, "build");
  materializeCandidate(path.resolve("packages/agent"), staging);
  const artifactDirectory = path.join(output, "artifacts");
  run(process.execPath, [path.join(staging, "scripts/pack-release.js"), "--out-dir", artifactDirectory]);
  const receipt = { candidateSha, sourceKind, buildMode: "azure-release-candidate",
    capabilitySource: "isolated-final-manifest", archive: "tokentimer-agent-0.20.0.tgz", capabilities: CAPABILITIES,
    packagerSha256: packager.digest(path.resolve("packages/agent/scripts/pack-release.js")) };
  receipt.sha256 = packager.digest(path.join(artifactDirectory, receipt.archive));
  const native = path.join(output, "native-provenance.json");
  run(process.execPath, ["scripts/verify-agent-native-package.js", "--archive", path.join(artifactDirectory, receipt.archive),
    "--go-version", "1.26.10", "--source-sha", candidateSha, "--out", native]);
  const provenance = JSON.parse(fs.readFileSync(native, "utf8"));
  assert.ok(provenance.binaries.every(binary => Object.keys(binary.settings).every(key => !/^vcs(?:\.|$)/.test(key))));
  Object.assign(receipt, { schemaVersion: 1, buildMode: "azure-release-candidate", packageVersion: "0.20.0",
    nodeVersion: process.version, npmVersion: run("npm", ["--version"]), goVersion: "go1.26.10",
    goFlags: run("go", ["env", "GOFLAGS"]),
    runnerImage: { os: process.env.ImageOS || "unknown", version: process.env.ImageVersion || "unknown" } });
  fs.writeFileSync(path.join(artifactDirectory, "artifact.json"), JSON.stringify(receipt) + "\n", { flag: "wx" });
  return receipt;
}

function build(output, expectedSha256) {
  policy.requireTrusted(process.env);
  assert.match(expectedSha256 || "", /^[a-f0-9]{64}$/);
  const receipt = createArchive(output, process.env.GITHUB_SHA, "workflow-checkout");
  inspect(path.join(output, "artifacts"), receipt.candidateSha, expectedSha256);
  return receipt;
}

function buildLocal(output) {
  assert.notEqual(process.env.GITHUB_ACTIONS, "true");
  const candidateSha = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", timeout: 10000 }).trim();
  const receipt = createArchive(output, candidateSha, "local-worktree");
  inspectReceipt(path.join(output, "artifacts"), candidateSha, receipt.sha256, "local-worktree");
  return receipt;
}

function collect(packageDirectory, reportDirectory, output, env = process.env) {
  policy.requireTrusted(env);
  assert.equal(env.GITHUB_RUN_ATTEMPT, "1");
  const reports = require("./certops-azure-keyvault-report");
  reports.artifactCheck(reportDirectory, { sourceSha: env.GITHUB_SHA });
  const report = JSON.parse(fs.readFileSync(path.join(reportDirectory, "azure-keyvault-evidence.json"), "utf8"));
  const cleanup = JSON.parse(fs.readFileSync(path.join(reportDirectory, "azure-keyvault-cleanup.json"), "utf8"));
  reports.verify(report, { sourceSha: env.GITHUB_SHA });
  reports.verifyCleanup(cleanup, env.GITHUB_SHA);
  assert.equal(cleanup.cleanup, "completed");
  const identity = verifyIdentity(report.packageArtifact);
  assert.equal(identity.runId, env.GITHUB_RUN_ID);
  assert.equal(identity.artifactId, env.TT_AZURE_PACKAGE_ARTIFACT_ID);
  assert.equal(identity.packageSha256, env.TT_AZURE_PACKAGE_SHA256);
  inspect(packageDirectory, env.GITHUB_SHA, identity.packageSha256);
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, JSON.stringify({
    schemaVersion: 1, profile: "azure-key-vault-final-package", status: "passed", packageArtifact: identity,
    providerScenarios: report.counts, cleanup: "completed", productionQualified: false, fullOperatorE2e: false,
    unqualified: report.unqualified,
  }) + "\n", { flag: "wx" });
}

module.exports = { CAPABILITIES, TOOLCHAIN, verifyIdentity, inspectArchive, inspect, materializeCandidate, build, buildLocal, collect };
if (require.main === module) {
  try {
    const [mode, first, second, third] = process.argv.slice(2);
    if (mode === "build") build(first, second);
    else if (mode === "build-local") {
      const receipt = buildLocal(first);
      console.log(`sha256=${receipt.sha256}`);
    }
    else if (mode === "collect") collect(first, second, third);
    else if (mode === "verify-release") inspectArchive(first, second);
    else throw new Error("Unknown package action");
  } catch {
    console.error("AZURE_KV_EXACT_PACKAGE_REJECTED");
    process.exitCode = 1;
  }
}
