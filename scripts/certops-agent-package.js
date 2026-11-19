"use strict";
// Package acceptance uses the normal release packager in an isolated build tree.
// A lab capability input is explicit provenance, never a released qualification.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const assert = require("node:assert/strict");
const { RUNTIMES, VERSION: BUNDLED_NODE_VERSION } = require("../packages/agent/scripts/windows-runtime-package");
const linuxCase = () => require("./certops-linux-cleanup-case.cjs");
const digest = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const ADCS_ACCEPTANCE_SCENARIOS = Object.freeze([
  "adcs-package-native-server-language-and-system-identity",
  "adcs-package-checksum-and-extraction", "adcs-package-documented-default-root-install", "adcs-package-local-policy-and-signed-dry-run",
  "adcs-real-browser-issuer-native-preflight", "adcs-real-browser-confirmed-ca-pin", "adcs-real-browser-profile-attachment",
  "adcs-real-browser-automation-native-enrollment", "adcs-real-browser-installed-enrollment-visible", "adcs-real-browser-owned-cleanup",
  "adcs-package-approved-request-production-worker-continuation",
  "adcs-package-service-restart-preserves-custody", "adcs-package-documented-uninstall-preserves-state",
]);
function verifyNativeEnvironment(native) {

  assert.ok(native);assert.equal(native.osFamily,"windows");assert.equal(native.productType,"3");
  assert.equal(native.build,{"2019":"17763","2022":"20348","2025":"26100"}[native.windowsVersion]);
  assert.ok(["2019","2022","2025"].includes(native.windowsVersion));
  assert.ok(["en-US","de-DE","fr-FR"].includes(native.language));
  assert.equal(native.uiCulture,native.language);assert.equal(native.systemLocale,native.language);
  assert.equal(native.identitySid,"S-1-5-18");assert.equal(native.domain,"lab.certops.test");
  assert.equal(native.installedDisplayResources,true);assert.equal(native.measurement,"native");
  const expectedVersion=process.env.CERTOPS_WINDOWS_VERSION||process.env.WINDOWS_VERSION,expectedLanguage=process.env.CERTOPS_WINDOWS_LANGUAGE||process.env.WINDOWS_LANGUAGE;
  if(expectedVersion)assert.equal(native.windowsVersion,expectedVersion);
  if(expectedLanguage)assert.equal(native.language,expectedLanguage);
  return true;
}
function verifyAdcsAcceptance(report, artifact, expectedSha, requireBundled = false) {
  assert.match(expectedSha || "", /^[a-f0-9]{40}$/);
  assert.equal(report.suite, "adcs-package-operator-acceptance");
  assert.equal(report.status, "passed"); assert.equal(report.strict, true);
  assert.equal(report.candidateSha, expectedSha); assert.equal(artifact.candidateSha, expectedSha);
  assert.equal(artifact.buildMode, "qualification-only-not-release");
  assert.equal(report.buildMode, artifact.buildMode);
  assert.match(artifact.sha256, /^[a-f0-9]{64}$/); assert.equal(report.packageSha256, artifact.sha256);
  assert.equal(report.qualificationStatus, "not-qualified"); assert.equal(report.publishedReleaseQualified, false);
  if (requireBundled || artifact.archiveKind !== undefined) verifyBundledRuntimeEvidence(report.bundledRuntime, artifact);
  assert.equal(report.certificateDatabaseInjection, false); assert.equal(report.workerDriven, true);
  assert.equal(report.cleanup?.status, "passed");
  verifyNativeEnvironment(report.nativeEnvironment);
  require("../tests/e2e/helpers/certops-adcs-package-pending").verifyProof(report.packagePendingWorker);
  require("../tests/e2e/helpers/certops-adcs-browser-journey").verifyProof(report.nativeBrowserAdcs,{workerDriven:true});
  assert.deepEqual(report.requiredScenarios, ADCS_ACCEPTANCE_SCENARIOS);
  assert.deepEqual(report.missingScenarios, []); assert.deepEqual(report.missingCapabilities, []);
  for (const id of ADCS_ACCEPTANCE_SCENARIOS) {
    const rows = report.scenarios.filter(row => row.id === id);
    assert.equal(rows.length, 1); assert.equal(rows[0].status, "passed");
  }
  assert.ok(report.scenarios.every(row => row.status === "passed"));
  return true;
}
function verifyBundledRuntimeEvidence(evidence, artifact) {
  assert.equal(artifact.archiveKind, "windows-bundled-amd64");
  assert.equal(artifact.runtimeNodeSha256, RUNTIMES.amd64.sha256);
  assert.equal(evidence?.serviceAccount, "LocalSystem");
  assert.equal(evidence?.childCount, 1);
  assert.equal(evidence?.childPath?.toLowerCase(), "c:\\programdata\\tokentimeragent\\app\\runtime\\amd64\\node.exe");
  assert.equal(evidence?.childSha256?.toLowerCase(), artifact.runtimeNodeSha256);
  return true;
}
function verifyBundledArchive(root, files, artifact) {
  assert.equal(artifact.archiveKind, "windows-bundled-amd64");
  assert.equal(artifact.runtimeNodeSha256, RUNTIMES.amd64.sha256);
  const metadata = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "runtime", "manifest.json"), "utf8"));
  assert.equal(metadata.windowsBundledRuntime, true);
  assert.deepEqual(manifest, { version: BUNDLED_NODE_VERSION, architecture: "amd64", path: "runtime/amd64/node.exe", sha256: RUNTIMES.amd64.sha256 });
  assert.equal(files["runtime/amd64/node.exe"], RUNTIMES.amd64.sha256);
  assert.ok(files["runtime/LICENSE"]);
  return true;
}
function verifyOperatorScope(infrastructure,report) {
  assert.equal(infrastructure.candidateSha,process.env.GITHUB_SHA);
  assert.match(infrastructure.candidateSha,/^[a-f0-9]{40}$/);
  assert.equal(infrastructure.scope,"disposable-enterprise-adcs-infrastructure");
  assert.equal(infrastructure.qualificationScope,"operator-acceptance");
  assert.equal(infrastructure.status,"provisioned-and-native-scenarios-completed");
  assert.equal(infrastructure.scenarioReport,"enterprise-adcs-package-acceptance.json");
  const stages=infrastructure.stages;
  for(const marker of ["installed-language-verified","acceptance-worker-started","operator-package-acceptance-passed","acceptance-worker-stopped","operator-acceptance-only-completed-not-comprehensive"])assert.ok(stages.includes(`CERTOPS_STAGE=${marker}`));
  assert.equal(stages.filter(row=>row==="CERTOPS_STAGE=installed-language-verified").length,2);
  assert.ok(!stages.includes("CERTOPS_STAGE=real-enterprise-adcs-tests-passed"));
  assert.equal(report.candidateSha,infrastructure.candidateSha);assert.equal(report.suite,"adcs-package-operator-acceptance");
  assert.equal(report.buildMode,"qualification-only-not-release");assert.match(report.packageSha256||"",/^[a-f0-9]{64}$/);
  assert.equal(report.status,"passed");assert.equal(report.strict,true);assert.equal(report.qualificationStatus,"not-qualified");
  assert.equal(report.publishedReleaseQualified,false);assert.equal(report.cleanup?.status,"passed");
  assert.equal(report.workerDriven,true);assert.equal(report.certificateDatabaseInjection,false);
  require("../tests/e2e/helpers/certops-adcs-package-pending").verifyProof(report.packagePendingWorker);
  require("../tests/e2e/helpers/certops-adcs-browser-journey").verifyProof(report.nativeBrowserAdcs,{workerDriven:true});
  verifyNativeEnvironment(report.nativeEnvironment);
  assert.deepEqual(report.requiredScenarios,ADCS_ACCEPTANCE_SCENARIOS);assert.deepEqual(report.missingScenarios,[]);assert.deepEqual(report.missingCapabilities,[]);
  for(const id of ADCS_ACCEPTANCE_SCENARIOS){const rows=report.scenarios.filter(row=>row.id===id);assert.equal(rows.length,1);assert.equal(rows[0].status,"passed");}
  assert.ok(report.scenarios.every(row=>row.status==="passed"));
  // The guest's operator-package-acceptance-passed marker is emitted only after
  // verify-adcs compares the receipt to the independently built archive.
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
  tarball = path.resolve(tarball);
  destination = path.resolve(destination);
  // Inspect and extract one immutable verified buffer. Stdin also avoids
  // Windows drive/path interpretation differences between BSD and GNU tar.
  const archiveBytes = fs.readFileSync(tarball), archiveOptions = { input: archiveBytes };
  assert.match(expectedSha256 || "", /^[a-f0-9]{64}$/);
  assert.equal(crypto.createHash("sha256").update(archiveBytes).digest("hex"), expectedSha256, "Agent archive checksum mismatch");
  const entries = run("tar", ["-tzf", "-"], archiveOptions).trim().split(/\r?\n/);
  assert.ok(entries.length > 0);
  for (const entry of entries) {
    assert.ok(entry.startsWith("package/") && !entry.includes("\\") && !entry.includes(":"), "Invalid package path");
    assert.ok(!entry.split("/").includes(".."), "Package traversal refused");
  }
  // Reject links before extraction, rather than discovering an escaped link later.
  for (const line of run("tar", ["-tvzf", "-"], archiveOptions).trim().split(/\r?\n/)) {
    assert.ok(line[0] === "-" || line[0] === "d", "Package links and special files refused");
  }
  fs.mkdirSync(destination);
  run("tar", ["-xzf", "-"], { ...archiveOptions, cwd: destination });
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
function verifyCandidateArchives(directory, expected) {
  const names = fs.readdirSync(directory).filter(name => name.endsWith(".tgz"));
  assert.deepEqual(names.sort(), [...expected].sort(), "Unexpected candidate archive set");
  const checksums = {};
  for (const name of expected) {
    const sha256 = digest(path.join(directory, name));
    assert.equal(fs.readFileSync(path.join(directory, name + ".sha256"), "utf8").trim(), `${sha256}  ${name}`);
    checksums[name] = sha256;
  }
  return checksums;
}
function buildCandidate({ sourcePackage, outputRoot, capabilities, candidateSha, windowsRuntimeDir, linuxCleanup = null }) {
  assert.match(candidateSha || "", /^[a-f0-9]{40}$/);
  if (windowsRuntimeDir && linuxCleanup) throw new Error("Linux qualification mode and Windows runtime cannot be combined");
  const distribution = !!linuxCleanup && linuxCleanup === linuxCase().distribution;
  const linuxOnly = linuxCleanup && !distribution;
  fs.mkdirSync(outputRoot); // Never reuse an artifact from another run.
  const staging = path.join(outputRoot, "build"), artifacts = path.join(outputRoot, "artifacts");
  fs.cpSync(sourcePackage, staging, { recursive: true, filter: file => !path.relative(sourcePackage, file).split(path.sep).some(part => ["node_modules", "dist", ".git"].includes(part)) });
  const input = path.join(staging, "src/capabilities/qualified-capabilities.json");
  const original = JSON.parse(fs.readFileSync(input, "utf8"));
  if (distribution) assert.equal(original.qualified.includes("windows-material-iis-v1"), false, "Windows IIS must remain absent from the qualification baseline");
  const selected = [...new Set([...original.qualified, ...capabilities])];
  if (linuxCleanup) {
    assert.deepEqual(capabilities, linuxCleanup.capabilities ?? [linuxCleanup.capability]);
    assert.ok(capabilities.every(capability => !original.qualified.includes(capability)));
    if (linuxOnly) {
      const packageFile = path.join(staging, "package.json");
      const pkg = JSON.parse(fs.readFileSync(packageFile, "utf8"));
      pkg.os = ["linux"];
      pkg.files = pkg.files.filter(file => !/\.exe$|install-agent\.ps1$/i.test(file));
      fs.writeFileSync(packageFile, JSON.stringify(pkg, null, 2) + "\n");
    }
    run(process.execPath, [path.join(staging, "scripts/check-shipped-sources.js")]);
  }
  fs.writeFileSync(input, JSON.stringify({ qualified: selected }));
  run(process.execPath, [path.join(staging, "scripts/build-qualified-capabilities.js")]);
  const args = [path.join(staging, "scripts/pack-release.js"), "--out-dir", artifacts];
  if (windowsRuntimeDir) args.push("--windows-runtime-dir", path.resolve(windowsRuntimeDir));
  if (linuxOnly) args.push("--linux-only");
  run(process.execPath, args);
  const version = JSON.parse(fs.readFileSync(path.join(staging, "package.json"), "utf8")).version;
  const archive = linuxOnly ? `tokentimer-agent-linux-${version}.tgz`
    : windowsRuntimeDir ? `tokentimer-agent-${version}-windows-amd64.tgz`
    : `tokentimer-agent-${version}.tgz`;
  const expected = windowsRuntimeDir
    ? [`tokentimer-agent-${version}.tgz`, archive, `tokentimer-agent-${version}-windows-arm64.tgz`]
    : [archive];
  const checksums = verifyCandidateArchives(artifacts, expected);
  const sha256 = checksums[archive];
  const receipt = { candidateSha, archive, sha256, sourceKind: process.env.GITHUB_ACTIONS === "true" ? "workflow-checkout" : "local-worktree", buildMode: linuxCleanup?.buildMode ?? "qualification-only-not-release", capabilities: selected, packagerSha256: digest(path.join(sourcePackage, "scripts/pack-release.js")) };
  if (windowsRuntimeDir) Object.assign(receipt, { archiveKind: "windows-bundled-amd64", runtimeNodeSha256: RUNTIMES.amd64.sha256 });
  if (linuxCleanup) {
    receipt.schemaVersion = 1;
    receipt.version = require(path.join(staging, "package.json")).version;
    if (distribution) receipt.packageVersion = receipt.version;
    receipt.nodeVersion = process.version;
    receipt.npmVersion = run("npm", ["--version"]).trim();
    require("./certops-linux-published-package").inspectLinuxCandidate(path.join(artifacts, archive), receipt, linuxCleanup.provider, linuxCleanup.staging, {
      distribution, sourceKind: receipt.sourceKind,
    });
  }
  fs.writeFileSync(path.join(outputRoot, "artifact.json"), JSON.stringify(receipt, null, 2));
  return receipt;
}
function buildLinuxCandidate(outputRoot, linuxCleanup) {
  assert.equal(process.platform, "linux");
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  const candidateSha = process.env.GITHUB_SHA;
  const root = path.resolve(__dirname, "..");
  assert.equal(run("git", ["rev-parse", "HEAD"], { cwd: root }).trim(), candidateSha);
  assert.equal(run("git", ["status", "--porcelain"], { cwd: root }).trim(), "");
  const expectedOutput = path.join(fs.realpathSync(process.env.RUNNER_TEMP), linuxCleanup.directory);
  assert.equal(path.resolve(outputRoot), expectedOutput);
  return buildCandidate({ sourcePackage: path.join(root, "packages/agent"), outputRoot: expectedOutput,
    capabilities: linuxCleanup.capabilities ?? [linuxCleanup.capability], candidateSha, linuxCleanup });
}
function verifyReleaseDistributionCandidate(directory, expectedSha256, { nodeVersion, npmVersion, goVersion }) {
  assert.match(expectedSha256 || "", /^[a-f0-9]{64}$/, "An exact expected package SHA-256 is required");
  const receipt = JSON.parse(fs.readFileSync(path.join(directory, "artifact.json"), "utf8"));
  const provenance = JSON.parse(fs.readFileSync(path.join(directory, "native-provenance.json"), "utf8"));
  assert.equal(receipt.archive, "tokentimer-agent-0.20.0.tgz");
  assert.equal(receipt.nodeVersion, `v${nodeVersion}`, "Unexpected candidate Node version");
  assert.equal(receipt.npmVersion, npmVersion, "Unexpected candidate npm version");
  assert.equal(provenance.goVersion, `go${goVersion}`, "Unexpected candidate Go version");
  assert.equal(provenance.status, "passed");
  assert.equal(provenance.sourceSha, receipt.candidateSha);
  assert.equal(provenance.archive, receipt.archive);
  assert.equal(receipt.sha256, expectedSha256, "Candidate package receipt SHA-256 differs from the expected SHA-256");
  assert.equal(provenance.archiveSha256, expectedSha256, "Candidate binary provenance has a different package SHA-256");
  const actualSha256 = digest(path.join(directory, "artifacts", receipt.archive));
  assert.equal(actualSha256, expectedSha256, "Candidate tarball bytes differ from the expected SHA-256");
  return actualSha256;
}
module.exports = { buildCandidate, extractVerified, verifyInstalled, verifyBundledArchive, verifyBundledRuntimeEvidence,
  verifyCandidateArchives, inventory, digest, verifyAdcsAcceptance, verifyOperatorScope,
  verifyReleaseDistributionCandidate, ADCS_ACCEPTANCE_SCENARIOS };
if (require.main === module) {
  try {
    const [sourcePackage, outputRoot, candidateSha, capabilityList, windowsRuntimeDir] = process.argv.slice(2);
    if (sourcePackage === "verify-adcs") verifyAdcsAcceptance(JSON.parse(fs.readFileSync(outputRoot, "utf8")), JSON.parse(fs.readFileSync(candidateSha, "utf8")), capabilityList, windowsRuntimeDir === "bundled");
    else if(sourcePackage === "verify-operator-scope")verifyOperatorScope(JSON.parse(fs.readFileSync(outputRoot,"utf8")),JSON.parse(fs.readFileSync(candidateSha,"utf8")));
    else if (sourcePackage === "build-linux-vault-cleanup") buildLinuxCandidate(outputRoot, linuxCase()("vault-kv2"));
    else if (sourcePackage === "build-linux-openbao-cleanup") buildLinuxCandidate(outputRoot, linuxCase()("openbao-kv2"));
    else if (sourcePackage === "build-linux-staging") buildLinuxCandidate(outputRoot, linuxCase()("vault-kv2", true));
    else if (sourcePackage === "build-release-distribution-candidate") buildLinuxCandidate(outputRoot, linuxCase().distribution);
    else if (sourcePackage === "verify-release-distribution-candidate") {
      const sha256 = verifyReleaseDistributionCandidate(outputRoot, candidateSha, {
        nodeVersion: process.env.NODE_VERSION, npmVersion: process.env.NPM_VERSION, goVersion: process.env.GO_VERSION,
      });
      process.stdout.write(`sha256=${sha256}\n`);
    }
    else buildCandidate({ sourcePackage, outputRoot, candidateSha, capabilities: capabilityList.split(","), windowsRuntimeDir });
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
