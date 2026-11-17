"use strict";
// Offline contract fixtures only; these cannot qualify a native package or Azure.
const test = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), os = require("node:os");
const { execFileSync, spawnSync } = require("node:child_process");
const subject = require("./certops-azure-keyvault-package.cjs");
const reports = require("./certops-azure-keyvault-report");
const packager = require("./certops-agent-package");
const generated = require("../packages/agent/scripts/build-qualified-capabilities");
const sha = "a".repeat(40), otherSha = "b".repeat(40);
const tar = process.platform === "win32" ? path.join(process.env.SystemRoot, "System32/tar.exe") : "tar";

function fixture(t, { capabilities = subject.CAPABILITIES, version = "0.20.0", omitBinary = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tt-azure-package-contract-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, "source"), directory = path.join(root, "artifacts");
  const write = (name, text) => {
    const target = path.join(source, "package", name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, text);
  };
  write("package.json", JSON.stringify({ name: "@tokentimer/agent", version }));
  write("src/capabilities/qualified-capabilities.json", JSON.stringify({ qualified: capabilities }, null, 2) + "\n");
  write("src/capabilities/qualified-capabilities.generated.js", generated.renderGeneratedModule(capabilities));
  for (const name of require("./verify-agent-native-package").EXPECTED_BINARIES.slice(omitBinary ? 1 : 0)) {
    write(name.slice("package/".length), "offline-non-executable-fixture");
  }
  fs.mkdirSync(directory);
  const archive = "tokentimer-agent-0.20.0.tgz", file = path.join(directory, archive);
  execFileSync(tar, ["-czf", file, "package"], { cwd: source, timeout: 10000 });
  const digest = packager.digest(file);
  const receipt = {
    schemaVersion: 1, candidateSha: sha, sourceKind: "workflow-checkout", buildMode: "azure-release-candidate",
    capabilitySource: "isolated-final-manifest", archive, packageVersion: "0.20.0", capabilities: subject.CAPABILITIES,
    packagerSha256: packager.digest(path.join(__dirname, "../packages/agent/scripts/pack-release.js")),
    ...subject.TOOLCHAIN,
    runnerImage: { os: "ubuntu24", version: "20261116.1.0" }, sha256: digest,
  };
  fs.writeFileSync(path.join(directory, "artifact.json"), JSON.stringify(receipt));
  fs.writeFileSync(file + ".sha256", `${digest}  ${archive}\n`);
  const identity = { artifactId: "12345678", runId: "87654321", candidateSha: sha,
    packageSha256: digest, packageVersion: "0.20.0", capabilities: [...subject.CAPABILITIES] };
  return { root, source, directory, file, receipt, digest, identity };
}
function evidence(f) {
  const directory = path.join(f.root, "evidence");
  fs.mkdirSync(directory);
  const report = reports.emptyReport(sha, f.digest, f.identity);
  report.scenarios.forEach(row => { row.status = "passed"; });
  report.counts = reports.counts(report.scenarios);
  report.status = "passed";
  report.databaseCleanup = "completed";
  report.facts = { ambiguousPutAttempts: 1, recoveredProviderVersions: 1, acceptedProviderPins: 2,
    azure401Responses: 1, azure403Responses: 4, entraTokenExchanges: 4, exactPackageVerified: true };
  const cleanup = { schemaVersion: 1, sourceSha: sha, cleanup: "completed", purgeRequested: false };
  const save = () => {
    fs.writeFileSync(path.join(directory, "azure-keyvault-evidence.json"), JSON.stringify(report));
    fs.writeFileSync(path.join(directory, "azure-keyvault-cleanup.json"), JSON.stringify(cleanup));
  };
  save();
  return { directory, report, cleanup, save };
}
function env(f) {
  return { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "tokentimerch/tokentimer-core", GITHUB_REF: "refs/heads/main",
    GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_SHA: sha, GITHUB_RUN_ID: f.identity.runId, GITHUB_RUN_ATTEMPT: "1",
    CERTOPS_AZURE_KEYVAULT_LAB_ENABLED: "true", TT_AZURE_PACKAGE_ARTIFACT_ID: f.identity.artifactId,
    TT_AZURE_PACKAGE_SHA256: f.digest };
}

test("typed package identity has a closed source, run, artifact and nine-capability contract", () => {
  const identity = { artifactId: "123", runId: "456", candidateSha: sha, packageSha256: "c".repeat(64),
    packageVersion: "0.20.0", capabilities: [...subject.CAPABILITIES] };
  subject.verifyIdentity(identity);
  for (const patch of [{ artifactId: "../123" }, { artifactId: 123 }, { runId: "0" }, { candidateSha: "main" },
    { packageSha256: "" }, { packageVersion: "0.19.0" }, { secret: "unexpected" },
    { capabilities: subject.CAPABILITIES.slice(0, -1) }, { capabilities: [...subject.CAPABILITIES, "windows-material-iis-v1"] },
    { capabilities: [...subject.CAPABILITIES, "linux-material-staging-v1"] }]) {
    assert.throws(() => subject.verifyIdentity({ ...identity, ...patch }));
  }
});

test("isolated final manifest leaves source gates intact and preserves release formatting", t => {
  const f = fixture(t, { capabilities: subject.CAPABILITIES.slice(0, -1) });
  const input = path.join(f.source, "package/src/capabilities/qualified-capabilities.json");
  const original = fs.readFileSync(input, "utf8"), staging = path.join(f.root, "build");
  subject.materializeCandidate(path.join(f.source, "package"), staging);
  assert.equal(fs.readFileSync(input, "utf8"), original);
  assert.equal(fs.readFileSync(path.join(staging, "src/capabilities/qualified-capabilities.json"), "utf8"),
    JSON.stringify({ qualified: subject.CAPABILITIES }, null, 2) + "\n");
  fs.writeFileSync(input, JSON.stringify({ qualified: [...subject.CAPABILITIES, "windows-material-iis-v1"] }));
  assert.throws(() => subject.materializeCandidate(path.join(f.source, "package"), path.join(f.root, "foreign")));
});

test("archive and receipt accept only the exact final version, source and bytes", t => {
  const f = fixture(t);
  assert.equal(subject.inspect(f.directory, sha, f.digest).archive, f.file);
  for (const [source, digest] of [[otherSha, f.digest], [sha, "d".repeat(64)], [sha, ""]]) {
    assert.throws(() => subject.inspect(f.directory, source, digest));
  }
  for (const patch of [{ sourceKind: "local-worktree" }, { buildMode: "qualification-only-not-release" },
    { packageVersion: "0.19.0" }, { goVersion: "go1.27.3" }, { capabilitySource: "unreviewed" },
    { nodeVersion: "v24.18.0" }, { npmVersion: "11.6.2" }, { goFlags: "" }, { extra: "foreign" }]) {
    fs.writeFileSync(path.join(f.directory, "artifact.json"), JSON.stringify({ ...f.receipt, ...patch }));
    assert.throws(() => subject.inspect(f.directory, sha, f.digest));
  }
  fs.writeFileSync(path.join(f.directory, "artifact.json"), JSON.stringify(f.receipt));
  fs.writeFileSync(f.file + ".sha256", `${f.digest}  another.tgz\n`);
  assert.throws(() => subject.inspect(f.directory, sha, f.digest));
});

test("archive inspection rejects missing binaries, wrong version and wider gates", t => {
  for (const options of [{ omitBinary: true }, { version: "0.19.0" },
    { capabilities: subject.CAPABILITIES.slice(0, -1) },
    { capabilities: [...subject.CAPABILITIES, "windows-material-iis-v1"] }]) {
    const f = fixture(t, options);
    assert.throws(() => subject.inspect(f.directory, sha, f.digest));
  }
});

test("scoped collector binds same-run artifact bytes and all scenarios plus database and owned cleanup", t => {
  const f = fixture(t), e = evidence(f), output = path.join(f.root, "verdict.json");
  subject.collect(f.directory, e.directory, output, env(f));
  const verdict = JSON.parse(fs.readFileSync(output));
  assert.equal(verdict.status, "passed");
  assert.equal(verdict.providerScenarios.passed, 18);
  assert.deepEqual(verdict.packageArtifact, f.identity);
  assert.equal(verdict.productionQualified, false);
  assert.equal(verdict.fullOperatorE2e, false);
  assert.ok(verdict.unqualified.includes("full-http-operator-and-real-ca-e2e"));
  assert.ok(verdict.unqualified.includes("azure-imds-managed-identity"));
  fs.writeFileSync(path.join(f.directory, "artifact.json"), JSON.stringify({ ...f.receipt, sourceKind: "local-worktree" }));
  assert.throws(() => subject.collect(f.directory, e.directory, path.join(f.root, "local-rejected.json"), env(f)));
  assert.equal(fs.existsSync(path.join(f.root, "local-rejected.json")), false);
  fs.writeFileSync(path.join(f.directory, "artifact.json"), JSON.stringify(f.receipt));
  for (const patch of [{ GITHUB_SHA: otherSha }, { GITHUB_RUN_ID: "123" }, { GITHUB_RUN_ATTEMPT: "2" },
    { GITHUB_REF: "refs/heads/feature" }, { GITHUB_EVENT_NAME: "pull_request" },
    { CERTOPS_AZURE_KEYVAULT_LAB_ENABLED: "false" }, { TT_AZURE_PACKAGE_ARTIFACT_ID: "999" },
    { TT_AZURE_PACKAGE_SHA256: "e".repeat(64) }]) {
    assert.throws(() => subject.collect(f.directory, e.directory, path.join(f.root, "rejected.json"), { ...env(f), ...patch }));
  }
  assert.equal(fs.existsSync(path.join(f.root, "rejected.json")), false);
  for (const mutate of [() => { e.cleanup.cleanup = "failed"; }, () => { e.report.databaseCleanup = "failed"; },
    () => { e.report.productionQualified = true; }, () => { e.report.scenarios[0].status = "pending"; }]) {
    const report = structuredClone(e.report), cleanup = structuredClone(e.cleanup);
    mutate(); e.save();
    assert.throws(() => subject.collect(f.directory, e.directory, path.join(f.root, "rejected.json"), env(f)));
    Object.assign(e.report, report); Object.assign(e.cleanup, cleanup); e.save();
  }
  fs.writeFileSync(path.join(e.directory, "raw.log"), "foreign file");
  assert.throws(() => subject.collect(f.directory, e.directory, path.join(f.root, "rejected.json"), env(f)));
});

test("local bootstrap cannot run inside Actions or silently create trusted qualification evidence", t => {
  const f = fixture(t);
  const result = spawnSync(process.execPath, [__filename.replace(/\.test\.js$/, ".cjs"), "build-local", path.join(f.root, "unused")],
    { encoding: "utf8", timeout: 10000, windowsHide: true, env: { ...process.env, GITHUB_ACTIONS: "true" } });
  assert.equal(result.status, 1);
  assert.equal(result.stderr.trim(), "AZURE_KV_EXACT_PACKAGE_REJECTED");
  assert.equal(fs.existsSync(path.join(f.root, "unused")), false);
});

test("release CLI rejects absent or different qualified digest before publishing bytes", t => {
  const f = fixture(t);
  for (const digest of ["", "e".repeat(64)]) {
    const child = spawnSync(process.execPath, [__filename.replace(/\.test\.js$/, ".cjs"), "verify-release", f.file, digest],
      { encoding: "utf8", timeout: 10000, windowsHide: true });
    assert.equal(child.status, 1);
    assert.equal(child.stderr.trim(), "AZURE_KV_EXACT_PACKAGE_REJECTED");
    assert.equal(child.stdout, "");
  }
});
