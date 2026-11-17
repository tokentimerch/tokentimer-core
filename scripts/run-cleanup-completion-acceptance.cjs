"use strict";

// Independent disposable PostgreSQL and KV v2 store. Never loads .env, never
// connects to an old lab, and removes only containers carrying this run's label.
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const root = path.resolve(__dirname, "..");
const nativeVault = process.argv.includes("--native-vault-restart");
const nativeOpenBao = process.argv.includes("--native-openbao-restart");
const cleanupVault = process.argv.includes("--cleanup-native-vault");
const cleanupOpenBao = process.argv.includes("--cleanup-native-openbao");
const nativeStaging = process.argv.includes("--native-staging");
const cleanupStaging = process.argv.includes("--cleanup-native-staging");
const openbao = process.argv.includes("--openbao") || nativeOpenBao || cleanupOpenBao;
const staging = nativeStaging || cleanupStaging;
const cleanupCase = require("./certops-linux-cleanup-case.cjs")(openbao ? "openbao-kv2" : "vault-kv2", staging);
const { provider, store, suite, testName, proofField } = cleanupCase;
const keepLab = process.argv.includes("--keep-lab");
const native = nativeVault || nativeOpenBao || nativeStaging;
const cleanupNative = cleanupVault || cleanupOpenBao || cleanupStaging;
function validateNativePreconditions() {
 if (!(native || cleanupNative)) return;
  const assert = require("node:assert/strict");
  require("./certops-linux-systemd-ownership").validateHostedEnvironment(process.env);
  assert.equal(process.platform, "linux");
  assert.equal(process.getuid(), 0);
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  assert.equal([nativeVault, nativeOpenBao, cleanupVault, cleanupOpenBao, nativeStaging, cleanupStaging].filter(Boolean).length, 1);
  assert.equal(openbao, nativeOpenBao || cleanupOpenBao);
  assert.equal(keepLab, false);
  assert.match(process.env.GITHUB_RUN_ID || "", /^[1-9]\d{0,15}$/);
  assert.match(process.env.GITHUB_RUN_ATTEMPT || "", /^[1-9]\d{0,7}$/);
  if (native) {
    assert.match(process.env.TT_CLEANUP_ARTIFACT_ID || "", /^[1-9]\d{0,15}$/);
    assert.match(process.env.TT_CLEANUP_ARTIFACT_SHA256 || "", /^[a-f0-9]{64}$/);
  }
}
const nonce = native || cleanupNative
  ? crypto.createHash("sha256").update(`linux-${staging ? "staging" : store}:${process.env.GITHUB_RUN_ID}:${process.env.GITHUB_RUN_ATTEMPT}`).digest("hex").slice(0, 16)
  : crypto.randomBytes(8).toString("hex");
const output = path.join(root, "qualification-results", `cleanup-completion-${nonce}`);
const failureReport = path.join(root, "qualification-results", suite.replace(/-restart$/, "-failure.json"));
let nativeStage = "preconditions";

function recordNativeFailure(error) {
  if (!native) return;
  const existing = fs.lstatSync(failureReport, { throwIfNoEntry: false });
  if (existing?.isSymbolicLink()) throw new Error("Failure report path is not owned");
  if (existing?.size) return;
  const directory = path.dirname(failureReport);
  fs.mkdirSync(directory, { recursive: true });
  if (fs.lstatSync(directory).isSymbolicLink()) throw new Error("Failure report directory is not owned");
  const exitCode = Number.isInteger(error.exitCode) && error.exitCode >= 0 && error.exitCode <= 255 ? error.exitCode : null;
  fs.writeFileSync(failureReport, JSON.stringify({
    schemaVersion: 1, suite, status: "failed",
    failures: [{ stage: nativeStage, category: exitCode === null ? "prerequisite-or-check-failed" : "child-exit", exitCode }],
  }) + "\n");
}

function fixtureState(container) {
  const result = spawnSync("docker", ["inspect", "--format", "{{json .State}}", container],
    { encoding: "utf8", windowsHide: true, timeout: 10000 });
  if (result.status !== 0) return { container, inspected: false };
  const state = JSON.parse(result.stdout);
  return { container, status: state.Status, oomKilled: state.OOMKilled, exitCode: state.ExitCode, error: state.Error };
}

function run(command, args, { env = process.env, log, timeout = 180000 } = {}) {
  const result = spawnSync(command, args, { cwd: root, env, encoding: "utf8", windowsHide: true,
    timeout, maxBuffer: 32 * 1024 * 1024 });
  if (log) fs.writeFileSync(path.join(output, log), (result.stdout || "") + (result.stderr || ""));
  if (result.status !== 0 || result.error) {
    const error = new Error(`${command} failed; ${log ? `diagnostics: ${path.join(output, log)}` : "owned fixture command failed"}`);
    error.exitCode = result.status;
    throw error;
  }
  return result.stdout;
}

function cleanupNativeRun() {
  const assert = require("node:assert/strict");
  require("./certops-linux-systemd-cleanup").cleanup();
  require("./certops-linux-systemd-ownership").assertHostReceiptRemoved(process.env.RUNNER_TEMP);
  const label = `tokentimer.cleanup-completion-owner=${nonce}`;
  const names = run("docker", ["ps", "-a", "--filter", `label=${label}`, "--format", "{{.Names}}"]).trim().split(/\r?\n/).filter(Boolean);
  for (const name of names) {
    assert.ok([`tt-cleanup-pg-${nonce}`, `tt-cleanup-vault-${nonce}`].includes(name));
    assert.equal(run("docker", ["inspect", "--format", '{{index .Config.Labels "tokentimer.cleanup-completion-owner"}}', name]).trim(), nonce);
    run("docker", ["rm", "--force", "--volumes", name]);
  }
  assert.equal(run("docker", ["ps", "-a", "--filter", `label=${label}`, "--format", "{{.Names}}"]).trim(), "");
}

async function main() {
  const containers = [];
  let nativeFacts;
  const summary = { schemaVersion: 1, scope: native ? suite : "cleanup-completion-functional-support", nativeAgentQualified: false,
    provider, candidateSha: run("git", ["rev-parse", "HEAD"]).trim(), dirty: Boolean(run("git", ["status", "--porcelain"]).trim()),
    startedAt: new Date().toISOString(), status: "running", logs: ["migration.log", "tests.log"] };
  if (native && (summary.dirty || summary.candidateSha !== process.env.GITHUB_SHA)) {
    throw new Error("Native cleanup requires a clean trusted-main checkout at the candidate SHA");
  }
  try {
    nativeStage = "ownership-preflight";
    if (native) run(process.execPath, ["--test", "scripts/certops-linux-systemd-db-ownership.test.js"], { log: "ownership-preflight.log", timeout: 60000 });
    nativeStage = "fixture-startup";
    const pg = `tt-cleanup-pg-${nonce}`, vault = `tt-cleanup-vault-${nonce}`;
    const database = `distribution_lifecycle_${nonce}_test`;
    for (const [name, args] of [
      [pg, ["--memory=512m", "-p", "127.0.0.1::5432", "-e", "POSTGRES_USER=certops_fixture", "-e",
        "POSTGRES_PASSWORD=synthetic-completion-only", "-e", `POSTGRES_DB=${database}`, "postgres:16-alpine"]],
      // Vault 1.21 dev was OOM-killed at 384m on GitHub-hosted runners before health returned.
      [vault, ["--memory=1024m", "-p", "127.0.0.1::8200", "-e", `${provider === "openbao-kv2" ? "BAO" : "VAULT"}_DEV_ROOT_TOKEN_ID=isolated-completion-fixture-only`,
        provider === "openbao-kv2" ? "openbao/openbao:2.4.1" : "hashicorp/vault:1.21", "server", "-dev", "-dev-listen-address=0.0.0.0:8200"]],
    ]) {
      run("docker", ["run", "-d", "--name", name, "--label", `tokentimer.cleanup-completion-owner=${nonce}`, ...args]);
      containers.push(name);
    }
    const port = name => {
      const result = run("docker", ["port", name]).match(/-> 127\.0\.0\.1:(\d+)/)?.[1];
      if (!result) throw new Error("Owned loopback port unavailable");
      return result;
    };
    const pgPort = port(pg), vaultAddress = `http://127.0.0.1:${port(vault)}`;
    let ready = false;
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
      const pgReady = spawnSync("docker", ["exec", pg, "pg_isready", "-h", "127.0.0.1", "-U", "certops_fixture"],
        { windowsHide: true, stdio: "ignore", timeout: 10000 }).status === 0;
      let vaultReady = false;
      try { vaultReady = (await fetch(`${vaultAddress}/v1/sys/health`, { signal: AbortSignal.timeout(2000) })).status === 200; } catch { /* startup */ }
      if (pgReady && vaultReady) { ready = true; break; }
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    if (!ready) {
      const states = containers.map(fixtureState);
      const detail = states.map(state => state.inspected === false
        ? `${state.container}:uninspected`
        : `${state.container}:${state.status}${state.oomKilled ? ",oom" : ""}`).join("; ");
      const error = new Error(`Owned PostgreSQL/Vault startup failed (${detail})`);
      error.fixtureStates = states;
      throw error;
    }
    const env = { ...process.env, NODE_ENV: "test", CERTOPS_ENABLED: "true", CERTOPS_MATERIAL_CLEANUP_ENABLED: staging ? "false" : "true",
      DB_HOST: "127.0.0.1", DB_PORT: pgPort, DB_NAME: database, DB_USER: "certops_fixture", DB_PASSWORD: "synthetic-completion-only",
      CERTOPS_SIGNING_ENCRYPTION_KEY: crypto.randomBytes(32).toString("hex"), CERTOPS_REGISTRATION_ENCRYPTION_KEY: crypto.randomBytes(32).toString("hex"),
      TT_CLEANUP_COMPLETION_DISPOSABLE: "1", TT_CLEANUP_VAULT_ADDRESS: vaultAddress, TT_CLEANUP_PROVIDER: provider, TT_CLEANUP_EVIDENCE_DIR: output };
    if (keepLab) {
      const config = path.join(root, ".tmp", `cleanup-ui-${nonce}`, "private.json");
      require("../packages/agent/src/material-store/index").writeProtectedJson(config, {
        owner: nonce, containers: [...containers], env: Object.fromEntries(Object.entries(env).filter(([key]) =>
          key.startsWith("DB_") || key.startsWith("CERTOPS_") || key.startsWith("TT_CLEANUP_") || key === "NODE_ENV")), output,
      });
      summary.retainedLabConfig = config;
    }
    nativeStage = "migration";
    run(process.execPath, ["apps/api/migrations/migrate.js"], { env, log: "migration.log" });
    const tests = native ? ["tests/e2e/certops-agent-e2e.test.js"] :
      ["tests/postgres/distribution-cleanup.test.js", "tests/postgres/distribution-cleanup-provider.test.js"];
    const args = ["--test", "--test-force-exit", "--test-concurrency=1"];
    if (native) {
      Object.assign(env, { TT_CLEANUP_NATIVE_VAULT: nativeVault ? "1" : "0", TT_CLEANUP_NATIVE_OPENBAO: nativeOpenBao ? "1" : "0", CERTOPS_E2E_REQUIRED: "1",
        TT_CLEANUP_NATIVE_STAGING: nativeStaging ? "1" : "0", CERTOPS_PROTOCOL_DISPOSABLE_STACK: "1", CERTOPS_CSR_DISPOSABLE_STACK: "1" });
      const reporter = pathToFileURL(path.join(__dirname, "certops-linux-vault-cleanup-failure.cjs")).href;
      args.push("--test-reporter=tap", "--test-reporter-destination=stdout",
        `--test-reporter=${reporter}`, `--test-reporter-destination=${failureReport}`,
        `--test-name-pattern=${testName}`);
    }
    args.push(...tests);
    summary.tests = tests;
    summary.command = `node ${args.join(" ")}`;
    nativeStage = "installed-case";
    const log = run(process.execPath, args, { env, log: "tests.log", timeout: 300000 });
    nativeStage = "verify-evidence";
    if (native) fs.rmSync(failureReport, { force: true });
    summary.status = "passed";
    const counts = {};
    for (const key of ["tests", "pass", "fail", "skipped", "cancelled"]) {
      const value = log.match(new RegExp(`(?:ℹ|#) ${key} (\\d+)`))?.[1];
      if (value !== undefined) counts[key] = Number(value);
    }
    summary.counts = counts;
    if (native) {
      const assert = require("node:assert/strict");
      assert.equal(counts.tests, 1);
      assert.equal(counts.pass, 1);
      assert.equal(counts.skipped, 0);
      nativeFacts = JSON.parse(fs.readFileSync(path.join(output, "native-facts.json"), "utf8"));
      if (nativeOpenBao) assert.equal(nativeFacts.provider, provider);
      assert.equal(nativeFacts.artifactId, process.env.TT_CLEANUP_ARTIFACT_ID);
      assert.equal(nativeFacts.packageSha256, process.env.TT_CLEANUP_ARTIFACT_SHA256);
      assert.equal(nativeFacts.installedTreeVerified, true);
      if (nativeStaging) {
        assert.equal(nativeFacts.provider, provider);
        assert.equal(nativeFacts.authenticatedAttempts, 1);
        assert.equal(nativeFacts.authenticatedReads, 1);
        assert.equal(nativeFacts.destinationMutations, 0);
        for (const fact of ["stagedAcrossRestart", "activationBlocked", "destinationUnchanged"]) assert.equal(nativeFacts[fact], true);
      } else {
        assert.equal(nativeFacts.actualDeleteRequests, 1);
        assert.equal(nativeFacts.authenticatedAttempts, 2);
      }
    } else console.log(log);
  } catch (error) {
    summary.status = "failed";
    recordNativeFailure(error);
    summary.failure = error.message;
    // Provider dev-server logs include bootstrap credentials. Export only
    // container state so startup/resource failures are diagnosable safely.
    summary.fixtureStates = error.fixtureStates || containers.map(fixtureState);
    throw error;
  } finally {
    if (native) {
      nativeStage = "teardown";
      cleanupNativeRun();
    }
    for (const container of native ? [] : [...containers].reverse()) {
      const owner = run("docker", ["inspect", "--format", '{{index .Config.Labels "tokentimer.cleanup-completion-owner"}}', container]).trim();
      if (owner !== nonce) throw new Error("Fixture ownership changed; refusing container removal");
      if (!keepLab) run("docker", ["rm", "--force", "--volumes", container]);
    }
    summary.finishedAt = new Date().toISOString();
    summary.cleanup = keepLab ? "owned-fixtures-retained-for-operator-ui" : "passed";
    fs.writeFileSync(path.join(output, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
    if (native && summary.status === "passed" && nativeFacts) {
      nativeStage = "write-receipt";
      const osRelease = fs.readFileSync("/etc/os-release", "utf8");
      require("node:assert/strict").match(osRelease, /^VERSION_ID="?24\.04"?$/m);
      require("node:assert/strict").match(osRelease, /^ID=ubuntu$/m);
      require("node:assert/strict").equal(process.arch, "x64");
      require("node:assert/strict").ok(process.report.getReport().header.glibcVersionRuntime);
      const matrix = require("./certops-qualification-manifest");
      const { source, requiredSources } = matrix.slots.find(slot => slot.id === (staging ? suite : "linux-vault-cleanup-restart"));
      const sourceRecord = file => ({ file, sha256: require("./certops-agent-package").digest(path.join(root, file)) });
      fs.writeFileSync(path.join(root, "qualification-results", suite + ".json"), JSON.stringify({
        schemaVersion: 1, suite, strict: true, status: "passed", evidenceLevel: "real-host",
        candidateSha: summary.candidateSha, fixtureSource: sourceRecord(source), fixtureSources: requiredSources.map(sourceRecord),
        artifactQualification: "workflow-checkout-source", platform: "linux", architecture: "x64",
        qualificationEnvironment: { measurement: "native", osFamily: "linux", distributionId: "ubuntu",
          distributionVersion: "24.04", executionSurface: "host", libc: "glibc" },
        startedAt: summary.startedAt, finishedAt: summary.finishedAt, requiredCapabilities: ["linux", "systemd"],
        capabilities: { linux: { available: true }, systemd: { available: true } },
        missingCapabilities: [], requiredScenarios: [suite], missingScenarios: [],
        scenarios: [{ id: suite, status: "passed", evidenceLevel: "real-host", startedAt: summary.startedAt, finishedAt: summary.finishedAt }],
        cleanup: { status: "passed" }, [proofField]: nativeFacts,
      }), { flag: "wx" });
    }
    console.log(`Cleanup completion evidence: ${output}`);
  }
}

Promise.resolve().then(() => {
  validateNativePreconditions();
  if (!cleanupNative) fs.mkdirSync(output, { recursive: true });
  nativeStage = "checkout";
  return cleanupNative ? cleanupNativeRun() : main();
})
  .catch(error => {
    if (native) {
      try { recordNativeFailure(error); } catch { console.error("Installed cleanup diagnostic unavailable"); }
      console.error(`Installed cleanup qualification failed. See ${path.basename(failureReport)} for diagnostic details.`);
    } else console.error(error.message);
    process.exitCode = 1;
  });
