"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const lab = require("../../infra/certops-azure-keyvault/lab");
const policy = require("../../infra/certops-azure-keyvault/policy");
const io = require("./helpers/azure-keyvault-live-io.cjs");
const { runNaturalExpiry, packageToken, applicationRetirementProbe, assertTokenFits, workDeadline, MAX_JOB_DURATION_MS, WINDOW_ERROR_CODES } = require("./helpers/azure-natural-token-expiry.cjs");
const { runBoundedWorker } = require("./helpers/azure-natural-token-supervisor.cjs");

const ID = /^[1-9][0-9]{0,15}$/;
const JOB = "natural-expiry";
const JOB_TIMEOUT_MS = MAX_JOB_DURATION_MS;
const CLEANUP_RESERVE_MS = 10 * 60000;
const APP_CLEANUP_RESERVE_MS = 15 * 60000;
const APPLICATION_CHECK = "expiry-app-ready.json";
const APPLICATION_RETIRED = "expiry-app-retired.json";
const STATE = "expiry-worker.json";
const PROFILE = "azure-natural-access-token-expiration";
const API = `/repos/${policy.REPOSITORY}/actions`;
const CLEANUP_FILE = "qualification-results/azure-keyvault-cleanup.json";
const packager = require("../../scripts/certops-agent-package");
const source = require("../../scripts/certops-final-package-source.cjs");

function expiryContext(env = process.env) {
  policy.requireTrusted(env);
  assert.equal(process.platform, "linux");
  assert.equal(env.GITHUB_JOB, JOB);
  assert.equal(env.GITHUB_RUN_ATTEMPT, "1");
  assert.match(env.GITHUB_RUN_ID, ID);
  assert.match(env.GITHUB_REPOSITORY_ID, ID);
  return env;
}

function expiryApplication(env) {
  const clientId = env.TT_AZURE_EXPIRY_APP_CLIENT_ID;
  const principalId = env.TT_AZURE_EXPIRY_APP_PRINCIPAL_ID;
  if (!clientId && !principalId) return null;
  assert.ok(policy.GUID.test(clientId || "") && policy.GUID.test(principalId || "") &&
    clientId.toLowerCase() !== env.AZURE_CLIENT_ID?.toLowerCase() &&
    clientId.toLowerCase() !== principalId.toLowerCase(), "AZURE_EXPIRY_EXTERNAL_READER_DENIED");
  return { clientId, principalId };
}

function workloadAuth(root, tenantId, clientId) {
  return { type: "workload-identity", tenantId, clientId, assertionFile: path.join(root, "assertion.jwt") };
}

function verifiedCandidate(root) {
  const candidateRoot = path.join(root, "expiry-extracted", "package");
  assert.deepEqual(packager.inventory(candidateRoot), lab.load(path.join(root, "expiry-package.json")).inventory);
  return candidateRoot;
}

function jobStart(run, page, { runId, repoId, sourceSha, now }) {
  source.verifyRun(run, runId, repoId);
  assert.equal(run.head_sha, sourceSha);
  assert.equal(run.status, "in_progress");
  const matching = source.verifyJobs(page).filter(job => job.name === JOB);
  assert.equal(matching.length, 1);
  const [job] = matching;
  assert.equal(String(job.run_id), runId);
  assert.equal(job.head_sha, sourceSha);
  assert.equal(job.status, "in_progress");
  const start = Date.parse(job.started_at);
  const runStart = Date.parse(run.run_started_at);
  assert.ok(Number.isSafeInteger(start) && Number.isSafeInteger(runStart) && start >= runStart && start <= now);
  return start;
}

async function activeRun(env) {
  return lab.github(`${API}/runs/${env.GITHUB_RUN_ID}`, env);
}

async function budgetFor(state, env, run) {
  const [page, group] = await Promise.all([
    lab.github(`${API}/runs/${env.GITHUB_RUN_ID}/attempts/1/jobs?per_page=100`, env),
    lab.verifyOwned(state, env),
  ]);
  assert.ok(group, "AZURE_EXPIRY_OWNED_GROUP_MISSING");
  const now = Date.now();
  const start = jobStart(run, page, { runId: env.GITHUB_RUN_ID, repoId: env.GITHUB_REPOSITORY_ID, sourceSha: env.GITHUB_SHA, now });
  return { jobDeadlineMs: start + JOB_TIMEOUT_MS, resourceDeadlineMs: Date.parse(group.tags.expiresAt),
    cleanupReserveMs: expiryApplication(env) ? APP_CLEANUP_RESERVE_MS : CLEANUP_RESERVE_MS };
}

async function stagePackage() {
  const env = expiryContext(), root = lab.privateRoot(env);
  const files = path.join(root, "expiry-candidate");
  const identity = await source.main(env.TT_AZURE_EXPIRY_PACKAGE_RUN_ID, env.TT_AZURE_EXPIRY_PACKAGE_ARTIFACT_ID,
    env.TT_AZURE_PACKAGE_SHA256, files, env);
  const extracted = packager.extractVerified({ tarball: path.join(files, "tokentimer-agent-0.20.0.tgz"),
    expectedSha256: identity.packageSha256, destination: path.join(root, "expiry-extracted") });
  lab.save(path.join(root, "expiry-package.json"), { identity, inventory: extracted.files });
}

async function checkApplication() {
  const env = expiryContext(), application = expiryApplication(env);
  if (!application) return;
  const root = lab.privateRoot(env);
  const candidateRoot = verifiedCandidate(root);
  const [run, page] = await Promise.all([activeRun(env), lab.github(`${API}/runs/${env.GITHUB_RUN_ID}/attempts/1/jobs?per_page=100`, env)]);
  const now = Date.now(), plan = policy.plan(env, now);
  const start = jobStart(run, page, { runId: env.GITHUB_RUN_ID, repoId: env.GITHUB_REPOSITORY_ID, sourceSha: env.GITHUB_SHA, now });
  const budget = { jobDeadlineMs: start + JOB_TIMEOUT_MS, resourceDeadlineMs: Date.parse(plan.tags.expiresAt),
    cleanupReserveMs: APP_CLEANUP_RESERVE_MS };
  workDeadline(budget, now);
  await io.assertion(root);
  const acquire = packageToken(candidateRoot, { auth: workloadAuth(root, plan.tenantId, application.clientId) });
  let token;
  await io.eventually(async () => {
    token = await acquire();
    return true;
  }, "AZURE_EXPIRY_EXTERNAL_READER_NOT_READY", 90000);
  // Leave a measured setup allowance before permitting allocation. The worker
  // independently checks the token it will actually observe before any write.
  assertTokenFits(token, now, Date.now(), { ...budget, cleanupReserveMs: budget.cleanupReserveMs + 5 * 60000 });
  lab.save(path.join(root, APPLICATION_CHECK), application);
  console.log("AZURE_EXPIRY_APPLICATION_FITS_LAB_WINDOW");
}

function ownedState(root, env) {
  const state = lab.load(path.join(root, "state.json"));
  lab.assertPlan(state);
  assert.equal(state.tags.runId, env.GITHUB_RUN_ID);
  assert.equal(state.tags.attempt, env.GITHUB_RUN_ATTEMPT);
  assert.equal(state.tags.sourceSha, env.GITHUB_SHA);
  return state;
}

function workerBudget(env) {
  const budget = { jobDeadlineMs: Number(env.TT_EXPIRY_JOB_DEADLINE_MS),
    resourceDeadlineMs: Number(env.TT_EXPIRY_RESOURCE_DEADLINE_MS), cleanupReserveMs: Number(env.TT_EXPIRY_CLEANUP_RESERVE_MS) };
  assert.equal(workDeadline(budget, Date.now()), Number(env.TT_EXPIRY_WORK_DEADLINE_MS));
  return budget;
}

// This worker uses the verified package with no fault injector. All subprocesses
// (the existing ARM CLI and OpenSSL helpers) inherit its supervised process group.
async function observe() {
  const env = expiryContext(), root = lab.privateRoot(env), budget = workerBudget(env);
  const state = ownedState(root, env);
  assert.equal(lab.load(path.join(root, STATE)).drained, false);
  assert.equal(env.AZURE_CONFIG_DIR, path.join(root, "azure-cli"));
  let armLoginAt = Date.now();
  async function verifyOwned() {
    if (Date.now() - armLoginAt > 40 * 60000) {
      // The provisioner's ARM access can expire while we retain the separate
      // Key Vault token. Refresh ARM access before the ownership checkpoint.
      const login = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-File",
        path.resolve(__dirname, "../../infra/certops-adcs/login-oidc.ps1")],
      { stdio: "ignore", timeout: 120000 });
      assert.equal(login.status, 0, "AZURE_EXPIRY_ARM_REAUTH_FAILED");
      armLoginAt = Date.now();
    }
    const group = await lab.verifyOwned(state, env);
    assert.ok(group && Date.parse(group.tags.expiresAt) === budget.resourceDeadlineMs);
    workDeadline(budget, Date.now());
  }
  await verifyOwned();
  assert.match(state.identities.issuer.clientId, policy.GUID);
  const application = expiryApplication(env);
  if (application) assert.deepEqual(lab.load(path.join(root, APPLICATION_CHECK)), application);
  const candidateRoot = verifiedCandidate(root);
  const { createMaterialStore } = require(path.join(candidateRoot, "src/material-store"));
  const { credential } = require(path.join(candidateRoot, "src/material-store/azure"));
  const { requestJson } = require(path.join(candidateRoot, "src/material-store/transport"));
  const intent = { workspaceId: crypto.randomUUID(), groupId: crypto.randomUUID(),
    materialVersionId: crypto.randomUUID(), materialStoreRef: "qualification", provider: "azure-key-vault" };
  const sans = ["valid.example.com", "www.valid.example.com"];
  const config = { provider: intent.provider, address: `https://${state.vault}.vault.azure.net`,
    timeoutMs: 15000, auth: workloadAuth(root, state.tenantId, state.identities.issuer.clientId),
    groups: { [intent.groupId]: { workspaceId: intent.workspaceId, prefix: `qualification/${intent.workspaceId}/${intent.groupId}`,
      keyAlgorithm: "rsa", sans } } };
  let issued = await io.assertion(root);
  const token = credential(config, config.timeoutMs);
  await io.eventually(async () => {
    workDeadline(budget, Date.now());
    if (issued.expiresAt < Date.now() + 120000) issued = await io.assertion(root);
    try {
      const response = await requestJson(new URL("/secrets?api-version=7.4&maxresults=1", config.address),
        { timeoutMs: config.timeoutMs, headers: { Authorization: `Bearer ${await token(true)}` } });
      return response.status === 200;
    } catch {
      return false;
    }
  }, "AZURE_KV_ISSUER_RBAC_OR_FEDERATION_NOT_READY_AT_RUN_VAULT");
  const issuerStore = createMaterialStore({ qualification: config }, intent);
  const readConfig = application ? { ...config, auth: workloadAuth(root, state.tenantId, application.clientId) } : config;
  const store = application ? createMaterialStore({ qualification: readConfig }, intent) : issuerStore;
  await io.assertion(root);
  return runNaturalExpiry({ candidateRoot, config: readConfig, store, budget,
    async prepareVersion() {
      const [material] = io.makeMaterial(root);
      const { workspaceId, groupId, materialVersionId } = intent;
      await verifyOwned();
      const receipt = await issuerStore.publish({ ...material, workspaceId, groupId, materialVersionId, schemaVersion: 1,
        sans, fingerprintSha256: io.verifyMaterial(material) });
      if (application) {
        assert.equal(store.objectRef, issuerStore.objectRef);
        state.approvedSecrets = [store.objectRef];
        lab.save(path.join(root, "state.json"), state);
        await lab.consumerAccess(state, state.approvedSecrets, true, env, application.principalId);
        await io.eventually(async () => {
          workDeadline(budget, Date.now());
          await store.fetch(receipt.providerVersion);
          return true;
        }, "AZURE_EXPIRY_EXTERNAL_READER_GRANT_NOT_READY", 180000);
      }
      return receipt.providerVersion;
    },
    renewAssertion: () => io.assertion(root), verifyOwned });
}

async function launch() {
  const env = expiryContext(), root = lab.privateRoot(env), state = ownedState(root, env);
  const run = await activeRun(env), budget = await budgetFor(state, env, run);
  workDeadline(budget, Date.now());
  const file = path.join(root, STATE);
  assert.ok(!fs.existsSync(file), "AZURE_EXPIRY_WORKER_REUSE_DENIED");
  const controller = new AbortController();
  const abort = () => controller.abort();
  process.once("SIGTERM", abort);
  process.once("SIGINT", abort);
  try {
    lab.save(file, { drained: false });
    const facts = await runBoundedWorker({ workerPath: __filename, budget, signal: controller.signal,
      onDrained: () => lab.save(file, { drained: true }) });
    lab.save(path.join(root, "expiry-observation.json"), { budget, facts });
  } finally {
    process.removeListener("SIGTERM", abort);
    process.removeListener("SIGINT", abort);
  }
}

function requireDrain(marker) {
  assert.ok(marker === undefined || marker?.drained === true, "AZURE_EXPIRY_DRAIN_UNVERIFIED");
}

async function cleanup() {
  const env = expiryContext(), root = lab.privateRoot(env), file = path.join(root, STATE);
  requireDrain(fs.existsSync(file) ? lab.load(file) : undefined);
  const state = fs.existsSync(path.join(root, "state.json")) ? ownedState(root, env) : null;
  await lab.cleanup(env);
  if (state) {
    const present = lab.arm("GET", lab.groupId(state) + "?api-version=2022-09-01", undefined, undefined, true);
    assert.equal(present, null, "AZURE_EXPIRY_TEARDOWN_UNVERIFIED");
  }
  lab.save(path.join(root, "expiry-cleanup-confirmed.json"), { confirmed: true });
}

async function confirmApplicationRetired() {
  const env = expiryContext(), application = expiryApplication(env);
  assert.ok(application, "AZURE_EXPIRY_EXTERNAL_READER_DENIED");
  const root = lab.privateRoot(env);
  assert.deepEqual(lab.load(path.join(root, APPLICATION_CHECK)), application);
  assert.equal(lab.load(path.join(root, "expiry-cleanup-confirmed.json")).confirmed, true);
  const { budget } = lab.load(path.join(root, "expiry-observation.json"));
  const deadline = Math.min(Date.now() + 4 * 60000, budget.jobDeadlineMs, budget.resourceDeadlineMs);
  const config = { auth: workloadAuth(root, env.AZURE_TENANT_ID, application.clientId) };
  const isRetired = applicationRetirementProbe(verifiedCandidate(root), config);
  await io.assertion(root);
  while (Date.now() + 15000 < deadline) {
    // Only an explicit application-not-found response counts. Timeouts and
    // other authentication errors do not establish retirement.
    if (await isRetired()) {
      lab.save(path.join(root, APPLICATION_RETIRED), application);
      return;
    }
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  throw new Error("AZURE_EXPIRY_APPLICATION_RETIREMENT_UNVERIFIED");
}

function finalize() {
  const env = expiryContext(), root = lab.privateRoot(env), observationFile = path.join(root, "expiry-observation.json");
  const marker = path.join(root, STATE);
  requireDrain(fs.existsSync(marker) ? lab.load(marker) : undefined);
  let report, hardDeadline;
  try {
    if (fs.existsSync(observationFile)) {
      requireDrain(lab.load(path.join(root, STATE)));
      assert.equal(lab.load(path.join(root, "expiry-cleanup-confirmed.json")).confirmed, true);
      const cleanup = JSON.parse(fs.readFileSync(CLEANUP_FILE, "utf8"));
      require("../../scripts/certops-azure-keyvault-report").verifyCleanup(cleanup, env.GITHUB_SHA);
      assert.equal(cleanup.cleanup, "completed");
      const application = expiryApplication(env);
      if (application) assert.deepEqual(lab.load(path.join(root, APPLICATION_RETIRED)), application);
      const { budget, facts } = lab.load(observationFile);
      const { PROFILES } = require("../../scripts/certops-final-package-evidence.cjs");
      const packageArtifact = require("../../scripts/certops-azure-keyvault-package.cjs")
        .verifyIdentity(lab.load(path.join(root, "expiry-package.json")).identity);
      const scenarios = PROFILES[PROFILE].scenarios.map(id => ({ id, status: "passed" }));
      hardDeadline = Math.min(budget.jobDeadlineMs, budget.resourceDeadlineMs);
      // This profile starts no database or agent service. The owned vault and
      // its identities were checked absent, and the private fixture is scrubbed below.
      report = { schemaVersion: 1, profile: PROFILE, sourceSha: env.GITHUB_SHA, runId: env.GITHUB_RUN_ID,
        packageArtifact, status: "passed", productionQualified: false, fullOperatorE2e: false,
        counts: { passed: scenarios.length, failed: 0, pending: 0, skipped: 0 }, scenarios,
        cleanup: { database: "completed", provider: "completed", agent: "completed", credentials: "completed", resources: "completed" },
        facts, nativeService: null };
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    assert.ok(!fs.existsSync(root), "AZURE_EXPIRY_PRIVATE_TEARDOWN_UNVERIFIED");
  }
  if (report) {
    assert.ok(Date.now() < hardDeadline);
    fs.mkdirSync("qualification-results", { recursive: true });
    fs.writeFileSync("qualification-results/azure-natural-expiration-final-package.json", JSON.stringify(report) + "\n", { flag: "wx" });
  }
}

module.exports = { jobStart, workerBudget, requireDrain, expiryApplication, JOB_TIMEOUT_MS, CLEANUP_RESERVE_MS };
if (require.main === module) {
  if (process.send) {
    observe().then(
      facts => process.send(facts, () => process.exit(0)),
      error => process.send({ failure: WINDOW_ERROR_CODES.includes(error.code) ?
        error.code : "AZURE_EXPIRY_WORKER_FAILED" }, () => process.exit(1)),
    );
  } else {
    const actions = { "stage-package": stagePackage, "check-application": checkApplication,
      launch, cleanup, "confirm-application-retired": confirmApplicationRetired, finalize };
    Promise.resolve().then(() => {
      assert.ok(Object.hasOwn(actions, process.argv[2]));
      return actions[process.argv[2]]();
    }).catch(error => {
      const reason = [error.code, error.message].find(value => /^AZURE_(?:EXPIRY|KV)_[A-Z0-9_]{1,180}$/.test(value));
      console.error(reason || "AZURE_EXPIRY_OPERATION_REFUSED");
      process.exitCode = 1;
    });
  }
}
