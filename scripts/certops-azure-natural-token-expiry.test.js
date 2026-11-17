"use strict";
// Register the helper contracts in the canonical CertOps tooling inventory.
// These fixtures never produce trusted qualification or an acceptance receipt.
require("../tests/e2e/helpers/azure-natural-token-expiry.test.cjs");
require("../tests/e2e/helpers/azure-natural-token-supervisor.test.cjs");
const test = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), os = require("node:os");
const expiry = require("../tests/e2e/helpers/azure-natural-token-expiry.cjs");
const { runBoundedWorker } = require("../tests/e2e/helpers/azure-natural-token-supervisor.cjs");
const launcher = require("../tests/e2e/azure-keyvault-natural-expiry.cjs");
const policy = require("../infra/certops-azure-keyvault/policy");
const source = require("./certops-final-package-source.cjs");

test("the public expiry helper rejects a missing budget before touching scope or credentials", async () => {
  let accessed = false;
  const config = { get address() { accessed = true; throw new Error("unexpected credential/scope access"); } };
  await assert.rejects(expiry.runNaturalExpiry({ candidateRoot: path.resolve("missing-candidate"), config,
    renewAssertion: async () => { accessed = true; }, verifyOwned: async () => { accessed = true; } }),
  { code: "AZURE_EXPIRY_BUDGET_INVALID" });
  assert.equal(accessed, false);
});

test("supervisor forwards the same absolute budget and reserved work deadline to its worker", async t => {
  const base = fs.realpathSync(os.tmpdir()), root = fs.mkdtempSync(path.join(base, "tt-expiry-budget-contract-"));
  assert.equal(path.dirname(root), base);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const worker = path.join(root, "worker.cjs"), observed = path.join(root, "observed.json"), now = Date.now();
  const budget = { jobDeadlineMs: now + 610000, resourceDeadlineMs: now + 1200000, cleanupReserveMs: 600000 };
  const facts = { issuedAt: 1700000000, expiresAt: 1700000060, observedExpiredAt: 1700000060,
    renewedAt: 1700000061, renewedExpiresAt: 1700000121, azureStatusBefore: 200, azureStatusExpired: 401,
    azureStatusAfter: 200, forced401: false, clockOverridden: false, pinnedVersion: "a".repeat(32) };
  fs.writeFileSync(worker, `const fs=require("node:fs"); fs.writeFileSync(${JSON.stringify(observed)}, JSON.stringify({
    jobDeadlineMs:Number(process.env.TT_EXPIRY_JOB_DEADLINE_MS),resourceDeadlineMs:Number(process.env.TT_EXPIRY_RESOURCE_DEADLINE_MS),
    cleanupReserveMs:Number(process.env.TT_EXPIRY_CLEANUP_RESERVE_MS),workDeadlineMs:Number(process.env.TT_EXPIRY_WORK_DEADLINE_MS)}));
    process.send(${JSON.stringify(facts)},()=>process.exit(0));`);
  let drained = false;
  const work = runBoundedWorker({ workerPath: worker, budget, onDrained: () => { drained = true; } });
  if (process.platform === "linux") assert.deepEqual(await work, facts);
  else await assert.rejects(work, { message: "AZURE_EXPIRY_DRAIN_UNVERIFIED" });
  assert.equal(drained, process.platform === "linux");
  assert.deepEqual(JSON.parse(fs.readFileSync(observed, "utf8")), { ...budget,
    workDeadlineMs: Math.min(budget.jobDeadlineMs, budget.resourceDeadlineMs) - budget.cleanupReserveMs });
});

const repoId = "94", sourceSha = "b".repeat(40), runId = "120", artifactId = "134";
const earlier = "2026-10-10T11:58:00Z", started = "2026-10-10T12:00:00Z", now = Date.parse("2026-10-10T12:12:00Z");
const run = { id: 120, path: policy.WORKFLOW, event: "workflow_dispatch", head_branch: "main",
  run_attempt: 1, head_repository: { id: 94 }, repository: { id: 94 }, head_sha: sourceSha, run_started_at: earlier };
const current = { name: "natural-expiry", run_id: 120, head_sha: sourceSha, status: "in_progress", started_at: started };
const collector = { ...current, name: "collect-final-package", status: "completed", conclusion: "success" };
const artifact = { id: 134, name: "azure-release-candidate", expired: false,
  workflow_run: { id: 120, head_sha: sourceSha, repository_id: 94, head_repository_id: 94, head_branch: "main" },
  digest: `sha256:${"a".repeat(64)}`, size_in_bytes: 1234 };
const page = (...jobs) => ({ total_count: jobs.length, jobs });

test("uses the authenticated current attempt's job start, never the workflow start or launch time", () => {
  const input = { runId, repoId, sourceSha, now };
  const active = { ...run, status: "in_progress" };
  assert.equal(launcher.jobStart(active, page(current), input), Date.parse(started));
  for (const mismatched of [{ name: "lab" }, { run_id: 135 }, { status: "queued" }, { started_at: null },
    { started_at: "2026-10-10T12:13:00Z" }, { started_at: "2026-10-10T11:55:00Z" }, { head_sha: "a".repeat(40) }])
    assert.throws(() => launcher.jobStart(active, page({ ...current, ...mismatched }), input));
  assert.throws(() => launcher.jobStart(active, page(current, current), input));
  assert.throws(() => launcher.jobStart({ ...active, run_attempt: 2 }, page(current), input));
  assert.throws(() => launcher.jobStart(active, { ...page(current), total_count: 101 }, input));
});

test("requires the exact artifact of a successful trusted provider collector", () => {
  const input = { runId, artifactId, repoId };
  const completed = { ...run, status: "completed", conclusion: "success" };
  assert.equal(source.verifyProducer(completed, page(collector), artifact, input), sourceSha);
  for (const difference of [{ expired: true }, { id: 135 }, { name: "other" }, { digest: null },
    { workflow_run: { ...artifact.workflow_run, id: 121 } },
    { workflow_run: { ...artifact.workflow_run, head_repository_id: 95 } }])
    assert.throws(() => source.verifyProducer(completed, page(collector), { ...artifact, ...difference }, input));
  assert.throws(() => source.verifyProducer(completed, page({ ...collector, conclusion: "skipped" }), artifact, input));
  assert.throws(() => source.verifyProducer({ ...completed, path: ".github/workflows/other.yml" }, page(collector), artifact, input));
});

test("the cleanup barrier permits no-worker and drained-worker states only", () => {
  assert.doesNotThrow(() => launcher.requireDrain(undefined));
  assert.doesNotThrow(() => launcher.requireDrain({ drained: true }));
  for (const marker of [null, {}, { drained: false }, { drained: "true" }])
    assert.throws(() => launcher.requireDrain(marker), { message: "AZURE_EXPIRY_DRAIN_UNVERIFIED" });
});

test("bounds the expiry job and preserves package, approval and proof ordering", () => {
  const { createRequire } = require("node:module");
  const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");
  const guard = require("./certops-workflow-security");
  const filename = "certops-azure-keyvault-qualification.yml";
  const workflow = yaml.load(fs.readFileSync(path.join(__dirname, "../.github/workflows", filename), "utf8"));
  assert.deepEqual(guard.validateWorkflow(workflow, filename), []);
  assert.equal(workflow.jobs["natural-expiry"]["timeout-minutes"] * 60000, launcher.JOB_TIMEOUT_MS);
  for (const mutate of [
    job => { [job.steps[3], job.steps[4]] = [job.steps[4], job.steps[3]]; },
    job => { job.steps[5].run = "az group create"; },
    job => { job.steps[8].if = "success()"; },
    job => { job.steps[10].if = "always()"; },
    job => { job.steps[10].with.path = "qualification-results/**"; },
    job => { job.env.TT_AZURE_EXPIRY_PACKAGE_ARTIFACT_ID = "3"; },
  ]) {
    const changed = structuredClone(workflow);
    mutate(changed.jobs["natural-expiry"]);
    assert.ok(guard.validateWorkflow(changed, filename).length);
  }
});

test("stages only the three verified archive members from the selected producer", t => {
  const fixture = require("./test-support/final-package-evidence.cjs");
  const candidate = fixture.candidate(t, sourceSha);
  const directory = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "tt-expiry-staging-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const binding = { candidateSha: sourceSha, artifactId, runId, packageSha256: candidate.digest };
  const bytes = fixture.zip(candidate.entries);
  const accepted = path.join(directory, "exact");
  assert.deepEqual(source.stage(bytes, accepted, binding), { ...binding, packageVersion: "0.20.0",
    capabilities: require("./certops-azure-keyvault-package.cjs").CAPABILITIES });
  const rejected = path.join(directory, "rejected");
  assert.throws(() => source.stage(bytes, rejected, { ...binding, packageSha256: "a".repeat(64) }));
  assert.equal(fs.existsSync(rejected), false);
  assert.throws(() => source.stage(fixture.zip([...candidate.entries, ["token.jwt", "extra"]]), rejected, binding));
  assert.equal(fs.existsSync(rejected), false);
});
