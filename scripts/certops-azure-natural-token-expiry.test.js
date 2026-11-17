"use strict";
// Register the helper contracts in the canonical CertOps tooling inventory.
// These fixtures never produce trusted qualification or an acceptance receipt.
require("../tests/e2e/helpers/azure-natural-token-expiry.test.cjs");
require("../tests/e2e/helpers/azure-natural-token-supervisor.test.cjs");
const test = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), os = require("node:os");
const expiry = require("../tests/e2e/helpers/azure-natural-token-expiry.cjs");
const { runBoundedWorker } = require("../tests/e2e/helpers/azure-natural-token-supervisor.cjs");

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
  const work = runBoundedWorker({ workerPath: worker, budget });
  if (process.platform === "linux") assert.deepEqual(await work, facts);
  else await assert.rejects(work, { message: "AZURE_EXPIRY_DRAIN_UNVERIFIED" });
  assert.deepEqual(JSON.parse(fs.readFileSync(observed, "utf8")), { ...budget,
    workDeadlineMs: Math.min(budget.jobDeadlineMs, budget.resourceDeadlineMs) - budget.cleanupReserveMs });
});
