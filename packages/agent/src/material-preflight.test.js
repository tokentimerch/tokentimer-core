"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { executeJob } = require("./index");

// skip-reason: no-host - Material distribution is qualified only on Linux.
test("a local material policy refusal has no uncertain side effect", { skip: process.platform !== "linux" }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "material-preflight-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const args = {
    jobId: "preflight-job", claimId: "preflight-claim", client: {},
    policyEngine: { checkPath: () => ({ allowed: true }) }, log: () => {},
    job: { action: "deploy-from-store", mode: "real", workspaceId: "11111111-1111-4111-8111-111111111111",
      agentId: "consumer", materialDeployment: { bindingId: "22222222-2222-4222-8222-222222222222", generation: 1, verificationPolicy: "installed" } },
    executionContext: { configDir: dir, execution: { dryRun: false }, materialStores: {}, materialBindings: {} },
  };
  const refused = await executeJob(args);
  assert.equal(refused.status, "blocked");
  assert.equal(refused.errorMessage, "material_binding_policy_denied");
  assert.deepEqual(fs.readdirSync(dir), [], "policy refusal must not create state or write files");
  const recovery = await executeJob({ ...args, executionContext: { ...args.executionContext, materialRecoveryOnly: true } });
  assert.equal(recovery.status, "orphaned_unknown_effect", "never hide a previous unresolved execution");
});
