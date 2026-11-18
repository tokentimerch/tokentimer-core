"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const policy = require("./policy");
const lab = require("./lab");
const operator = require("./operator-lab.cjs");

const ID = "123456";
const guid = (prefix) => prefix.repeat(8) + "-0000-4000-8000-000000000000";
const sourceSha = "a".repeat(40), digest = "b".repeat(64);
const runEnv = {
  GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: policy.REPOSITORY, GITHUB_REF: "refs/heads/main",
  GITHUB_WORKFLOW_REF: policy.REPOSITORY + "/" + policy.OPERATOR_WORKFLOW + "@refs/heads/main",
  GITHUB_SHA: sourceSha, GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_RUN_ID: ID, GITHUB_RUN_ATTEMPT: "1",
  GITHUB_ACTOR_ID: "42", RUNNER_ENVIRONMENT: "github-hosted", CERTOPS_AZURE_KEYVAULT_LAB_ENABLED: "true",
  TT_AZURE_OPERATOR_PACKAGE_RUN_ID: "100", TT_AZURE_OPERATOR_PACKAGE_ARTIFACT_ID: "200",
  TT_AZURE_OPERATOR_PACKAGE_SHA256: digest, LAB_LOCATION: "swedencentral",
  AZURE_CLIENT_ID: guid("1"), AZURE_TENANT_ID: guid("2"), AZURE_SUBSCRIPTION_ID: guid("3"), AZURE_KV_ISSUER_ROLE_ID: guid("4"),
};

test("privileged staging leaves OIDC cache initialization to the unprivileged Linux runner", {
  skip: process.platform !== "linux" || process.geteuid?.() !== 0,
}, t => {
  const runnerUid = 1000;
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "tt-operator-custody-"));
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  fs.chownSync(temp, runnerUid, runnerUid);
  const env = { ...runEnv, RUNNER_TEMP: temp };
  const staged = operator.context(env);
  const cacheRoot = path.join(temp, "tt-kvqual-" + ID + "-1");
  assert.equal(staged.root, cacheRoot + "-operator");
  assert.equal(fs.existsSync(cacheRoot), false);
  const state = path.join(staged.root, "fixture-state");
  fs.writeFileSync(state, "local fixture", { mode: 0o600, flag: "wx" });
  const result = spawnSync(process.execPath, ["-e", [
    'const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");',
    'const root = require(process.argv[1]).privateRoot();',
    'assert.equal(fs.statSync(root).uid, process.geteuid());',
    'fs.mkdirSync(path.join(root, "azure-cli"), { mode: 0o700 });',
    'assert.throws(() => fs.readFileSync(process.argv[2]), { code: "EACCES" });',
    'process.stdout.write(root);',
  ].join("\n"), require.resolve("./lab"), state], { env, uid: runnerUid, gid: runnerUid, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, cacheRoot);
  assert.equal(fs.statSync(cacheRoot).uid, runnerUid);
  assert.equal(fs.statSync(path.join(cacheRoot, "azure-cli")).uid, runnerUid);
  assert.equal(fs.statSync(staged.root).uid, 0);
  assert.equal(fs.statSync(staged.root).mode & 0o777, 0o700);
  assert.equal(operator.context(env).root, staged.root);
  assert.equal(fs.statSync(cacheRoot).uid, runnerUid);
});

test("the operator lease owns only the tagged vault and requires its exact workflow path", () => {
  const now = Date.now();
  const plan = policy.plan(runEnv, now, "test-nonce");
  assert.deepEqual(plan.identities, {});
  assert.deepEqual(Object.keys(plan.roles), ["issuer", "consumer"]);
  assert.equal(plan.tags.schema, policy.OPERATOR_SCHEMA);
  assert.doesNotThrow(() => lab.assertPlan(plan));
  const vault = { name: plan.vault, id: lab.vaultId(plan), tags: plan.tags, type: "Microsoft.KeyVault/vaults" };
  assert.doesNotThrow(() => policy.ownedResources([vault], plan));
  assert.throws(() => policy.ownedResources([{ ...vault, type: "Microsoft.Storage/storageAccounts" }], plan));
  const run = { id: Number(ID), head_sha: sourceSha, event: "workflow_dispatch", head_branch: "main",
    path: policy.OPERATOR_WORKFLOW, run_attempt: 1, created_at: new Date(now).toISOString() };
  assert.doesNotThrow(() => policy.verifyRun(run, plan.tags));
  assert.throws(() => policy.verifyRun({ ...run, path: policy.WORKFLOW }, plan.tags));
  assert.throws(() => policy.ownedGroup({ name: plan.group, id: lab.groupId(plan), tags: { ...plan.tags, attempt: "2" } },
    { subscriptionId: plan.subscriptionId }));
});

test("operator self-approval is bound to the retained package and first trusted run", () => {
  const approval = { state: "approved", user: { id: 42 }, environments: [{ name: policy.LAB_ENV }] };
  const run = { id: Number(ID), run_attempt: 1, event: "workflow_dispatch", status: "in_progress",
    head_branch: "main", head_sha: sourceSha, path: policy.OPERATOR_WORKFLOW, actor: { id: 42 }, triggering_actor: { id: 42 } };
  const scope = { environment: policy.LAB_ENV, runId: ID, actorId: "42", headSha: sourceSha, producerRunId: "100",
    artifactId: "200", packageSha256: digest, expiresAt: Date.now() + 60000 };
  const env = { ...runEnv, TT_AZURE_LAB_SELF_APPROVAL: JSON.stringify(scope) };
  assert.equal(policy.requireLabApproval(run, [approval], env), true);
  assert.throws(() => policy.requireLabApproval({ ...run, path: policy.WORKFLOW }, [approval], env));
  assert.throws(() => policy.requireLabApproval(run, [approval], { ...env, GITHUB_RUN_ATTEMPT: "2" }));
  assert.throws(() => policy.requireLabApproval(run, [approval], { ...env, TT_AZURE_OPERATOR_PACKAGE_ARTIFACT_ID: "201" }));
});
