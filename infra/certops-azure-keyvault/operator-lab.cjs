"use strict";
const assert = require("node:assert/strict");
const { randomBytes } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const policy = require("./policy");
const lab = require("./lab");
const { verifyIdentity } = require("../../scripts/certops-azure-keyvault-package.cjs");
const { createRetirementProbe } = require("../../tests/wildcard-vault/ux-lab/azure-operator-review/azure-role-token-broker.cjs");

const ROLE_API = "?api-version=2022-04-01";
const ROLES = ["issuer", "consumer"];
const OBJECT = /^tt-[a-f0-9]{64}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ID = /^[1-9][0-9]{0,15}$/;
const SETUP_BUDGET_MS = 60 * 60000;
const RETIREMENT_BUDGET_MS = 12 * 60000;

function context(env) {
  policy.requireTrusted(env);
  assert.equal(process.platform, "linux");
  assert.equal(process.geteuid(), 0);
  assert.ok(policy.operatorWorkflow(env));
  assert.equal(env.GITHUB_RUN_ATTEMPT, "1");
  assert.equal(env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.match(env.GITHUB_RUN_ID, ID);
  assert.ok(path.isAbsolute(env.RUNNER_TEMP || ""));
  // Staging runs as root before the runner account initializes its OIDC cache.
  const root = path.join(fs.realpathSync(env.RUNNER_TEMP), "tt-kvqual-" + env.GITHUB_RUN_ID + "-1-operator");
  if (!fs.existsSync(root)) fs.mkdirSync(root, { mode: 0o700 });
  const stat = fs.lstatSync(root);
  assert.ok(stat.isDirectory() && stat.uid === 0 && (stat.mode & 0o777) === 0o700);
  assert.equal(fs.realpathSync(root), root);
  return {
    root,
    file: path.join(root, "operator-owned.json"),
    credentialRoot: path.join(root, "operator-certificates"),
  };
}

function verifyAppRoles(roles, env) {
  const config = {};
  assert.deepEqual(Object.keys(roles).sort(), ["consumer", "issuer"]);
  for (const role of ROLES) {
    const app = roles[role];
    assert.equal(app.tenantId, env.AZURE_TENANT_ID.toLowerCase());
    for (const id of [app.tenantId, app.clientId, app.principalId]) assert.match(id || "", policy.GUID);
    assert.match(app.certificateSha256 || "", SHA256);
    assert.notEqual(app.clientId.toLowerCase(), env.AZURE_CLIENT_ID.toLowerCase());
    config[role] = { tenantId: app.tenantId, clientId: app.clientId.toLowerCase(),
      principalId: app.principalId.toLowerCase(), certificateSha256: app.certificateSha256 };
  }
  for (const field of ["clientId", "principalId", "certificateSha256"])
    assert.notEqual(config.issuer[field], config.consumer[field], "operator role apps must be independent");
  return config;
}

function attach(state, kind, name) {
  const scope = lab.vaultId(state.plan) + (name === undefined ? "" : "/secrets/" + name);
  return lab.roleAssignment({ ...state.plan, identities: state.apps }, kind, scope);
}

function assignment(verb, selected) {
  return lab.arm(verb, selected.id + ROLE_API, verb === "PUT" ? selected.body : undefined,
    "Microsoft.Authorization/roleAssignments/" + (verb === "GET" ? "read" : verb === "PUT" ? "write" : "delete"),
    verb !== "PUT");
}

function approvedIdentity(approvedPackage, env) {
  const packageArtifact = verifyIdentity(approvedPackage);
  assert.equal(packageArtifact.runId, env.TT_AZURE_OPERATOR_PACKAGE_RUN_ID);
  assert.equal(packageArtifact.artifactId, env.TT_AZURE_OPERATOR_PACKAGE_ARTIFACT_ID);
  assert.equal(packageArtifact.packageSha256, env.TT_AZURE_OPERATOR_PACKAGE_SHA256);
  return packageArtifact;
}

async function provision({ approvedPackage, roles, env = process.env }) {
  const { file } = context(env);
  await lab.githubApproval(env);
  const packageArtifact = approvedIdentity(approvedPackage, env);
  const apps = verifyAppRoles(roles, env);
  assert.equal(fs.existsSync(file), false, "existing operator lease refused");
  const now = Date.now();
  const plan = policy.plan(env, now, randomBytes(16).toString("hex"));
  const state = {
    plan, packageArtifact, apps, deadlineMs: now + SETUP_BUDGET_MS,
    actions: [], issuerGrantIntent: false,
  };
  lab.save(file, state);
  await lab.provisionVault(plan, env);
  state.issuerGrantIntent = true;
  lab.save(file, state);
  assignment("PUT", attach(state, "issuer"));
  return { packageArtifact, vaultHost: plan.vault + ".vault.azure.net", ...apps, deadlineMs: state.deadlineMs };
}

function authority(env = process.env) {
  const { file, credentialRoot } = context(env);
  function stateFor(owner) {
    const state = lab.load(file);
    const { plan, packageArtifact, apps } = state;
    approvedIdentity(packageArtifact, env);
    assert.deepEqual(apps, verifyAppRoles(apps, env));
    assert.ok(plan.tags.runId === env.GITHUB_RUN_ID && plan.tags.sourceSha === env.GITHUB_SHA &&
      plan.tags.attempt === "1" && plan.tags.schema === policy.OPERATOR_SCHEMA);
    lab.assertPlan(plan);
    const expected = { project: "tt-wildcard-ux-qual-azure-" + plan.tags.runId, runId: plan.tags.runId,
      sourceSha: plan.tags.sourceSha, packageArtifact, vaultHost: plan.vault + ".vault.azure.net" };
    assert.deepEqual(owner ? Object.fromEntries(Object.keys(expected).map(name => [name, owner[name]])) : expected, expected);
    return { state, expected };
  }
  async function assertLease(owner) {
    const { state } = stateFor(owner);
    assert.ok(Date.now() + 10000 < state.deadlineMs, "operator vault work deadline reached");
    assert.ok(await lab.verifyOwned(state.plan, env));
    return state;
  }
  return {
    ownedReceipt() { return stateFor().expected; },
    async assertRun(owner) {
      await lab.githubApproval(env);
      const state = await assertLease(owner);
      assert.deepEqual({ issuer: owner.issuer, consumer: owner.consumer }, state.apps);
      assert.equal(owner.deadlineMs, state.deadlineMs);
      assert.equal(state.issuerGrantIntent, true);
      const grant = assignment("GET", attach(state, "issuer"));
      const expected = attach(state, "issuer").body.properties;
      assert.equal(grant?.properties.principalId.toLowerCase(), expected.principalId);
      assert.equal(grant?.properties.roleDefinitionId.toLowerCase(), expected.roleDefinitionId.toLowerCase());
    },
    assertLease,
    async journal(owner, { action, name }) {
      const state = await assertLease(owner);
      assert.match(name || "", OBJECT);
      const expected = ["publication-intent", "consumer-grant-intent", "consumer-denied-put-intent"];
      assert.equal(action, expected[state.actions.length]);
      assert.ok(state.actions.every(row => row.name === name));
      state.actions.push({ action, name });
      lab.save(file, state);
    },
    async grantExactRead(owner, name, app) {
      const state = await assertLease(owner);
      assert.match(name || "", OBJECT);
      assert.deepEqual(app, state.apps.consumer);
      assert.deepEqual(state.actions.at(-1), { action: "consumer-grant-intent", name });
      assignment("PUT", attach(state, "consumer", name));
    },
    async removeAndVerify(owner) {
      const { state, expected } = stateFor(owner);
      const { plan, apps } = state;
      const group = await lab.verifyOwned(plan, env);
      if (group) {
        const selected = [];
        if (state.issuerGrantIntent) selected.push(attach(state, "issuer"));
        const grant = state.actions.find(row => row.action === "consumer-grant-intent");
        if (grant) {
          assert.match(grant.name, OBJECT);
          selected.push(attach(state, "consumer", grant.name));
        }
        for (const role of selected) {
          assignment("DELETE", role);
          const deadline = Date.now() + 30000;
          let removed;
          do {
            removed = assignment("GET", role) === null;
            if (!removed) await lab.sleep(1000);
          } while (!removed && Date.now() < deadline);
          assert.ok(removed, "owned role assignment remains");
        }
        await lab.remove(plan, env);
      }
      assert.equal(await lab.verifyOwned(plan, env), null, "owned vault group remains");
      if (!fs.existsSync(credentialRoot)) {
        const receipt = lab.load(path.join(path.dirname(file), "operator-cleaned.json"));
        assert.deepEqual(receipt, expected);
        return { vaultAbsent: true, roleAssignmentsAbsent: true, appsAndCredentialsAbsent: true };
      }
      const deadlineMs = Math.min(Date.now() + RETIREMENT_BUDGET_MS, Date.parse(plan.tags.expiresAt));
      const directory = fs.lstatSync(credentialRoot);
      assert.ok(directory.isDirectory() && directory.uid === 0 && (directory.mode & 0o777) === 0o700);
      assert.equal(fs.realpathSync(credentialRoot), credentialRoot);
      try {
        const retired = createRetirementProbe({ certificateRoot: credentialRoot, deadlineMs, ...apps });
        console.log("Owned Key Vault removed. Waiting for the operator to retire both disposable Entra apps.");
        while (Date.now() + 15000 < deadlineMs) {
          if (await retired()) {
            lab.save(path.join(path.dirname(file), "operator-cleaned.json"), expected);
            return { vaultAbsent: true, roleAssignmentsAbsent: true, appsAndCredentialsAbsent: true };
          }
          await lab.sleep(5000);
        }
        throw new Error("Operator Entra retirement was not verified");
      } finally {
        for (const role of ROLES) for (const extension of ["cert.pem", "key.pem"])
          fs.rmSync(path.join(credentialRoot, role + "." + extension), { force: true });
        fs.rmdirSync(credentialRoot);
      }
    },
  };
}

module.exports = { context, provision, authority };
