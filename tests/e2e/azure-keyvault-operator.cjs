"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const lab = require("../../infra/certops-azure-keyvault/lab");
const operator = require("../../infra/certops-azure-keyvault/operator-lab.cjs");
const producer = require("../../scripts/certops-final-package-source.cjs");
const launcher = require("../wildcard-vault/ux-lab/azure-operator-review/azure-operator-protected-launch.cjs");

const roles = ["issuer", "consumer"];
function paths() {
  const owned = operator.context(process.env);
  return { ...owned, packageDirectory: path.join(owned.root, "package"), identity: path.join(owned.root, "identity.json"),
    evidenceDirectory: path.join(owned.root, "evidence"),
  };
}

async function stage() {
  const { packageDirectory, identity } = paths();
  const env = process.env;
  const selected = await producer.main(env.TT_AZURE_OPERATOR_PACKAGE_RUN_ID, env.TT_AZURE_OPERATOR_PACKAGE_ARTIFACT_ID,
    env.TT_AZURE_OPERATOR_PACKAGE_SHA256, packageDirectory, env);
  lab.save(identity, selected);
  console.log(JSON.stringify(selected));
}

function takeCredentials() {
  const inputs = {};
  for (const role of roles) {
    for (const type of ["cert", "key"]) {
      const name = "TT_AZURE_OPERATOR_" + role.toUpperCase() + "_" + type.toUpperCase() + "_PEM";
      const pem = process.env[name];
      delete process.env[name];
      assert.ok(typeof pem === "string" && pem.length > 0 && pem.length <= 16 * 1024,
        "both approved Azure operator credential pairs are required");
      inputs[role + "." + type + ".pem"] = pem;
    }
  }
  return inputs;
}

function writeCredentials(directory, credentialFiles) {
  fs.mkdirSync(directory, { mode: 0o700 });
  for (const [name, pem] of Object.entries(credentialFiles))
    fs.writeFileSync(path.join(directory, name), pem, { mode: 0o600, flag: "wx" });
}

async function run() {
  const credentials = takeCredentials();
  const layout = paths(), env = process.env;
  await lab.githubApproval(env);
  const approvedPackage = lab.load(layout.identity);
  const appRoles = JSON.parse(env.TT_AZURE_OPERATOR_APP_ROLES);
  const approved = await operator.provision({ approvedPackage, roles: appRoles, env });
  writeCredentials(layout.credentialRoot, credentials);
  fs.mkdirSync(layout.evidenceDirectory, { mode: 0o700 });
  const report = await launcher.runProtected({
    approved,
    packageDirectory: layout.packageDirectory,
    candidateRepo: env.TT_AZURE_OPERATOR_CANDIDATE_DIR,
    evidenceDirectory: layout.evidenceDirectory,
    credentialRoot: layout.credentialRoot,
    images: { apiImage: env.TT_AZURE_OPERATOR_API_IMAGE, workerImage: env.TT_AZURE_OPERATOR_WORKER_IMAGE,
      roleImage: env.TT_AZURE_OPERATOR_ROLE_IMAGE },
    authority: operator.authority(env), env,
  });
  assert.equal(report.status, "passed");
}

async function cleanup() {
  const layout = paths();
  if (!fs.existsSync(layout.file)) return;
  const authority = operator.authority();
  const owner = authority.ownedReceipt();
  const results = await Promise.allSettled([
    authority.removeAndVerify(owner), launcher.cleanupLocal(owner),
  ]);
  assert.ok(results.every(result => result.status === "fulfilled"), "independent operator cleanup did not complete");
}

if (require.main === module) {
  const actions = { stage, run, cleanup };
  Promise.resolve().then(() => {
    assert.ok(Object.hasOwn(actions, process.argv[2]));
    return actions[process.argv[2]]();
  }).catch(error => {
    const code = /^AZURE_[A-Z0-9_]{1,140}$/.test(error?.code || "") ? error.code : "AZURE_OPERATOR_FAILED";
    const match = /(?:operator-lab|azure-keyvault-operator|azure-operator-(?:protected-launch|public-journey|data-plane|tls-proof))\.cjs:\d+:\d+/;
    const frame = match.exec(typeof error?.stack === "string" ? error.stack : "");
    console.error(code + (frame ? " " + frame[0] : ""));
    process.exitCode = 1;
  });
}
