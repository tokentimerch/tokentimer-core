"use strict";
// Customer-side package/runbook acceptance. Management credentials stay in this
// disposable process; TokenTimer receives neither AppRole IDs nor Vault tokens.
const fs = require("node:fs"), path = require("node:path"), https = require("node:https"), crypto = require("node:crypto"), assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { extractVerified, verifyInstalled } = require("../../../scripts/certops-agent-package");
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(check) {
  for (let attempt = 0; attempt < 100; attempt++) { if (await check()) return; await sleep(200); }
  throw new Error("Vault Agent runbook step did not complete");
}
function create({ root, build, receiptPath, artifactsRoot }) {
  const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8")), processes = new Map(), roles = new Map();
  assert.match(receipt.archive, /^tokentimer-agent-[A-Za-z0-9.+-]+\.tgz$/);
  let files, roleRestarts = 0;
  function privateFile(file, value) {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, value, { mode: 0o600 }); fs.chmodSync(file, 0o600);
    fs.chownSync(path.dirname(file), 10001, 10001); fs.chownSync(file, 10001, 10001);
  }
  function rememberToken(name) {
    const sink = path.join(root, name, "material-token");
    if (fs.existsSync(sink)) privateFile(path.join(root, name, "credential-history", crypto.randomUUID() + ".vault-token"), fs.readFileSync(sink));
  }
  async function request(route, method = "GET", body, token = "ux-lab-only-vault-token") {
    const result = await new Promise((resolve, reject) => {
      const req = https.request(new URL(route, "https://127.0.0.1:18200/v1/"), {
        method, ca: fs.readFileSync(path.join(root, "transport.crt")), rejectUnauthorized: true,
        headers: { "X-Vault-Token": token, "Content-Type": "application/json" },
      }, res => { let raw = ""; res.on("data", value => { raw += value; if (raw.length > 1048576) req.destroy(new Error("Vault response bound exceeded")); }); res.on("end", () => {
        try { resolve({ status: res.statusCode, body: raw ? JSON.parse(raw) : {} }); }
        catch { reject(new Error("Invalid Vault response; private content withheld")); }
      }); });
      req.setTimeout(10000, () => req.destroy(new Error("Vault runbook request timed out")));
      req.on("error", reject); req.end(body ? JSON.stringify(body) : undefined);
    });
    assert.ok(result.status >= 200 && result.status < 300, "Vault runbook request failed; private response withheld");
    return result.body;
  }
  async function stop(name) {
    const child = processes.get(name);
    if (child && child.exitCode === null && child.signalCode === null) {
      const exited = new Promise(resolve => child.once("exit", resolve));
      child.kill("SIGTERM");
      await Promise.race([exited, sleep(10000)]);
      assert.ok(child.exitCode !== null || child.signalCode !== null, "Vault Agent did not stop");
    }
    processes.delete(name);
  }
  async function start(name, previousToken) {
    const dir = path.join(root, name), config = path.join(dir, "vault-agent", "agent.hcl");
    const log = fs.openSync(path.join(dir, "vault-agent.log"), "a", 0o600);
    fs.fchownSync(log, 10001, 10001);
    const child = spawn("vault", ["agent", "-config=" + config], { stdio: ["ignore", log, log], uid: 10001, gid: 10001, env: { ...process.env, HOME: dir } });
    let spawnError;
    child.on("error", error => { spawnError = error; });
    fs.closeSync(log); processes.set(name, child);
    await until(() => {
      assert.equal(child.exitCode, null, "Vault Agent exited before authentication");
      assert.ifError(spawnError);
      const sink = path.join(dir, "material-token");
      const token = fs.existsSync(sink) && fs.readFileSync(sink, "utf8").trim();
      return token && token !== previousToken;
    });
    assert.equal(fs.statSync(path.join(dir, "material-token")).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.join(dir, "material-token")).uid, 10001);
    assert.match(fs.readFileSync(`/proc/${child.pid}/status`, "utf8"), /^Uid:\s+10001\s+10001\s+10001\s+10001$/m);
  }
  async function rotate(name, workspaceId, groupId) {
    const prefix = `tokentimer/${workspaceId}/${groupId}`, role = `tt-${name}-${groupId}`, dir = path.join(root, name, "vault-agent");
    await stop(name); rememberToken(name);
    const auth = await request("sys/auth");
    if (!auth.data["approle/"]) await request("sys/auth/approle", "POST", { type: "approle" });
    const mounts = await request("sys/mounts");
    assert.equal(mounts.data["secret/"].options.version, "2");
    const capabilities = name.includes("issuer") ? ["create", "read"] : ["read"];
    await request("sys/policies/acl/" + role, "PUT", { policy: `path "secret/data/${prefix}/bundles/*" { capabilities = ${JSON.stringify(capabilities)} }` });
    await request("auth/approle/role/" + role, "POST", { token_policies: [role], token_period: "20m", token_num_uses: 0, secret_id_ttl: "24h", secret_id_num_uses: 0 });
    const roleId = (await request(`auth/approle/role/${role}/role-id`)).data.role_id;
    const issued = (await request(`auth/approle/role/${role}/secret-id`, "POST", {})).data;
    const secretId = issued.secret_id;
    const oldSecret = path.join(dir, "secret-id");
    if (fs.existsSync(oldSecret)) privateFile(path.join(root, name, "credential-history", crypto.randomUUID() + ".secret-id"), fs.readFileSync(oldSecret));
    privateFile(path.join(dir, "role-id"), roleId); privateFile(path.join(dir, "secret-id"), secretId);
    // Follow the runbook's login/lookup/revoke smoke test before auto-auth.
    const smoke = (await request("auth/approle/login", "POST", { role_id: roleId, secret_id: secretId })).auth;
    const lookup = (await request("auth/token/lookup-self", "GET", undefined, smoke.client_token)).data;
    assert.equal(lookup.renewable, true);
    assert.deepEqual([...lookup.policies].sort(), ["default", role].sort());
    await request("auth/token/revoke-self", "POST", {}, smoke.client_token);
    privateFile(path.join(dir, "agent.hcl"), `pid_file = "${dir}/agent.pid"
vault {
 address = "https://127.0.0.1:18200"
 ca_cert = "${root}/transport.crt"
}
auto_auth {
 method "approle" {
  mount_path = "auth/approle"
  config = {
   role_id_file_path = "${dir}/role-id"
   secret_id_file_path = "${dir}/secret-id"
   remove_secret_id_file_after_reading = false
  }
 }
 sink "file" {
  config = {
   path = "${root}/${name}/material-token"
   mode = 384
  }
 }
}
`);
    const sink = path.join(root, name, "material-token");
    const previousToken = fs.existsSync(sink) ? fs.readFileSync(sink, "utf8").trim() : undefined;
    await start(name, previousToken);
    const token = fs.readFileSync(path.join(root, name, "material-token"), "utf8").trim();
    const granted = (await request("sys/capabilities-self", "POST", { path: `secret/data/${prefix}/bundles/${crypto.randomUUID()}` }, token)).capabilities;
    assert.deepEqual([...granted].sort(), [...capabilities].sort());
    for (const deniedPath of [
      `secret/metadata/${prefix}/bundles`,
      `secret/data/tokentimer/${workspaceId}/${crypto.randomUUID()}/bundles/${crypto.randomUUID()}`,
    ]) {
      assert.deepEqual((await request("sys/capabilities-self", "POST", { path: deniedPath }, token)).capabilities, ["deny"]);
    }
    const old = roles.get(name);
    if (old) {
      await request(`auth/approle/role/${old.role}/secret-id-accessor/destroy`, "POST", { secret_id_accessor: old.accessor });
      roleRestarts++;
    }
    roles.set(name, { role, accessor: issued.secret_id_accessor, permissionsChecked: true, isolationChecked: true });
  }
  return {
    prepare() {
      assert.equal(fs.existsSync(build), false, "Package acceptance requires a fresh package directory");
      const extracted = extractVerified({ tarball: path.join(artifactsRoot, receipt.archive), expectedSha256: receipt.sha256, destination: build });
      files = extracted.files;
      return extracted.root;
    },
    verify(packageRoot) { verifyInstalled(files, packageRoot); }, rotate, stop,
    async revoke(name) {
      await stop(name); rememberToken(name);
      await request("auth/token/revoke", "POST", { token: fs.readFileSync(path.join(root, name, "material-token"), "utf8").trim() });
    },
    async close() { for (const name of processes.keys()) await stop(name); },
    proof(packageRoot) {
      verifyInstalled(files, packageRoot);
      assert.ok(["issuer", "nginx", "haproxy"].every(name => roles.get(name)?.permissionsChecked && roles.get(name)?.isolationChecked));
      assert.ok(roleRestarts > 0, "The documented Vault Agent credential rotation must actually run");
      return { candidateSha: receipt.candidateSha, packageSha256: receipt.sha256, buildMode: receipt.buildMode,
        packageFilesUnmodified: true, authentication: "vault-agent-approle", vaultTlsVerified: true,
        separateRolesAndSinks: true, rolePermissionsChecked: true, roleIsolationChecked: true, credentialRotationCount: roleRestarts,
        supervision: "documented-node-process", vaultAgentUid: 10001, systemdQualified: false, publishedReleaseQualified: false };
    },
  };
}
module.exports = { create };
