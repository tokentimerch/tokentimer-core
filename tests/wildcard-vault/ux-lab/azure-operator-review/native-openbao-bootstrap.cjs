"use strict";
// Disposable hosted runner only. The live workflow must invoke cleanup after
// interruptions before the independently verified Docker/DB teardown.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createHash, X509Certificate } = require("node:crypto");
const { execFileSync, spawnSync } = require("node:child_process");
const ownership = require("../../../../scripts/certops-linux-systemd-ownership");
const { extractVerified, verifyInstalled } = require("../../../../scripts/certops-agent-package");
const { verifyIdentity } = require("../../../../scripts/certops-azure-keyvault-package.cjs");
const { endpoint, loadEndpointCa, requestPinned } = require("./native-openbao-transport.cjs");
const { uninstallVaultAgent } = require("../../../e2e/linux-systemd-real-journey");

const UNIT = "tokentimer-agent.service", USER = "tokentimer-agent", ROOT = "/opt/tokentimer-agent";
const STATE = ROOT + "/state", DROPIN = "/etc/systemd/system/" + UNIT + ".d";
const SYSTEM_TARGETS = [ROOT, "/etc/systemd/system/" + UNIT, DROPIN, "/etc/polkit-1/rules.d/50-tokentimer-agent.rules"];
const ROLE_FILE = "/run/tt-native-openbao/role.json";

function command(file, args, options = {}) {
  const res = spawnSync(file, args, { encoding: "utf8", timeout: 30000, maxBuffer: 1048576, ...options });
  assert.equal(res.status, 0, "owned native command refused");
  return res.stdout?.trim();
}

function assertHosted() {
  assert.ok(process.platform === "linux" && process.getuid() === 0);
  ownership.validateHostedEnvironment(process.env);
  assert.equal(process.env.GITHUB_REPOSITORY, "tokentimerch/tokentimer-core");
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  assert.equal(process.env.GITHUB_EVENT_NAME, "workflow_dispatch");
  assert.equal(process.env.GITHUB_RUN_ATTEMPT, "1");
  assert.match(process.env.GITHUB_RUN_ID, /^[1-9][0-9]{0,15}$/);
}

function inspectOwnedTransport({ project, customerImage, apiAddress, baoAddress }, docker = args => execFileSync("docker", args, {
  encoding: "utf8", timeout: 15000, maxBuffer: 1048576,
})) {
  assert.match(project, /^tt-wildcard-ux-qual-[a-z0-9-]+$/);
  assert.match(customerImage, /^sha256:[a-f0-9]{64}$/);
  const api = endpoint(apiAddress), bao = endpoint(baoAddress);
  assert.notEqual(api.port, bao.port);
  const labels = [`label=com.docker.compose.project=${project}`, "label=com.docker.compose.service=customers"];
  const ids = docker(["ps", "--no-trunc", "-q", ...labels.flatMap(label => ["--filter", label])]).trim();
  assert.match(ids, /^[a-f0-9]{64}$/);
  const [container, ...rest] = JSON.parse(docker(["container", "inspect", ids]));
  assert.equal(rest.length, 0);
  assert.ok(container?.State.Running && container.Id === ids && container.Image === customerImage);
  assert.equal(container.Config.Labels["com.docker.compose.project"], project);
  assert.equal(container.Config.Labels["com.docker.compose.service"], "customers");
  for (const [internal, hostPort] of [["18443/tcp", api.port], ["18201/tcp", bao.port]]) {
    assert.deepEqual(container.NetworkSettings.Ports[internal], [{ HostIp: "127.0.0.1", HostPort: hostPort }]);
  }
  return { ca: () => docker(["exec", "--user", "0", ids, "cat", "/lab/transport.crt"]),
    issuerRoot: () => docker(["exec", "--user", "0", ids, "cat", "/lab/issuer-root.pem"]),
    credentials: () => JSON.parse(docker(["exec", "--user", "0", ids, "cat", ROLE_FILE])) };
}

function privateFile(file, bytes, uid, gid) {
  const fd = fs.openSync(file, "wx", 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fchownSync(fd, uid, gid); }
  finally { fs.closeSync(fd); }
}

function serviceProperty(name) {
  const result = spawnSync("systemctl", ["show", UNIT, "-p", name, "--value"], { encoding: "utf8", timeout: 10000 });
  if (result.status === 0) return result.stdout.trim();
  assert.equal(name === "LoadState" && result.stdout?.trim(), "not-found", "cannot verify owned unit");
  return "not-found";
}

function runPaths() {
  const run = process.env.GITHUB_RUN_ID;
  const receiptPath = path.join(fs.realpathSync(process.env.RUNNER_TEMP), `tt-native-openbao-${run}.json`);
  const root = "/var/lib/tt-native-openbao-" + run;
  return { run, root, receiptPath, installer: path.join(root, "exact-package/package/scripts/install-agent.sh") };
}

function cleanHost(plan, held) {
  const expected = runPaths();
  held.assertUnchanged();
  for (const field of ["run", "root", "installer"]) assert.equal(plan[field], expected[field]);
  assert.equal(plan.unit, UNIT);
  verifyIdentity(plan.packageArtifact);
  ownership.assertNoSymlinkTargets([...SYSTEM_TARGETS, plan.root, plan.installer]);
  if (fs.existsSync(SYSTEM_TARGETS[1])) {
    const trustedInstaller = path.resolve(__dirname, "../../../../packages/agent/scripts/install-agent.sh");
    const hash = file => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
    assert.equal(hash(plan.installer), hash(trustedInstaller), "owned uninstaller differs from reviewed source");
    uninstallVaultAgent({ installer: plan.installer, run: command, mainPid: () => Number(serviceProperty("MainPID")) });
  } else {
    assert.equal(serviceProperty("LoadState"), "not-found");
  }
  for (const target of [ROOT, plan.root, DROPIN]) {
    if (!fs.lstatSync(target, { throwIfNoEntry: false })) continue;
    assert.equal(fs.realpathSync(target), target);
    fs.rmSync(target, { recursive: true });
  }
  for (const [database, tool] of [["passwd", "userdel"], ["group", "groupdel"]]) {
    if (spawnSync("getent", [database, USER]).status === 0) command(tool, [USER]);
    assert.equal(spawnSync("getent", [database, USER]).status, 2);
  }
  command("systemctl", ["daemon-reload"]);
  assert.equal(serviceProperty("LoadState"), "not-found");
  for (const target of [...SYSTEM_TARGETS, plan.root]) assert.equal(fs.lstatSync(target, { throwIfNoEntry: false }), undefined);
  ownership.removeOwnershipReceipt(expected.receiptPath, held);
}

function cleanup() {
  assertHosted();
  const { receiptPath, root } = runPaths();
  if (!fs.lstatSync(receiptPath, { throwIfNoEntry: false })) {
    for (const target of [...SYSTEM_TARGETS, root]) assert.equal(fs.lstatSync(target, { throwIfNoEntry: false }), undefined);
    assert.equal(serviceProperty("LoadState"), "not-found");
    for (const database of ["passwd", "group"]) assert.equal(spawnSync("getent", [database, USER]).status, 2);
    return;
  }
  const held = ownership.captureOwnershipReceipt(receiptPath);
  try { cleanHost(JSON.parse(held.original.toString("utf8")), held); }
  finally { held.close(); }
}

async function prepare({ project, customerImage, apiAddress, baoAddress, packageArtifact, stage, workspaceId }) {
  assertHosted();
  verifyIdentity(packageArtifact);
  assert.match(workspaceId, /^[0-9a-f-]{36}$/);
  const { run, receiptPath, root, installer } = runPaths();
  for (const target of [...SYSTEM_TARGETS, receiptPath, root]) {
    assert.equal(fs.lstatSync(target, { throwIfNoEntry: false }), undefined, "refuse pre-existing service or receipt");
  }
  for (const database of ["passwd", "group"]) assert.equal(spawnSync("getent", [database, USER]).status, 2);
  assert.equal(serviceProperty("LoadState"), "not-found");

  const stagedIdentity = JSON.parse(fs.readFileSync(path.join(stage, "harness-input.json"), "utf8"));
  assert.deepEqual(stagedIdentity.packageArtifact, packageArtifact);
  const transport = inspectOwnedTransport({ project, customerImage, apiAddress, baoAddress });
  const plan = { run, project, root, unit: UNIT, installer, packageArtifact };
  ownership.claimOwnershipReceipt(receiptPath, plan);
  const held = ownership.captureOwnershipReceipt(receiptPath);
  assert.deepEqual(JSON.parse(held.original.toString("utf8")), plan);
  try {
    fs.mkdirSync(root, { mode: 0o755 });
    const output = path.join(root, "output"), caFile = path.join(root, "transport.pem");
    const { files } = extractVerified({
      tarball: path.join(stage, "artifacts/tokentimer-agent-0.20.0.tgz"),
      expectedSha256: packageArtifact.packageSha256, destination: path.join(root, "exact-package"),
    });
    const nodeExecutable = fs.realpathSync(process.execPath);
    assert.match(nodeExecutable, /^\/[A-Za-z0-9/_.-]+$/);
    const pem = transport.ca();
    const caDigest = createHash("sha256").update(pem).digest("hex");
    privateFile(caFile, pem, 0, 0);
    const ca = loadEndpointCa(caFile, caDigest);
    const issuerCa = path.join(root, "issuer-root.pem");
    privateFile(issuerCa, transport.issuerRoot(), 0, 0);
    const apiReady = await requestPinned({ address: apiAddress, ca, target: "/api/csrf-token" });
    assert.equal(apiReady.status, 200);
    const role = transport.credentials();
    for (const key of ["roleId", "secretId"]) assert.ok(/^[0-9a-f-]{36}$/.test(role[key] || ""), "private AppRole handoff missing");
    const login = await requestPinned({ address: baoAddress, ca, method: "POST", target: "/v1/auth/approle/login",
      body: { role_id: role.roleId, secret_id: role.secretId } });
    assert.equal(login.status, 200);
    const token = login.data?.auth?.client_token;
    assert.ok(typeof token === "string" && token.length > 0 && token.length < 4096 && login.data.auth.renewable === true,
      "expected a scoped renewable consumer token");
    return {
      files, output, nodeExecutable, packageArtifact,
      install(bootstrapToken) {
        held.assertUnchanged();
        assert.ok(/^ttboot_[A-Za-z0-9_-]+$/.test(bootstrapToken || ""));
        fs.mkdirSync(DROPIN, { mode: 0o755 });
        fs.writeFileSync(path.join(DROPIN, "99-qualification.conf"),
          `[Service]\nExecStart=\nExecStart="${nodeExecutable}" ${ROOT}/app/bin/tokentimer-agent.js\n`, { flag: "wx", mode: 0o644 });
        command("bash", [installer, "--api-url", apiAddress, "--workspace-id", workspaceId,
          "--ca-bundle", caFile, "--no-trust-store", "--write-path", output], {
          env: { PATH: `${path.dirname(nodeExecutable)}:/usr/sbin:/usr/bin:/sbin:/bin`, TOKENTIMER_AGENT_BOOTSTRAP_TOKEN: bootstrapToken },
        });
        verifyInstalled(files, ROOT + "/app");
      },
      readAgentId() {
        if (!fs.existsSync(path.join(STATE, "credential")) || fs.existsSync(path.join(STATE, "bootstrap.env"))) return null;
        return JSON.parse(fs.readFileSync(path.join(STATE, "config.json"), "utf8")).agentId;
      },
      verifyOutput(expectedDns, expectedFingerprint) {
        assert.equal(expectedDns, "nginx.wildcard.test");
        const leaf = path.join(output, "cert.pem"), chain = path.join(output, "chain.pem");
        const cert = new X509Certificate(fs.readFileSync(leaf));
        const fingerprint = cert.fingerprint256.replaceAll(":", "").toLowerCase();
        assert.equal(fingerprint, expectedFingerprint);
        assert.equal(cert.checkHost(expectedDns), expectedDns);
        command("openssl", ["verify", "-CAfile", issuerCa, "-untrusted", chain, "-verify_hostname", expectedDns, leaf]);
        return { leafSha256: fingerprint, chainSha256: createHash("sha256").update(fs.readFileSync(chain)).digest("hex") };
      },
      configure({ agentId, bindingId, groupId, sans }) {
        held.assertUnchanged();
        command("systemctl", ["stop", UNIT]);
        const file = path.join(STATE, "config.json"), config = JSON.parse(fs.readFileSync(file, "utf8"));
        assert.ok(config.agentId === agentId && config.workspaceId === workspaceId && config.serverUrl === apiAddress);
        const before = fs.lstatSync(file);
        assert.ok(before.isFile() && before.uid > 0 && (before.mode & 0o777) === 0o600);
        const storeCa = path.join(STATE, "openbao-ca.pem"), tokenFile = path.join(STATE, "openbao-token");
        privateFile(storeCa, ca, before.uid, before.gid);
        privateFile(tokenFile, token + "\n", before.uid, before.gid);
        const target = { type: "endpoint", reference: "native-openbao", certPath: path.join(output, "cert.pem"),
          keyPath: path.join(output, "key.pem"), chainPath: path.join(output, "chain.pem") };
        const next = { ...config, declaredTargetSelectors: [bindingId],
          policy: { allowedPaths: [output], allowedTargetSelectors: [bindingId, "native-openbao"] },
          execution: { enabled: true, dryRun: false },
          materialStores: { customer: { provider: "openbao-kv2", address: baoAddress, caFile: storeCa, tokenFile, mount: "secret",
            groups: { [groupId]: { workspaceId, sans, keyAlgorithm: "ec", prefix: `tokentimer/${workspaceId}/${groupId}` } } } },
          materialBindings: { [bindingId]: { workspaceId, groupId, agentId, materialStoreRef: "customer",
            deploymentProfileRef: "native-openbao", profileRevision: 1, authorizationRevision: 1, verificationPolicy: "installed", target } } };
        privateFile(file + ".native-next", JSON.stringify(next) + "\n", before.uid, before.gid);
        fs.renameSync(file + ".native-next", file);
        command("systemctl", ["start", UNIT]);
      },
      restart() { held.assertUnchanged(); command("systemctl", ["restart", UNIT]); },
      async renew() {
        const result = await requestPinned({ address: baoAddress, ca, method: "POST", target: "/v1/auth/token/renew-self", token, body: {} });
        assert.equal(result.status, 200);
        assert.equal(result.data?.auth?.renewable, true);
      },
      async close() {
        let closed = false;
        try {
          const revoked = await requestPinned({ address: baoAddress, ca, method: "POST", target: "/v1/auth/token/revoke-self", token, body: {} });
          closed = revoked.status === 204;
        } finally {
          try { cleanHost(plan, held); }
          finally { held.close(); }
        }
        assert.equal(closed, true, "consumer AppRole token revocation was not observed");
      },
    };
  } catch (primary) {
    try { cleanHost(plan, held); }
    catch (error) { throw new AggregateError([primary, error], "native consumer preparation and cleanup failed"); }
    finally { held.close(); }
    throw primary;
  }
}
module.exports = { assertHosted, inspectOwnedTransport, prepare, cleanup };
if (require.main === module) {
  try {
    assert.deepEqual(process.argv.slice(2), ["--cleanup"]);
    cleanup();
  } catch {
    console.error("Owned native OpenBao teardown failed");
    process.exitCode = 1;
  }
}
