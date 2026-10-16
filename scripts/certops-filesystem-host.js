/**
 * Qualify the production filesystem certificate coordinator on an explicitly disposable host.
 * certops-filesystem-qualification.yml selects the native distribution. This harness
 * owns its temporary keys, certificate paths and receipts, verifies real file/lock
 * behavior, and emits mandatory named evidence rather than qualifying API admission. */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const deploy = require("../packages/agent/src/deploy");
const policy = require("../packages/agent/src/policy");
const verify = require("../packages/agent/src/verify");
const { createHostGate } = require("../packages/agent/scripts/host-gate");
const concurrent = require("./certops-filesystem-concurrent");
const backupAlias = require("./certops-filesystem-backup-alias");
const backupRetention = require("./certops-filesystem-backup-retention");
const scenarios = ["filesystem-first-deploy", "filesystem-process-replay", "filesystem-rotation-backups", "filesystem-path-containment", "filesystem-input-refusals", "filesystem-backup-finalize", "filesystem-cleanup", concurrent.SCENARIO, backupAlias.SCENARIO, backupRetention.SCENARIO];
function guard() {
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(process.env.CERTOPS_FILESYSTEM_DISPOSABLE_HOST, "1");
}
function native(file, args, env = process.env) {
  const result = spawnSync(file, args, { env, encoding: "utf8", timeout: 30000, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(result.status, 0, `${path.basename(file)} failed; raw output withheld`);
  return result;
}
function checkPathFor(root) { return policy.createPolicyEngine(policy.loadPolicyConfig({ allowedPaths: [root] })).checkPath; }
async function replay(file) {
  guard();
  const input = JSON.parse(fs.readFileSync(file, "utf8"));
  const result = await deploy.deployCertificateAndKey({ ...input, checkPath: checkPathFor(input.root) });
  assert.equal(result.skipped, true, "Fresh process must observe idempotence from actual files");
}
async function main() {
  guard();
  const temporaryRoot = fs.realpathSync.native(os.tmpdir());
  const root = concurrent.canonicalDirectory(fs.mkdtempSync(path.join(temporaryRoot, "certops-filesystem-")));
  const outside = concurrent.canonicalDirectory(fs.mkdtempSync(path.join(temporaryRoot, "certops-outside-")));
  const gate = createHostGate({ suite: "filesystem-host", strict: true, requiredCapabilities: ["native-filesystem", "openssl-key-oracle"], fixtureSource: { file: "scripts/certops-filesystem-host.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ "native-filesystem": { available: fs.statSync(root).isDirectory() }, "openssl-key-oracle": { available: native("openssl", ["version"]).status === 0 } }) });
  gate.report.fixtureSources = backupRetention.REQUIRED_SOURCES.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"..",file))).digest("hex")}));
  if (process.platform === "linux") {
    const release = fs.readFileSync("/etc/os-release", "utf8");
    gate.report.qualificationEnvironment.distributionVersion = release.match(/^VERSION_ID="?([^"\n]+)/m)?.[1];
  }
  const target = { type: "domain", reference: "filesystem.example.test", certPath: path.join(root, "server.crt"), keyPath: path.join(root, "server.key"), chainPath: path.join(root, "chain.pem"), backupDir: path.join(root, "backups") };
  fs.mkdirSync(target.backupDir);
  const checkPath = checkPathFor(root);
  const sha = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  function fixture(name) {
    const key = path.join(root, `${name}.key`), cert = path.join(root, `${name}.crt`), csr = path.join(root, `${name}.csr`);
    const ca = path.join(root, "ca.crt"), caKey = path.join(root, "ca.key");
    if (!fs.existsSync(ca)) native("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey, "-out", ca, "-days", "2", "-subj", `/CN=Filesystem-CA-${crypto.randomUUID()}`, "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
    native("openssl", ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=filesystem.example.test"]);
    const ext = path.join(root, `${name}.ext`);
    fs.writeFileSync(ext, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:filesystem.example.test\n");
    native("openssl", ["x509", "-req", "-in", csr, "-CA", ca, "-CAkey", caKey, "-set_serial", `0x${crypto.randomUUID().replaceAll("-", "")}`, "-days", "2", "-extfile", ext, "-out", cert]);
    const certificatePem = fs.readFileSync(cert, "utf8");
    const privateKeyPem = fs.readFileSync(key, "utf8");
    const chainPem = fs.readFileSync(ca, "utf8");
    const validation = verify.validateCertificateForDeploy({ certificatePem, privateKeyPem, requestedSans: [target.reference], chainPems: [chainPem] });
    assert.equal(validation.valid, true, "Production pre-deploy validator must accept actual matching fixture");
    return { certificatePem, privateKeyPath: key, chainPem, retainPrivateKeyStaging: true };
  }
  function independentlyObserve(expected) {
    const x509 = new crypto.X509Certificate(fs.readFileSync(target.certPath));
    assert.equal(x509.fingerprint256, new crypto.X509Certificate(expected.certificatePem).fingerprint256);
    assert.ok(x509.checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(target.keyPath))));
    assert.equal(x509.checkHost(target.reference), target.reference);
    assert.equal(fs.readFileSync(target.chainPath, "utf8"), expected.chainPem);
    native("openssl", ["verify", "-CAfile", target.chainPath, "-verify_hostname", target.reference, target.certPath]);
    independentlyCheckKeyPermissions(target.keyPath);
  }
  function independentlyCheckKeyPermissions(file) {
    if (process.platform !== "win32") assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    else {
      const aclEnvironment = { ...process.env, CERTOPS_FIXTURE_KEY: file };
      for (const key of Object.keys(aclEnvironment)) if (key.toLowerCase() === "psmodulepath") delete aclEnvironment[key];
      const observed = native("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; $acl=Get-Acl -LiteralPath $env:CERTOPS_FIXTURE_KEY; if(-not $acl.AreAccessRulesProtected){throw 'Inherited key ACL'}; $allowed=@('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value); foreach($rule in $acl.Access){$sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;if($rule.AccessControlType -eq 'Allow' -and $sid -notin $allowed){throw 'Unexpected key ACL trustee'}}; 'restricted'"], aclEnvironment);
      assert.equal(observed.stdout.trim(), "restricted");
    }
  }
  let failure, ready = false, cleanup = "failed", rotated;
  try {
    await gate.preflight(); ready = true;
    const first = fixture("first"), second = fixture("second");
    await gate.scenario(scenarios[0], async () => {
      const result = await deploy.deployCertificateAndKey({ target, ...first, checkPath });
      assert.equal(result.deployed, true); assert.equal(result.firstDeploy, true); independentlyObserve(first);
    });
    await gate.scenario(scenarios[1], () => {
      const file = path.join(root, "replay.json"); fs.writeFileSync(file, JSON.stringify({ root, target, ...first }), { mode: 0o600 });
      native(process.execPath, [__filename, "--replay", file]); independentlyObserve(first);
    });
    await gate.scenario(scenarios[2], async () => {
      const before = [target.certPath, target.keyPath, target.chainPath].map(sha);
      rotated = await deploy.deployCertificateAndKey({ target, ...second, checkPath });
      assert.equal(rotated.deployed, true); assert.equal(rotated.firstDeploy, false); independentlyObserve(second);
      assert.deepEqual([rotated.backupPaths.cert, rotated.backupPaths.key, rotated.backupPaths.chain].map(sha), before);
      independentlyCheckKeyPermissions(rotated.backupPaths.key);
    });
    await gate.scenario(scenarios[3], async () => {
      const marker = path.join(outside, "marker"); fs.writeFileSync(marker, "preserved");
      const alias = path.join(root, "escape"); fs.symlinkSync(outside, alias, process.platform === "win32" ? "junction" : "dir");
      const refused = await deploy.deployCertificateAndKey({ target: { ...target, certPath: path.join(alias, "escape.crt"), keyPath: path.join(alias, "escape.key"), chainPath: undefined }, ...first, checkPath });
      assert.equal(refused.deployed, false); assert.deepEqual(fs.readdirSync(outside), ["marker"]); assert.equal(fs.readFileSync(marker, "utf8"), "preserved"); independentlyObserve(second);
    });
    await gate.scenario(scenarios[4], async () => {
      const before = [target.certPath, target.keyPath, target.chainPath].map(sha);
      await assert.rejects(deploy.deployCertificateAndKey({ target: { ...target, keyPath: undefined }, ...first, checkPath }), /keyPath is required/);
      await assert.rejects(deploy.deployCertificateAndKey({ target, ...first, certificatePem: fs.readFileSync(first.privateKeyPath, "utf8"), checkPath }), /private-key PEM marker/);
      const validation = verify.validateCertificateForDeploy({ certificatePem: first.certificatePem, privateKeyPem: fs.readFileSync(second.privateKeyPath, "utf8"), requestedSans: [target.reference] });
      assert.equal(validation.valid, false);
      const denied = await deploy.deployCertificateAndKey({ target: { ...target, certPath: path.join(outside, "denied.crt") }, ...first, checkPath });
      assert.equal(denied.deployed, false); assert.equal(fs.existsSync(path.join(outside, "denied.crt")), false);
      assert.deepEqual([target.certPath, target.keyPath, target.chainPath].map(sha), before);
    });
    await gate.scenario(scenarios[5], async () => {
      await deploy.discardDeployBackups(rotated);
      for (const file of Object.values(rotated.backupPaths)) assert.equal(fs.existsSync(file), false);
      independentlyObserve(second);
    });
    await gate.scenario(concurrent.SCENARIO, async () => {
      const third = fixture("third");
      gate.report.nativeFilesystemConcurrency = await concurrent.qualifyConcurrentRotation({workDir:root,materials:[first,second,third],independentlyCheckKeyPermissions});
    }, {oracle:"Two actual same-process default-backup-directory rotations preserve FIFO paired lineage, all six independent backups and stable trusted TLS checkpoints"});
    await gate.scenario(backupAlias.SCENARIO, async () => {
      gate.report.nativeFilesystemBackupAlias = await backupAlias.qualifyBackupDirectoryAlias({workDir:root,materials:[first,second],independentlyCheckKeyPermissions});
    }, {oracle:"Actual native backup-directory alias escapes are refused before mutation; a real allowed directory then rotates and preserves all three predecessor backups"});
    await gate.scenario(backupRetention.SCENARIO, async () => {
      gate.report.nativeFilesystemBackupRetention = await backupRetention.qualifyBackupRetention({workDir:root,materials:[first,second,fixture("retention-third")],independentlyCheckKeyPermissions});
    }, {oracle:"Actual retentionCount1 prunes only an exact destination generation while preserving same-basename sibling backups, current rollback files and legacy/operator/outside sentinels"});
  } catch (error) { failure = error; }
  finally {
    const clean = () => {
      concurrent.assertCleanupSafe(root);
      backupAlias.assertCleanupSafe(root);
      backupRetention.assertCleanupSafe(root);
      const errors = [];
      for (const [directory, prefix] of [[root, "certops-filesystem-"], [outside, "certops-outside-"]]) {
        try {
          assert.equal(path.dirname(path.resolve(directory)), path.resolve(temporaryRoot)); assert.ok(path.basename(directory).startsWith(prefix));
          fs.rmSync(directory, { recursive: true, force: true });
        } catch (error) { errors.push(error); }
      }
      assert.equal(fs.existsSync(root), false); assert.equal(fs.existsSync(outside), false);
      assert.equal(errors.length, 0, "Owned temporary directory cleanup failed");
    };
    try { if (ready) await gate.scenario(scenarios[6], clean); else clean(); cleanup = "passed"; } catch (error) { failure ||= error; }
    try { await gate.finish({ requiredScenarios: scenarios, cleanup: { status: cleanup } }); } catch (error) { failure ||= error; }
  }
  if (failure) throw failure;
}
module.exports = { main, scenarios };
if (require.main === module) (process.argv[2] === "--replay" ? replay(process.argv[3]) : main()).catch(() => { console.error("Native filesystem qualification failed; inspect sanitized named report"); process.exitCode = 1; });
