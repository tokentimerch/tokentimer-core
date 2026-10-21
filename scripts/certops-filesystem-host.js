/**
 * Qualification: native paired filesystem deployment
 *
 * Run trusted-main manual certops-filesystem-qualification.yml separately on Ubuntu
 * 22.04/24.04 and Windows Server 2022/2025 with native OpenSSL, real filesystem/POSIX or
 * Windows ACLs and real symlink/junction. Require first cert/key/chain deploy,
 * fresh-process idempotent replay, rotation/exact predecessor backups, escape-link
 * refusal, input/policy no-mutation, explicit backup finalization and cleanup.
 * Independently parse genuine CA leaves, match keys, DNS and deployed chain with
 * OpenSSL. Keys/backups need mode 0600 or protected ACLs restricted to current user,
 * SYSTEM, Administrators; reject unexpected trustees. Mismatched key, missing explicit
 * key destination, private material as public cert and outside-allowlist paths must
 * preserve current deployment/outside sentinel. Retain staging keys for replay and pass
 * actual local policy. This is direct native executor coverage, not signed dispatch,
 * service identity, reload, TLS cutover, multi-target rollback, rename interruption or
 * disk-failure proof. Remove links without traversal, validate absolute parents/prefixes
 * before recursive deletion, attempt both owned roots even after one cleanup failure and
 * prove absence. Only sanitized named JSON uploads; no private bytes/hashes, replay
 * inputs, native command output or backup files.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
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
const tls = require("node:tls");
const { once } = require("node:events");
const { spawnSync } = require("node:child_process");
const deploy = require("../packages/agent/src/deploy");
const policy = require("../packages/agent/src/policy");
const verify = require("../packages/agent/src/verify");
const { createHostGate } = require("../packages/agent/scripts/host-gate");
const concurrent = require("./certops-filesystem-concurrent");
const backupAlias = require("./certops-filesystem-backup-alias");
const backupRetention = require("./certops-filesystem-backup-retention");
const { runDeployReloadVerify } = require("../packages/agent/src");
const ROLLBACK_SCENARIO = "filesystem-production-paired-rollback";
const ROLLBACK_SCOPE = "native-filesystem-production-coordinator-served-leaf-mismatch-paired-rollback";
const ROLLBACK_FLAGS = ["actualCandidatePairObserved", "trustedPredecessorServedThroughout", "productionVerifyMismatchObserved", "productionRollbackObserved", "predecessorPairBytesRestoredAndChainPreserved", "privateStagingPreserved", "ownedListenerAndConnectionsDrained"];
const ROLLBACK_SOURCES = [...backupRetention.REQUIRED_SOURCES, "packages/agent/src/index.js", "packages/agent/src/reload/index.js", "packages/agent/src/evidence/index.js", "packages/agent/vendor/log-scrub/secret-material.js"];
function verifyRollbackProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), ["schemaVersion", "scope", "fingerprints", ...ROLLBACK_FLAGS].sort());
  assert.equal(value.schemaVersion, 1); assert.equal(value.scope, ROLLBACK_SCOPE);
  assert.ok(Array.isArray(value.fingerprints) && value.fingerprints.length === 2 && value.fingerprints.every(item => typeof item === "string" && /^[a-f0-9]{64}$/.test(item)));
  assert.notEqual(value.fingerprints[0], value.fingerprints[1]);
  for (const flag of ROLLBACK_FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
const scenarios = ["filesystem-first-deploy", "filesystem-process-replay", "filesystem-rotation-backups", "filesystem-path-containment", "filesystem-input-refusals", "filesystem-backup-finalize", "filesystem-cleanup", concurrent.SCENARIO, backupAlias.SCENARIO, backupRetention.SCENARIO, ROLLBACK_SCENARIO];
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
async function qualifyPairedRollback({ root, target, predecessor, candidate, independentlyObserve, onCleanupSafety = () => {} }) {
  const sha = file => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  // Keep the real listener on the predecessor while the production coordinator
  // writes the candidate. A genuine served-leaf mismatch must restore disk bytes.
  const original = [target.certPath, target.keyPath, target.chainPath].map(sha);
  const staging = [predecessor, candidate].map(material => sha(material.privateKeyPath));
  const observePair = material => {
    assert.equal(verify.computeCertificateFingerprint(fs.readFileSync(target.certPath, "utf8")), verify.computeCertificateFingerprint(material.certificatePem));
    assert.equal(sha(target.keyPath), sha(material.privateKeyPath));
    const leaf = new crypto.X509Certificate(fs.readFileSync(target.certPath));
    assert.equal(leaf.checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(target.keyPath))), true);
    assert.equal(fs.readFileSync(target.chainPath, "utf8"), predecessor.chainPem);
    // The coordinator rotates only the pair; the separate chain stays at its
    // predecessor bytes even when the candidate carries a different CA bundle.
    independentlyObserve({ ...material, chainPem: predecessor.chainPem });
  };
  const fingerprints = [predecessor, candidate].map(material => verify.computeCertificateFingerprint(material.certificatePem));
  assert.notEqual(fingerprints[0], fingerprints[1]);
  const sockets = new Set(), closes = [];
  const retain = socket => {
    sockets.add(socket);
    closes.push(new Promise(resolve => socket.once("close", () => { sockets.delete(socket); resolve(); })));
    socket.on("error", () => {});
    socket.setTimeout(10000, () => socket.destroy());
    return socket;
  };
  let serverFailed = false;
  const server = tls.createServer({ cert: predecessor.certificatePem, key: fs.readFileSync(predecessor.privateKeyPath) }, socket => socket.end());
  server.on("connection", retain);
  server.on("error", () => { serverFailed = true; });
  const rootIdentity = fs.lstatSync(root, { bigint: true });
  assert.ok(rootIdentity.isDirectory() && !rootIdentity.isSymbolicLink());
  onCleanupSafety(false);
  let proof;
  try {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const port = server.address().port;
    const trustedFingerprint = async () => {
      const socket = retain(tls.connect({ host: "127.0.0.1", port, servername: target.reference, ca: predecessor.chainPem, rejectUnauthorized: true }));
      try {
        await once(socket, "secureConnect");
        assert.equal(socket.authorized, true);
        return crypto.createHash("sha256").update(socket.getPeerCertificate().raw).digest("hex");
      } finally {
        const closed = once(socket, "close");
        socket.destroy();
        await closed;
      }
    };
    assert.equal(await trustedFingerprint(), fingerprints[0]);
    const observed = [];
    let observerFailed = false;
    const client = { async reportEvidence(body) {
      try {
        for (const item of body.evidenceItems) {
          const fields = Object.fromEntries((item.metadata || []).map(entry => [entry.name, entry.value]));
          if (item.eventType === "deployment.updated" && fields.step === "deploy") {
            assert.equal(fields.idempotentSkip, false);
            observePair(candidate);
            observed.push("deploy");
          } else if (item.eventType === "validation.failed" && fields.step === "verify") {
            observePair(candidate);
            observed.push("verify-mismatch");
          } else if (item.eventType === "deployment.updated" && fields.step === "rollback") {
            assert.equal(fields.failedStep, "verify");
            assert.equal(fields.restored, true);
            observePair(predecessor);
            assert.deepEqual([target.certPath, target.keyPath, target.chainPath].map(sha), original);
            observed.push("rollback");
          } else continue;
          assert.equal(await trustedFingerprint(), fingerprints[0]);
        }
      } catch { observerFailed = true; }
    } };
    const result = await runDeployReloadVerify({
      job: { action: "deploy", mode: "real", target: { type: "domain", reference: target.reference }, backupDir: target.backupDir, verifyHost: "127.0.0.1", verifyPort: port },
      jobId: crypto.randomUUID(), client,
      policyEngine: policy.createPolicyEngine(policy.loadPolicyConfig({ allowedPaths: [root], allowedVerifyHosts: ["127.0.0.1"] })),
      certificatePem: candidate.certificatePem, certPath: target.certPath, keyPath: target.keyPath,
      stagedKeyPath: candidate.privateKeyPath, keyRotated: true, retainPrivateKeyStaging: true, requestedSans: [target.reference],
    });
    assert.equal(observerFailed, false, "Independent rollback observer failed");
    assert.equal(result.status, "failed");
    assert.equal(result.deployResult.deployed, true);
    assert.match(result.errorMessage, /verify step failed: live endpoint does not serve the deployed certificate/);
    assert.deepEqual(observed, ["deploy", "verify-mismatch", "rollback"]);
    observePair(predecessor);
    assert.deepEqual([target.certPath, target.keyPath, target.chainPath].map(sha), original);
    assert.deepEqual([predecessor, candidate].map(material => sha(material.privateKeyPath)), staging);
    proof = { schemaVersion: 1, scope: ROLLBACK_SCOPE, fingerprints, actualCandidatePairObserved: true, trustedPredecessorServedThroughout: true, productionVerifyMismatchObserved: true, productionRollbackObserved: true, predecessorPairBytesRestoredAndChainPreserved: true, privateStagingPreserved: true };
  } finally {
    // Await every retained connection and the listener before deleting key files.
    const closed = new Promise((resolve, reject) => server.close(error => error && error.code !== "ERR_SERVER_NOT_RUNNING" ? reject(error) : resolve()));
    for (const socket of sockets) socket.destroy();
    let drainTimer;
    try {
      await Promise.race([Promise.all([closed, ...closes]), new Promise((_, reject) => { drainTimer = setTimeout(() => reject(new Error("Owned TLS listener/socket drain was not proven")), 10000); })]);
    } finally { clearTimeout(drainTimer); }
    assert.equal(sockets.size, 0);
    assert.equal(server.listening, false);
    const now = fs.lstatSync(root, { bigint: true });
    assert.ok(now.isDirectory() && !now.isSymbolicLink());
    assert.equal(now.dev, rootIdentity.dev); assert.equal(now.ino, rootIdentity.ino);
    onCleanupSafety(true);
  }
  assert.equal(serverFailed, false);
  proof.ownedListenerAndConnectionsDrained = true;
  verifyRollbackProof(proof);
  return proof;
}
async function main() {
  guard();
  const temporaryRoot = fs.realpathSync.native(os.tmpdir());
  const root = concurrent.canonicalDirectory(fs.mkdtempSync(path.join(temporaryRoot, "certops-filesystem-")));
  const outside = concurrent.canonicalDirectory(fs.mkdtempSync(path.join(temporaryRoot, "certops-outside-")));
  const gate = createHostGate({ suite: "filesystem-host", strict: true, requiredCapabilities: ["native-filesystem", "openssl-key-oracle"], fixtureSource: { file: "scripts/certops-filesystem-host.js", sha256: crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex") }, probeCapabilities: () => ({ "native-filesystem": { available: fs.statSync(root).isDirectory() }, "openssl-key-oracle": { available: native("openssl", ["version"]).status === 0 } }) });
  gate.report.fixtureSources = ROLLBACK_SOURCES.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"..",file))).digest("hex")}));
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
  let rollbackCleanupSafe = true;
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
    await gate.scenario(ROLLBACK_SCENARIO, async () => {
      gate.report.nativeFilesystemPairedRollback = await qualifyPairedRollback({ root, target, predecessor: second, candidate: first, independentlyObserve, onCleanupSafety: safe => { rollbackCleanupSafe = safe; } });
    }, { oracle: "Actual production deployment writes a distinct certificate/key pair, refuses an independently trusted stale served leaf, and restores the exact predecessor bytes through production rollback" });
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
      assert.equal(rollbackCleanupSafe, true, "Preserve filesystem fixture until owned TLS resources drain");
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
module.exports = { main, scenarios, qualifyPairedRollback, verifyRollbackProof, ROLLBACK_SCENARIO, ROLLBACK_SCOPE, ROLLBACK_FLAGS, ROLLBACK_SOURCES };
if (require.main === module) (process.argv[2] === "--replay" ? replay(process.argv[3]) : main()).catch(() => { console.error("Native filesystem qualification failed; inspect sanitized named report"); process.exitCode = 1; });
