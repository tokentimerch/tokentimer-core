"use strict";
/** Native consuming-daemon served-leaf mismatch source. A read-only local evidence recorder
 * observes the production coordinator; native validate/reload implementations
 * and actual certificate files are unchanged. This is not signed/API admission. */
const assert = require("node:assert/strict");
const {createProofVerifier, fileIdentity, snapshot, assertSnapshot} = require("./certops-daemon-coordinator-rollback");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const { runDeployReloadVerify } = require("../packages/agent/src");
const { reloadService } = require("../packages/agent/src/reload");
const {
  createPolicyEngine,
  loadPolicyConfig,
} = require("../packages/agent/src/policy");
const SCOPE =
  "native-consuming-daemon-production-coordinator-served-leaf-mismatch-rollback";
const PREFIX = ".preserve-daemon-served-leaf-";
const unresolvedRoots = new Set();
const FLAGS = [
  "actualTrustedPredecessor",
  "actualCandidateDeployedBeforeVerification",
  "candidatePairIndependentlyObserved",
  "trustedPredecessorStillServedAfterReload",
  "actualNativeValidationAndReloadSucceeded",
  "productionRollbackRestoredPair",
  "actualFingerprintMismatchRefused",
  "restoredPairBytesAndPermissions",
  "trustedPredecessorAfterRollback",
  "exactOwnedConfigurationRestored",
  "actualValidationAndReloadRecovered",
  "privateStagingPreserved",
  "ownershipGuardReleased",
];
const REQUIRED_SOURCES = [
  "scripts/certops-daemon-coordinator-rollback.js",
  "scripts/certops-daemon-served-leaf-mismatch.js",
  "scripts/certops-nginx-host.js",
  "packages/agent/src/index.js",
  "packages/agent/src/deploy/index.js",
  "packages/agent/src/reload/index.js",
  "packages/agent/src/verify/index.js",
  "packages/agent/src/evidence/index.js",
  "packages/agent/src/policy/index.js",
  "packages/agent/src/platform/index.js",
  "packages/agent/src/platform/durability.js",
  "packages/agent/vendor/log-scrub/secret-material.js",
  "packages/agent/scripts/host-gate.js",
];
const scenarioFor = (service) =>
  `${service}-coordinator-served-leaf-mismatch-paired-rollback`;
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const verifyProof = createProofVerifier(SCOPE, FLAGS);



function assertCleanupSafe(root) {
  assert.ok(
    !unresolvedRoots.has(root),
    "Preserve unresolved daemon served-leaf fixture ownership",
  );
  assert.ok(
    !fs.readdirSync(root).some((name) => name.startsWith(PREFIX)),
    "Preserve unresolved daemon rollback fixture",
  );
}
function beginCleanupGuard(root, service) {
  assert.ok(
    !unresolvedRoots.has(root),
    "Existing unresolved served-leaf ownership",
  );
  unresolvedRoots.add(root);
  const marker = path.join(root, PREFIX + crypto.randomUUID() + ".json");
  fs.writeFileSync(
    marker,
    JSON.stringify({ schemaVersion: 1, token: crypto.randomUUID(), service }),
    { flag: "wx", mode: 0o600 },
  );
  const before = snapshot(marker);
  return {
    assertOwned() {
      assertSnapshot(marker, before);
    },
    release() {
      assertSnapshot(marker, before);
      fs.unlinkSync(marker);
      unresolvedRoots.delete(root);
    },
  };
}
function retainConfiguration(file) {
  const original = snapshot(file),
    fd = fs.openSync(file, "r+");
  let closed = false;
  const check = () => {
    assert.ok(!closed);
    const st = fs.fstatSync(fd, { bigint: true });
    assert.ok(st.isFile() && st.nlink === 1n && st.ino > 0n);
    assert.equal(st.dev + ":" + st.ino, original.identity);
    assert.equal(
      fileIdentity(file),
      original.identity,
      "Preserve foreign configuration replacement",
    );
  };
  try {
    check();
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
  return {
    replace(expectedSha, bytes) {
      check();
      assert.ok(
        sha(fs.readFileSync(file)) === expectedSha,
        "Preserve unexpected configuration bytes",
      );
      fs.writeSync(fd, bytes, 0, bytes.length, 0);
      fs.ftruncateSync(fd, bytes.length);
      fs.fsyncSync(fd);
      check();
      assert.ok(
        sha(fs.readFileSync(file)) === sha(bytes),
        "Owned configuration write mismatch",
      );
    },
    close() {
      if (!closed) {
        fs.closeSync(fd);
        closed = true;
      }
    },
  };
}
function alternateConfiguration({
  configText,
  target,
  staleCert,
  staleKey,
  service,
}) {
  assert.ok(["nginx", "apache", "haproxy"].includes(service));
  assert.ok(
    typeof configText === "string" && configText.includes(target.certPath),
  );
  if (service === "haproxy")
    assert.equal(target.keyPath, target.certPath + ".key");
  else assert.ok(configText.includes(target.keyPath));
  const replaced = configText
    .split(target.certPath)
    .join(staleCert)
    .split(target.keyPath)
    .join(staleKey);
  assert.ok(
    replaced !== configText &&
      !replaced.includes(target.certPath) &&
      !replaced.includes(target.keyPath),
  );
  assert.ok(replaced.includes(staleCert));
  if (service !== "haproxy") assert.ok(replaced.includes(staleKey));
  return Buffer.from(replaced);
}
async function qualifyServedLeafMismatch({
  root,
  service,
  target,
  config,
  configText,
  candidate,
  predecessor,
  profiles,
  observe,
  port,
}) {
  assert.equal(process.platform, "linux");
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
  assert.equal(process.env.CERTOPS_RELOAD_DISPOSABLE_HOST, "1");
  assert.ok(["nginx", "apache", "haproxy"].includes(service));
  assert.equal(fs.realpathSync.native(root), root);
  for (const file of [
    config,
    target.certPath,
    target.keyPath,
    candidate.privateKeyPath,
    predecessor.privateKeyPath,
  ]) {
    assert.equal(path.dirname(file), root);
    fileIdentity(file);
  }
  assert.equal(typeof profiles, "function");
  assert.equal(typeof observe, "function");
  const rootStat = fs.lstatSync(root, { bigint: true });
  assert.ok(
    rootStat.isDirectory() && !rootStat.isSymbolicLink() && rootStat.ino > 0n,
  );
  const rootId = `${rootStat.dev}:${rootStat.ino}`;
  const originalConfig = snapshot(config);
  assert.ok(
    sha(configText) === originalConfig.sha256,
    "Original native configuration differs",
  );
  const oldCert = snapshot(target.certPath),
    oldKey = snapshot(target.keyPath),
    candidateStaging = snapshot(candidate.privateKeyPath),
    oldStaging = snapshot(predecessor.privateKeyPath);
  const leaf = (pem) => new crypto.X509Certificate(pem);
  const fingerprints = [predecessor, candidate].map((item) =>
    sha(leaf(item.certificatePem).raw),
  );
  assert.equal(new Set(fingerprints).size, 2);
  const trustedFingerprint = async () =>
    (await observe()).replaceAll(":", "").toLowerCase();
  const pairMatches = (material) => {
    const actual = leaf(fs.readFileSync(target.certPath));
    assert.ok(sha(actual.raw) === sha(leaf(material.certificatePem).raw));
    assert.ok(
      actual.checkPrivateKey(
        crypto.createPrivateKey(fs.readFileSync(target.keyPath)),
      ),
    );
    assert.equal(actual.checkHost(target.reference), target.reference);
    assert.ok(
      sha(fs.readFileSync(target.keyPath)) ===
        sha(fs.readFileSync(material.privateKeyPath)),
      "Actual private key bytes differ",
    );
    assert.equal(fs.statSync(target.keyPath).mode & 0o777, 0o600);
  };
  pairMatches(predecessor);
  assert.equal(await trustedFingerprint(), fingerprints[0]);
  const cleanupGuard = beginCleanupGuard(root, service);
  assert.ok(Number.isSafeInteger(port) && port > 1024 && port <= 65535);
  const staleCert = path.join(
    root,
    "served-predecessor-" + crypto.randomUUID() + ".crt",
  );
  const staleKey = staleCert + ".key";
  const staleConfig = alternateConfiguration({
    configText,
    target,
    staleCert,
    staleKey,
    service,
  });
  fs.writeFileSync(staleCert, predecessor.certificatePem, {
    flag: "wx",
    mode: 0o600,
  });
  fs.writeFileSync(staleKey, fs.readFileSync(predecessor.privateKeyPath), {
    flag: "wx",
    mode: 0o600,
  });
  const staleCertBefore = snapshot(staleCert),
    staleKeyBefore = snapshot(staleKey);
  const owned = () => {
    const st = fs.lstatSync(root, { bigint: true });
    assert.ok(
      st.isDirectory() &&
        !st.isSymbolicLink() &&
        `${st.dev}:${st.ino}` === rootId,
    );
    cleanupGuard.assertOwned();
  };
  let deploymentObserved = 0,
    verifyRefusals = 0,
    successfulReloads = 0,
    rollbacks = 0,
    observerFailed = false,
    result;
  const metadata = (item) =>
    Object.fromEntries(
      (item.metadata || []).map((entry) => [entry.name, entry.value]),
    );
  const client = {
    async reportEvidence(body) {
      try {
        assert.ok(
          Array.isArray(body.evidenceItems) && body.evidenceItems.length <= 16,
        );
        for (const item of body.evidenceItems) {
          const fields = metadata(item);
          if (
            item.eventType === "validation.passed" &&
            fields.step === "reload"
          ) {
            successfulReloads++;
            assert.equal(await trustedFingerprint(), fingerprints[0]);
          }
          if (
            item.eventType === "deployment.updated" &&
            fields.step === "deploy"
          ) {
            assert.equal(fields.idempotentSkip, false);
            pairMatches(candidate);
            assert.equal(await trustedFingerprint(), fingerprints[0]);
            deploymentObserved++;
          }
          if (
            item.eventType === "validation.failed" &&
            fields.step === "verify"
          ) {
            assert.equal(await trustedFingerprint(), fingerprints[0]);
            pairMatches(candidate);
            verifyRefusals++;
          }
          if (
            item.eventType === "deployment.updated" &&
            fields.step === "rollback"
          ) {
            assert.equal(fields.failedStep, "verify");
            assert.equal(fields.restored, true);
            pairMatches(predecessor);
            rollbacks++;
          }
        }
      } catch {
        observerFailed = true;
      }
    },
  };
  const retainedConfig = retainConfiguration(config);
  try {
    owned();
    retainedConfig.replace(originalConfig.sha256, staleConfig);
    const configured = await reloadService({
      service,
      commandProfiles: profiles(),
    });
    assert.equal(configured.reloaded, true);
    assert.equal(await trustedFingerprint(), fingerprints[0]);
    const commands = profiles();
    const engine = createPolicyEngine(
      loadPolicyConfig({
        allowedPaths: [root],
        allowedVerifyHosts: ["127.0.0.1"],
        allowedCommands: {
          validate: { argv: commands.validateArgv },
          reload: { argv: commands.reloadArgv },
        },
      }),
    );
    result = await runDeployReloadVerify({
      job: {
        action: "deploy",
        mode: "real",
        target: { type: "domain", reference: target.reference },
        reloadService: service,
        reloadCommandRefs: { validate: "validate", reload: "reload" },
        backupDir: target.backupDir,
        verifyHost: "127.0.0.1",
        verifyPort: port,
      },
      jobId: crypto.randomUUID(),
      policyEngine: engine,
      client,
      certificatePem: candidate.certificatePem,
      certPath: target.certPath,
      keyPath: target.keyPath,
      stagedKeyPath: candidate.privateKeyPath,
      keyRotated: true,
      retainPrivateKeyStaging: true,
      requestedSans: [target.reference],
    });
  } finally {
    // Restore only the exact owned alternate configuration, never foreign bytes.
    try {
      owned();
      retainedConfig.replace(sha(staleConfig), Buffer.from(configText));
      assertSnapshot(config, originalConfig);
    } finally {
      retainedConfig.close();
    }
  }
  assert.equal(
    observerFailed,
    false,
    "Native coordinator read-only evidence oracle failed",
  );
  assert.equal(result.status, "failed");
  assert.equal(result.deployResult.deployed, true);
  assert.equal(result.deployResult.skipped, false);
  assert.equal(deploymentObserved, 1);
  assert.equal(verifyRefusals, 1);
  assert.equal(successfulReloads, 1);
  assert.match(
    result.errorMessage,
    /verify step failed: live endpoint does not serve the deployed certificate/,
  );
  assert.equal(rollbacks, 1);
  assertSnapshot(target.certPath, oldCert, false);
  assertSnapshot(target.keyPath, oldKey, false);
  pairMatches(predecessor);
  assert.equal(await trustedFingerprint(), fingerprints[0]);
  const recovered = await reloadService({
    service,
    commandProfiles: profiles(),
  });
  assert.equal(recovered.reloaded, true);
  assert.equal(await trustedFingerprint(), fingerprints[0]);
  assertSnapshot(candidate.privateKeyPath, candidateStaging);
  assertSnapshot(predecessor.privateKeyPath, oldStaging);
  owned();
  assertSnapshot(staleCert, staleCertBefore);
  assertSnapshot(staleKey, staleKeyBefore);
  fs.unlinkSync(staleKey);
  fs.unlinkSync(staleCert);
  cleanupGuard.release();
  const proof = {
    schemaVersion: 1,
    scope: SCOPE,
    service,
    evidenceTransport: "read-only-local-recorder-not-signed-api",
    fingerprints,
    ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
  };
  verifyProof(proof);
  return proof;
}
module.exports = {
  SCOPE,
  FLAGS,
  REQUIRED_SOURCES,
  scenarioFor,
  verifyProof,
  snapshot,
  assertSnapshot,
  assertCleanupSafe,
  qualifyServedLeafMismatch,
  alternateConfiguration,
  retainConfiguration,
  beginCleanupGuard,
};
