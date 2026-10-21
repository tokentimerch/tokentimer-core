/**
 * Qualification: native consuming-daemon coordinator rollback
 *
 * After trusted cutover to B in each nginx/Apache/HAProxy fixture, append an owned
 * invalid directive and run production runDeployReloadVerify with staged A/key and
 * genuine native validation/reload profiles. At deployment.updated a read-only recorder
 * observes actual A files while fresh trusted TLS still serves B. Native validation must
 * fail BEFORE reload; paired rollback must report restored:true at reload and restore
 * exact B bytes/ownership/modes, matching key/DNS and trusted TLS. Do not claim replaced
 * inode identity. Restore configuration only when original inode plus exact appended
 * fault still match; actual successful validation/reload and trusted B must precede
 * guard release. Keep both staging files exact. Unknown mutations retain a durable
 * guard: parent drains its owned daemon/port, then refuses recursive private cleanup
 * until resolved. Proof excludes private bytes, paths/raw commands. All six slots
 * require closed proof/current critical sources; this direct coordinator recorder does
 * not qualify signed dispatch/API ingestion.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/** Native consuming-daemon rollback source. A read-only local evidence recorder
 * observes the production coordinator; native validate/reload implementations
 * and actual certificate files are unchanged. This is not signed/API admission. */
const assert = require("node:assert/strict");
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
  "native-consuming-daemon-production-coordinator-validation-rollback";
const PREFIX = ".preserve-daemon-coordinator-";
const FLAGS = [
  "actualTrustedPredecessor",
  "actualCandidateDeployedBeforeValidation",
  "candidatePairIndependentlyObserved",
  "predecessorStillServedBeforeValidation",
  "actualNativeValidationRefused",
  "productionRollbackRestoredPair",
  "rollbackEvidenceObserved",
  "restoredPairBytesAndPermissions",
  "trustedPredecessorAfterRollback",
  "exactOwnedConfigurationRestored",
  "actualValidationAndReloadRecovered",
  "privateStagingPreserved",
  "ownershipGuardReleased",
];
const REQUIRED_SOURCES = [
  "scripts/certops-daemon-coordinator-rollback.js",
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
  `${service}-coordinator-validation-paired-rollback`;
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
function createProofVerifier(SCOPE, FLAGS) {
 return function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "schemaVersion",
      "scope",
      "service",
      "evidenceTransport",
      "fingerprints",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.scope, SCOPE);
  assert.ok(["nginx", "apache", "haproxy"].includes(value.service));
  assert.equal(
    value.evidenceTransport,
    "read-only-local-recorder-not-signed-api",
  );
  assert.ok(
    Array.isArray(value.fingerprints) &&
      value.fingerprints.length === 2 &&
      value.fingerprints.every(
        (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v),
      ) &&
      new Set(value.fingerprints).size === 2,
  );
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
};
}
const verifyProof = createProofVerifier(SCOPE, FLAGS);
function fileIdentity(file) {
  const st = fs.lstatSync(file, { bigint: true });
  assert.ok(
    st.isFile() && !st.isSymbolicLink() && st.ino > 0n,
    "Owned native file required",
  );
  assert.equal(fs.realpathSync.native(file), file);
  return `${st.dev}:${st.ino}`;
}
function snapshot(file) {
  const st = fs.lstatSync(file, { bigint: true });
  return {
    identity: fileIdentity(file),
    sha256: sha(fs.readFileSync(file)),
    mode: String(st.mode),
    uid: String(st.uid),
    gid: String(st.gid),
  };
}
function assertSnapshot(file, before, preserveIdentity = true) {
  const current = snapshot(file);
  if (!preserveIdentity) {
    delete current.identity;
    before = { ...before };
    delete before.identity;
  }
  assert.ok(
    isDeepStrictEqual(current, before),
    "Owned bytes or permissions changed",
  );
}
function assertCleanupSafe(root) {
  assert.ok(
    !fs.readdirSync(root).some((name) => name.startsWith(PREFIX)),
    "Preserve unresolved daemon rollback fixture",
  );
}
async function qualifyCoordinatorRollback({
  root,
  service,
  target,
  config,
  configText,
  candidate,
  predecessor,
  profiles,
  observe,
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
  const marker = path.join(root, PREFIX + crypto.randomUUID() + ".json");
  fs.writeFileSync(
    marker,
    JSON.stringify({ schemaVersion: 1, token: crypto.randomUUID(), service }),
    { flag: "wx", mode: 0o600 },
  );
  const markerBefore = snapshot(marker);
  const invalidBytes = Buffer.concat([
    fs.readFileSync(config),
    Buffer.from("\ncertops_unknown_directive on;\n"),
  ]);
  const owned = () => {
    const st = fs.lstatSync(root, { bigint: true });
    assert.ok(
      st.isDirectory() &&
        !st.isSymbolicLink() &&
        `${st.dev}:${st.ino}` === rootId,
    );
    assertSnapshot(marker, markerBefore);
  };
  let deploymentObserved = 0,
    validationRefusals = 0,
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
            fields.step === "reload"
          ) {
            assert.equal(fields.stage, "validate");
            validationRefusals++;
          }
          if (
            item.eventType === "deployment.updated" &&
            fields.step === "rollback"
          ) {
            assert.equal(fields.failedStep, "reload");
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
  try {
    owned();
    fs.writeFileSync(config, invalidBytes);
    const commands = profiles();
    const engine = createPolicyEngine(
      loadPolicyConfig({
        allowedPaths: [root],
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
    // Restore only our still-identical invalid append, never a foreign config.
    owned();
    assert.equal(fileIdentity(config), originalConfig.identity);
    assert.ok(
      sha(fs.readFileSync(config)) === sha(invalidBytes),
      "Preserve unexpected native config replacement",
    );
    fs.writeFileSync(config, configText);
    assertSnapshot(config, originalConfig);
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
  assert.equal(validationRefusals, 1);
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
  fs.unlinkSync(marker);
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
  createProofVerifier,
  fileIdentity,
  SCOPE,
  FLAGS,
  REQUIRED_SOURCES,
  scenarioFor,
  verifyProof,
  snapshot,
  assertSnapshot,
  assertCleanupSafe,
  qualifyCoordinatorRollback,
};
