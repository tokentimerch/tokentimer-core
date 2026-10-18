"use strict";
/** Real Linux CSR-based ACME key reuse. Run after rotation controls and before
 * agent retirement. The parent owns the agent, TLS listener, jobs and all local
 * files; this helper registers each admitted job before waiting for completion.
 * Only the public profile API changes policy. No inventory dates are rewritten. */
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const scope = "real-linux-manual-and-default-scheduler-csr-key-reuse";
const scenarioName = "real ACME: manual and default scheduler renewals reuse the same local key";
const fields = ["publicProfilePolicyChanged", "manualRenewalSucceeded", "defaultSqlNowRenewalSucceeded", "claimBoundVerification", "unchangedPrivateCustody", "privateMaterialStayedLocal", "unchangedSpki", "distinctCaLeavesAndSerials", "advancingExpiry", "trustedTlsEachGeneration", "dnsCleanEachGeneration", "stableReuseProfile"];
const requiredSources = ["tests/e2e/helpers/certops-acme-key-reuse.js", "tests/e2e/acme-real-journey.js", "packages/agent/src/index.js", "packages/agent/src/keys/index.js", "packages/agent/src/acme/index.js", "packages/agent/src/signing/index.js", "apps/api/services/certops/renewalProfileAdmin.js", "apps/api/services/certops/renewalProfile.js", "apps/api/services/certops/renewalScheduler.js", "apps/api/services/certops/agentDispatch.js"];
const MATERIAL_PATH_SCOPE = "actual-linux-acme-space-unicode-config-state-material-paths";
const MATERIAL_PATH_FLAGS = ["ownedDirectoryIdentityStable", "canonicalAncestorsWithoutAliases", "configAndClientStateObserved", "privateCustodyAndCertificateObserved", "signedProfilePathPreserved"];
const MATERIAL_PATH_LIMITS = ["clientExecutablePathQualified", "repositoryOrHookPathQualified", "otherPlatformsQualified"];
function verifyMaterialPaths(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof));
  assert.deepEqual(Object.keys(proof).sort(), ["scope", "observedGenerations", "spaceAndUnicodeInEveryPath", ...MATERIAL_PATH_FLAGS, ...MATERIAL_PATH_LIMITS].sort());
  assert.equal(proof.scope, MATERIAL_PATH_SCOPE); assert.equal(proof.observedGenerations, 3);
  assert.equal(proof.spaceAndUnicodeInEveryPath, true);
  for (const flag of MATERIAL_PATH_FLAGS) assert.equal(proof[flag], true);
  for (const flag of MATERIAL_PATH_LIMITS) assert.equal(proof[flag], false);
  return true;
}
// Reads only paths owned by the caller's disposable native journey. It never
// records paths, account data or private bytes in public qualification evidence.
function assertOwnedMaterialRoot(workDir, identity) {
  const root=fs.lstatSync(workDir,{bigint:true});
  assert.ok(identity && root.isDirectory() && !root.isSymbolicLink() && root.dev === identity.dev && root.ino === identity.ino);
  assert.equal(fs.realpathSync(workDir),workDir);
}
function materialPathObserver({workDir, configDir, certPath, keyPath, acmeKind, workDirIdentity}) {
  assert.ok(["certbot", "acme.sh"].includes(acmeKind));
  assert.ok(path.isAbsolute(workDir) && path.resolve(workDir) === workDir);
  const identity = workDirIdentity;
  assertOwnedMaterialRoot(workDir,identity);
  assert.ok(identity.isDirectory() && !identity.isSymbolicLink());
  assert.equal(fs.realpathSync(workDir), workDir);
  const stateDir = path.join(configDir, "acme", acmeKind === "certbot" ? "certbot" : "acme.sh");
  const nodes = [[configDir,true], [path.join(configDir,"config.json"),false], [stateDir,true], [certPath,false], [keyPath,false]];
  const directories = new Map(); let observations = 0;
  return {
    observe() {
      assertOwnedMaterialRoot(workDir,identity);
      for (const [file,isDirectory] of nodes) {
        assert.ok(file.startsWith(workDir + path.sep) && path.resolve(file) === file);
        assert.ok(file.includes(" ") && /[^\x00-\x7f]/.test(file));
        let current = workDir;
        for (const part of path.relative(workDir,file).split(path.sep)) {
          current = path.join(current,part);
          const node = fs.lstatSync(current,{bigint:true}); assert.equal(node.isSymbolicLink(),false);
          assert.equal(fs.realpathSync(current),current);
          if (node.isDirectory()) {
            const original = directories.get(current);
            if (original) assert.ok(node.dev === original.dev && node.ino === original.ino);
            else directories.set(current,node);
          }
        }
        const node = fs.lstatSync(file,{bigint:true});
        assert.equal(node.isDirectory(),isDirectory);
        assert.equal(node.uid,BigInt(process.getuid()));
        if (!isDirectory) assert.ok(node.isFile() && node.nlink === 1n && node.size > 0n && (node.mode & 0o777n) === 0o600n);
      }
      assert.ok(fs.readdirSync(stateDir).length > 0, "Actual ACME client-state directory must exist after native issuance");
      observations++;
    },
    proof() {
      const proof = {scope:MATERIAL_PATH_SCOPE,observedGenerations:observations,spaceAndUnicodeInEveryPath:true,...Object.fromEntries(MATERIAL_PATH_FLAGS.map(flag=>[flag,true])),...Object.fromEntries(MATERIAL_PATH_LIMITS.map(flag=>[flag,false]))};
      verifyMaterialPaths(proof); return proof;
    },
  };
}
function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof));
  assert.deepEqual(Object.keys(proof).sort(), [...fields, "scope", "client", "fingerprints", "serials", "spkiFingerprint", "jobIds", "sourceProfileId", "sourceProfileFingerprint", "materialPaths"].sort());
  verifyMaterialPaths(proof.materialPaths);
  assert.equal(proof.scope, scope); assert.ok(["certbot", "acme.sh"].includes(proof.client));
  for (const field of fields) assert.equal(proof[field], true, field);
  for (const name of ["fingerprints", "serials"]) {
    assert.ok(Array.isArray(proof[name])); assert.equal(proof[name].length, 3);
    for (const value of proof[name]) assert.match(value, name === "serials" ? /^[A-F0-9]{1,64}$/ : /^[a-f0-9]{64}$/);
    assert.equal(new Set(proof[name]).size, 3);
  }
  assert.match(proof.spkiFingerprint, /^[a-f0-9]{64}$/);
  assert.match(proof.sourceProfileFingerprint, /^[a-f0-9]{64}$/);
  assert.match(proof.sourceProfileId, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i);
  assert.ok(Array.isArray(proof.jobIds)); assert.equal(proof.jobIds.length, 2);
  for (const id of proof.jobIds) assert.match(id, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i);
  assert.equal(new Set(proof.jobIds.map(id => id.toLowerCase())).size, 2); return true;
}
async function qualifyKeyReuse({ pool, workspaceId, agent, publicSession, certificateId, certPath, keyPath, ownedJobIds, waitUntil, verifyDnsCleanup, verifyNames, servedFingerprint, repoRoot, acmeKind, workDir, configDir, workDirIdentity }) {
  assert.equal(process.platform, "linux"); assert.ok(["certbot", "acme.sh"].includes(acmeKind));
  const query = (sql, args = []) => pool.query(sql, args);
  const profile = async () => (await query("SELECT cp.id, cp.public_metadata, cp.renew_before_days, cp.status, cp.updated_at FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2", [workspaceId, certificateId])).rows[0];
  const original = await profile(); assert.ok(original); assert.equal(original.status, "active");
  assert.equal(original.public_metadata.renewalProfile.keyRotationPolicy.rotateOnRenew, true, "Run reuse only after the journey's positive rotation controls");
  const expected = structuredClone(original.public_metadata.renewalProfile); expected.keyRotationPolicy.rotateOnRenew = false;
  const changed = await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/profiles/${original.id}`, "PATCH", { renewalProfile: expected });
  assert.equal(changed.status, 200); const stable = await profile(); assert.deepEqual(stable.public_metadata.renewalProfile, expected);
  const privateBytes = fs.readFileSync(keyPath), privateKey = crypto.createPrivateKey(privateBytes);
  const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
  const spki = leaf => sha(leaf.publicKey.export({ type: "spki", format: "der" }));
  const leaves = [], jobs = [];
  const paths = materialPathObserver({workDir,configDir,certPath,keyPath,acmeKind,workDirIdentity});
  const observe = async () => {
    paths.observe();
    const stat = fs.lstatSync(keyPath); assert.equal(stat.isFile(), true); assert.equal(stat.isSymbolicLink(), false);
    assert.equal(stat.mode & 0o777, 0o600); assert.equal(stat.uid, process.getuid()); assert.equal(stat.nlink, 1);
    assert.ok(fs.readFileSync(keyPath).equals(privateBytes), "Actual local private key bytes must remain unchanged");
    const leaf = new crypto.X509Certificate(fs.readFileSync(certPath)); verifyNames(leaf);
    assert.ok(leaf.checkPrivateKey(privateKey)); assert.equal(await servedFingerprint(), leaf.fingerprint256);
    await verifyDnsCleanup(); if (leaves.length) {
      assert.equal(spki(leaf), spki(leaves[0])); assert.ok(Date.parse(leaf.validTo) > Date.parse(leaves.at(-1).validTo));
      for (const prior of leaves) { assert.notEqual(leaf.fingerprint256, prior.fingerprint256); assert.notEqual(leaf.serialNumber, prior.serialNumber); }
    }
    leaves.push(leaf);
  };
  await observe();
  const complete = async job => {
    await waitUntil(async () => {
      assert.equal(agent.exitCode, null); assert.equal(agent.signalCode, null);
      const row = (await query("SELECT status,payload,claim_id,source,mode,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND id=$2", [workspaceId, job.id])).rows[0];
      assert.ok(row); if (["failed", "rejected", "cancelled", "blocked", "orphaned_unknown_effect"].includes(row.status)) throw new Error("Real key-reuse renewal terminated unsuccessfully");
      if (row.status !== "succeeded") return false;
      assert.equal(row.mode, "real"); assert.equal(row.payload.keyRotation, false); assert.equal(row.source, job.source); assert.ok(row.claim_id);
      assert.deepEqual(row.payload.renewalProfile, expected, "Claimed execution must retain the complete stable source profile snapshot");
      assert.equal(row.payload.acmeKind, acmeKind); assert.equal(row.payload.commandRef, expected.acme.commandRef); assert.equal(row.payload.caEndpoint, expected.ca.endpoint);
      assert.deepEqual([...row.payload.sans].sort(), [...expected.sanPolicy.sans].sort()); assert.equal(row.payload.certPath, certPath);
      assert.equal(row.result_metadata.keyRotated, false);
      assert.ok((await query("SELECT 1 FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.claim_id=j.claim_id AND e.evidence_type='validation.passed' AND e.metadata->>'step'='verify'", [workspaceId, job.id])).rows.length);
      const publicData = JSON.stringify([row, (await query("SELECT metadata,redacted_output FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2", [workspaceId, job.id])).rows]);
      const bodySentinel = privateBytes.toString("utf8").split(/\r?\n/).find(line => line && !line.startsWith("-----"));
      assert.ok(bodySentinel && bodySentinel.length >= 32);
      assert.equal([privateBytes.toString("utf8"), privateBytes.toString("base64"), bodySentinel, "PRIVATE KEY-----"].some(secret => publicData.includes(secret)), false, "Actual private material must remain absent from persisted public job and evidence data");
      return true;
    }, 180000);
    await observe(); assert.deepEqual(await profile(), stable);
  };
  // Let the real CA's second-resolution notAfter advance; this is actual time,
  // not a scheduler clock override or manufactured inventory eligibility.
  await new Promise(resolve => setTimeout(resolve, 1500));
  const manual = await publicSession.request(`/api/v1/workspaces/${workspaceId}/certops/jobs`, "POST", { operation: "renew", subjectType: "managed_certificate", subjectId: String(certificateId), idempotencyKey: crypto.randomUUID() });
  assert.equal(manual.status, 201); ownedJobIds.push(manual.body.job.id); jobs.push({ id: manual.body.job.id, source: "api" }); await complete(jobs[0]);
  await new Promise(resolve => setTimeout(resolve, 1500));
  const due = (await query("SELECT mc.not_after, mc.not_after <= NOW() + (COALESCE(cp.renew_before_days,30) || ' days')::interval AS due FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2 AND cp.status='active' AND EXISTS (SELECT 1 FROM certops_management_periods p WHERE p.workspace_id=mc.workspace_id AND p.managed_certificate_id=mc.id AND p.ended_at IS NULL AND p.automation_enabled=TRUE)", [workspaceId, certificateId])).rows[0];
  assert.equal(due?.due, true, "Actual SQL NOW must select the naturally due managed certificate");
  const scheduler = require(path.join(repoRoot, "apps/api/services/certops/renewalScheduler.js"));
  const key = scheduler.renewalIdempotencyKey(certificateId, due.not_after);
  assert.equal((await query("SELECT 1 FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key=$2", [workspaceId, key])).rows.length, 0);
  // Capture jobs even when the sweep reports an error, so parent cleanup owns
  // any committed admission rather than losing it on the assertion below.
  let sweep;
  try { sweep = await scheduler.runRenewalSchedulerSweep({ dbPool: pool, env: process.env }); }
  finally {
    const admitted = (await query("SELECT id,source FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND idempotency_key=$3", [workspaceId, String(certificateId), key])).rows;
    for (const job of admitted) { ownedJobIds.push(job.id); jobs.push(job); }
  }
  assert.equal(sweep.errors.length, 0); assert.equal(jobs.length, 2); assert.equal(jobs[1].source, "automation"); await complete(jobs[1]);
  const proof = { scope, client: acmeKind, materialPaths: paths.proof(), ...Object.fromEntries(fields.map(field => [field, true])), fingerprints: leaves.map(leaf => sha(leaf.raw)), serials: leaves.map(leaf => leaf.serialNumber), spkiFingerprint: spki(leaves[0]), jobIds: jobs.map(job => job.id), sourceProfileId: stable.id, sourceProfileFingerprint: sha(JSON.stringify(stable)) };
  verifyProof(proof); return proof;
}

const SCOPE = "acme-client-path-and-key-reuse-variants";
const SUITE = "acme-key-reuse-variants";
const SUITE_LEVEL = "integration";
const PROOF_LEVEL = "script";
const REPORT_FILE = "acme-key-reuse.json";
const REPORT_ENV = "CERTOPS_ACME_KEY_REUSE_REPORT";
const SCENARIOS = Object.freeze([
  "acme-client-path-outside-owned-directory",
  "acme-second-order-reuses-spki",
]);
const CATALOG_IDS = Object.freeze([
  "acme.key-policy",
  "acme.linux-certbot",
  "acme.linux-acmesh",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-acme-key-reuse.js",
  "scripts/certops-acme-key-reuse.js",
  "scripts/certops-acme-key-reuse.test.js",
  "docs/certops/cross/acme-key-reuse.md",
  "scripts/_registration/cross-coverage.json",
  ".github/workflows/certops-cross-coverage-variants.yml",
]);
const PROOF_KEYS = Object.freeze([
  "scope",
  "evidenceLevel",
  "nativeExecutionQualified",
  "sharedFleetQualified",
  "liveCertbot",
  "hostCapabilityAbsentIsPass",
  "keyReuseRefused",
  "outsidePathRefused",
  "inUseKeyPreserved",
  "inUseKeyDeleted",
  "blanketNetshReset",
]);

function contained(root, candidate) {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function refuseBlanketReset(command) {
  if (/netsh/i.test(String(command)) && /reset/i.test(String(command))) {
    throw Object.assign(new Error("blanket netsh reset refused"), {
      code: "BLANKET_NETSH_RESET",
    });
  }
}

function assertClientPath(root, clientPath) {
  const base = path.resolve(root);
  if (!contained(base, clientPath)) {
    throw Object.assign(new Error("client path outside owned directory"), {
      code: "CLIENT_PATH",
    });
  }
  const relative = path.relative(base, path.resolve(clientPath));
  let current = base;
  for (const segment of relative.split(path.sep)) {
    current = path.join(current, segment);
    if (!fs.existsSync(current)) break;
    if (!fs.lstatSync(current).isSymbolicLink()) continue;
    const link = path.resolve(path.dirname(current), fs.readlinkSync(current));
    if (!contained(base, link)) {
      throw Object.assign(new Error("client path outside owned directory"), {
        code: "CLIENT_PATH",
      });
    }
    throw Object.assign(new Error("client path outside owned directory"), {
      code: "CLIENT_PATH",
    });
  }
}

function createRun(root) {
  assert.equal(typeof root, "string");
  return {
    root: path.resolve(root),
    spkis: new Set(),
    keys: new Map(),
    sharedFleet: false,
    nativeExecutionQualified: false,
    sharedFleetQualified: false,
    liveCertbot: "pending",
  };
}

function registerKey(state, id, keyPath, bytes) {
  assert.equal(state.keys.has(id), false);
  assertClientPath(state.root, keyPath);
  const body = Buffer.from(bytes);
  fs.writeFileSync(keyPath, body);
  state.keys.set(id, { path: keyPath, inUse: true, bytes: Buffer.from(body) });
  return state.keys.get(id);
}

function submitOrder(state, order) {
  assert.equal(state.nativeExecutionQualified, false);
  assert.equal(state.sharedFleetQualified, false);
  assert.equal(state.liveCertbot, "pending");
  refuseBlanketReset(order.cleanupCommand || "");
  if (state.sharedFleet === true || order.sharedFleet === true) {
    throw Object.assign(new Error("shared fleet refused"), { code: "SHARED_FLEET" });
  }
  assertClientPath(state.root, order.clientPath);
  assert.match(order.spki, /^[a-f0-9]{64}$/);
  if (state.spkis.has(order.spki)) {
    throw Object.assign(new Error("key-reuse gate failed"), { code: "KEY_REUSE" });
  }
  state.spkis.add(order.spki);
  return {
    accepted: true,
    nativeExecutionQualified: false,
    sharedFleetQualified: false,
    liveCertbot: "pending",
  };
}

function deleteKey(state, id) {
  const key = state.keys.get(id);
  assert.ok(key, "known key required");
  assert.ok(fs.readFileSync(key.path).equals(key.bytes));
  throw Object.assign(new Error("refusing to delete an in-use key"), {
    code: "KEY_IN_USE",
  });
}

function spkiOf(publicKey) {
  return crypto
    .createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
}

function verifyVariantProof(proof) {
  assert.deepEqual(Object.keys(proof).sort(), [...PROOF_KEYS].sort());
  assert.equal(proof.scope, SCOPE);
  assert.equal(proof.evidenceLevel, PROOF_LEVEL);
  assert.equal(proof.nativeExecutionQualified, false);
  assert.equal(proof.sharedFleetQualified, false);
  assert.equal(proof.liveCertbot, "pending");
  assert.equal(proof.hostCapabilityAbsentIsPass, false);
  assert.equal(proof.keyReuseRefused, true);
  assert.equal(proof.outsidePathRefused, true);
  assert.equal(proof.inUseKeyPreserved, true);
  assert.equal(proof.inUseKeyDeleted, false);
  assert.equal(proof.blanketNetshReset, false);
  return true;
}

function localProof(flags) {
  const proof = {
    scope: SCOPE,
    evidenceLevel: PROOF_LEVEL,
    nativeExecutionQualified: false,
    sharedFleetQualified: false,
    liveCertbot: "pending",
    hostCapabilityAbsentIsPass: false,
    keyReuseRefused: flags.keyReuseRefused === true,
    outsidePathRefused: flags.outsidePathRefused === true,
    inUseKeyPreserved: flags.inUseKeyPreserved === true,
    inUseKeyDeleted: false,
    blanketNetshReset: false,
  };
  verifyVariantProof(proof);
  return proof;
}

function assessLab(env = process.env) {
  const missing = [];
  if (env.CERTOPS_ACME_KEY_REUSE_LAB !== "1") missing.push("CERTOPS_ACME_KEY_REUSE_LAB");
  if (env.CERTOPS_REAL_ACME_CLIENT !== "certbot") missing.push("certbot");
  return { ok: missing.length === 0, missing, liveCertbot: "pending" };
}

function closedReport(reason, env = process.env) {
  const lab = assessLab(env);
  const now = new Date().toISOString();
  return {
    schemaVersion: 1,
    suite: SUITE,
    strict: true,
    status: "failed",
    evidenceLevel: SUITE_LEVEL,
    proofEvidenceLevel: PROOF_LEVEL,
    qualified: false,
    claimsQualification: false,
    hostCapabilityAbsentIsPass: false,
    nativeExecutionQualified: false,
    sharedFleetQualified: false,
    liveCertbot: "pending",
    inUseKeyDeleted: false,
    blanketNetshReset: false,
    startedAt: now,
    finishedAt: now,
    requiredScenarios: [...SCENARIOS],
    missingScenarios: [...SCENARIOS],
    scenarios: [],
    requiredSources: [...REQUIRED_SOURCES],
    catalogIds: [...CATALOG_IDS],
    promotesCatalogRows: false,
    reason: lab.ok
      ? "Live certbot execution is not claimed by this contract"
      : String(reason || `lab absent: ${lab.missing.join(",")}`),
    cleanup: { status: "failed", summary: "No certbot process was started" },
  };
}

function writeReport(reportPath, report) {
  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}

function run(options = {}) {
  const env = options.env || process.env;
  const report = closedReport(options.reason, env);
  const reportPath = options.reportPath || env[REPORT_ENV] || path.join("qualification-results", REPORT_FILE);
  if (options.write !== false) writeReport(reportPath, report);
  return report;
}

const variants = {
  SCOPE, SUITE, SUITE_LEVEL, PROOF_LEVEL, REPORT_FILE, REPORT_ENV, SCENARIOS, CATALOG_IDS, REQUIRED_SOURCES, PROOF_KEYS,
  contained, refuseBlanketReset, assertClientPath, createRun, registerKey, submitOrder, deleteKey, spkiOf,
  verifyProof: verifyVariantProof, localProof, assessLab, closedReport, writeReport, run,
};
module.exports = { assertOwnedMaterialRoot, MATERIAL_PATH_SCOPE, MATERIAL_PATH_FLAGS, MATERIAL_PATH_LIMITS, verifyMaterialPaths, materialPathObserver, qualifyKeyReuse, verifyProof, scope, scenarioName, fields, requiredSources, variants };
