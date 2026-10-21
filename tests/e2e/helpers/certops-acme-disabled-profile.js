/**
 * Qualification: manual renewal while automation disabled
 *
 * In Ubuntu 24.04/certbot/noEAB after result-outbox restart, reopen the second exact
 * bulk certificate's own management period with its real stored profile. Production
 * SQL-NOW/default-threshold/terminal-status selector must include it, then exclude it
 * after public autoRenewEnabled:false. Real public manual renewal must still get current
 * signed claim, actual CA leaf/new serial+SPKI, matching protected key, trusted TLS and
 * claim-bound evidence while stored profile stays disabled. Public re-enable must make
 * the same row selectable again; stop only the newly opened period. Do not inject
 * clocks/expiry/query/scheduler or fabricate inventory. No sweep or background worker
 * runs; keep those proof flags false. Preserve primary pair/TLS/ policy. Register sticky
 * ownership before mutation; exact receipt bytes/identity, listener/socket drain and
 * period closure precede release, otherwise preserve DB and private root. Sidecar
 * acme-disabled-profile-proof.json binds second bulk item and generation. No scheduler
 * zero-job, archived-profile or concurrency claim.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/** Actual owned native manual renewal while automatic renewal is disabled.
 * Only the production SQL-NOW selector is invoked; no scheduler/worker claim. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  tls = require("node:tls");
const { isDeepStrictEqual } = require("node:util");
const bulk = require("./certops-acme-bulk-renewal"),
  reader = require("./certops-acme-native-adoption").readOwnedBytes,
  scheduler = require("../../../apps/api/services/certops/renewalScheduler");
const SCOPE = "native-manual-renewal-under-disabled-automatic-profile";
const SCENARIO = "real-acme-disabled-profile-native-manual-renewal";
const FIELD = "nativeAcmeDisabledProfile",
  SIDECAR = "qualification-results/acme-disabled-profile-proof.json";
const FLAGS = Object.freeze([
  "actualOwnedPriorNativeGeneration",
  "actualPublicManagementReadd",
  "actualPublicDisable",
  "productionNowSelectionExcludesDisabled",
  "actualPublicManualAdmission",
  "actualSignedCurrentClaim",
  "actualCaLeafAndNewKey",
  "trustedTlsMatchesDeployment",
  "currentClaimVerification",
  "profileRemainsDisabledAfterSuccess",
  "actualPublicReenable",
  "productionNowSelectionIncludesEnabled",
  "executionPolicyPreserved",
  "originalServingPreserved",
  "ownedPeriodStopped",
  "retainedTlsDrained",
  "ownershipGuardReleased",
]);
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    ...bulk.REQUIRED_SOURCES,
    "tests/e2e/helpers/certops-acme-disabled-profile.js",
    "tests/e2e/helpers/certops-acme-native-adoption.js",
    "apps/api/services/certops/renewalScheduler.js",
    "apps/api/services/certops/renewalProfileAdmin.js",
    "apps/api/services/certops/certificateIdentity.js",
  ]),
]);
const active = new Set(),
  GUARD = ".native-disabled-profile-active";
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
function verifyProof(p) {
  assert.ok(p && typeof p === "object");
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "certificateId",
      "profileId",
      "jobId",
      "claimId",
      "fingerprints",
      "schedulerSweepQualified",
      "backgroundWorkerQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  for (const k of ["certificateId", "profileId", "jobId", "claimId"])
    assert.match(p[k], UUID);
  assert.ok(
    Array.isArray(p.fingerprints) &&
      p.fingerprints.length === 2 &&
      p.fingerprints.every(
        (x) => typeof x === "string" && /^[a-f0-9]{64}$/.test(x),
      ) &&
      new Set(p.fingerprints).size === 2,
  );
  assert.equal(p.schedulerSweepQualified, false);
  assert.equal(p.backgroundWorkerQualified, false);
  for (const k of FLAGS) assert.equal(p[k], true);
  return true;
}
function verifyAgainstBulk(p, previous) {
  verifyProof(p);
  bulk.verifyProof(previous);
  assert.equal(p.certificateId, previous.certificateIds[1]);
  assert.equal(p.fingerprints[0], previous.fingerprints[3]);
  assert.ok(
    ![...previous.fingerprints, previous.originalServingFingerprint].includes(
      p.fingerprints[1],
    ),
    "Fresh native leaf must not reuse any prior generation",
  );
  assert.ok(
    ![...previous.issueJobIds, ...previous.jobIds]
      .map((x) => x.toLowerCase())
      .includes(p.jobId.toLowerCase()),
  );
  assert.ok(
    !previous.claimIds
      .map((x) => x.toLowerCase())
      .includes(p.claimId.toLowerCase()),
  );
  return true;
}
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(path.resolve(root)) && !fs.existsSync(path.join(root, GUARD)),
    "Preserve unresolved disabled-profile native state",
  );
}
async function qualify(c) {
  assert.equal(process.platform, "linux");
  assert.equal(c.acmeKind, "certbot");
  bulk.verifyProof(c.bulkProof);
  const root = fs.realpathSync(c.workDir);
  assert.equal(root, path.resolve(c.workDir));
  assertCleanupSafe(root);
  assert.ok(Array.isArray(c.ownedProfileResources));
  assert.ok(Array.isArray(c.ownedWorkers) && c.ownedWorkers.length > 0);
  assert.ok(
    Array.isArray(c.ownedBulkResources) && c.ownedBulkResources.length > 0,
  );
  for (const resource of c.ownedBulkResources) {
    assert.equal(resource.hasOwnershipReceipt(), false);
    assert.equal(resource.hasLiveResource(), false);
  }
  for (const worker of c.ownedWorkers) {
    assert.equal(worker.hasOwnershipReceipt(), false);
    require("./certops-acme-background-runner").validateLifecycle(
      worker.getState(),
    );
  }
  const certificateId = c.bulkProof.certificateIds[1],
    certPath = path.join(root, "bulk-item-1/fullchain.pem"),
    keyPath = path.join(c.configDir, "keys", certificateId + ".key.pem");
  const material = () => {
    const cert = reader(certPath),
      key = reader(keyPath),
      leaf = new crypto.X509Certificate(cert);
    assert.equal(leaf.checkHost(c.domain), c.domain);
    assert.equal(leaf.checkPrivateKey(crypto.createPrivateKey(key)), true);
    return {
      cert,
      key,
      leaf,
      fp: sha(leaf.raw),
      spki: sha(leaf.publicKey.export({ type: "spki", format: "der" })),
    };
  };
  const before = material();
  assert.equal(before.fp, c.bulkProof.fingerprints[3]);
  assert.equal(before.spki, c.bulkProof.spkiFingerprints[3]);
  const query = (sql, args = []) => c.pool.query(sql, args),
    prefix = `/api/v1/workspaces/${c.workspaceId}/certops`;
  const profile = async (subject = certificateId) =>
    (
      await query(
        "SELECT cp.id,cp.name,cp.status,cp.issuer_id,cp.renew_before_days,cp.description,cp.key_mode,cp.source,cp.source_ref,cp.public_metadata FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2",
        [c.workspaceId, subject],
      )
    ).rows[0];
  const original = await profile();
  const primaryProfile = await profile(c.certificateId);
  assert.ok(primaryProfile && primaryProfile.id !== original.id);
  assert.match(original.id, UUID);
  assert.equal(original.status, "active");
  assert.equal(
    original.public_metadata.renewalProfile.keyRotationPolicy.rotateOnRenew,
    true,
  );
  const primaryCert = reader(c.certPath),
    primaryKey = reader(c.keyPath),
    primaryFp = await c.servedFingerprint();
  const guard = path.join(root, GUARD),
    bytes = Buffer.from(crypto.randomBytes(32).toString("hex"));
  let complete = false,
    closed = false,
    server;
  const sockets = new Set();
  active.add(root);
  const resource = {
    hasOwnershipReceipt: () => !complete || fs.existsSync(guard),
    hasLiveResource: () => (!!server && !closed) || sockets.size > 0,
    async close() {
      for (const s of sockets) s.destroy();
      if (server && !closed)
        await new Promise((resolve, reject) =>
          server.close((e) =>
            e
              ? reject(Error("Owned disabled-profile listener failed to drain"))
              : ((closed = true), resolve()),
          ),
        );
      await c.waitUntil(() => sockets.size === 0, 5000);
    },
  };
  c.ownedProfileResources.push(resource);
  fs.writeFileSync(guard, bytes, { flag: "wx", mode: 0o600 });
  const guardId = fs.lstatSync(guard, { bigint: true });
  const samePolicy = async (status) => {
    const current = await profile();
    assert.equal(current.status, status);
    assert.ok(
      isDeepStrictEqual({ ...current, status: original.status }, original),
      "Operator execution policy changed",
    );
  };
  const due = async () =>
    new Set(
      (
        await scheduler.findCertificatesDueForRenewal({
          db: c.pool,
          thresholdDays: scheduler.resolveRenewalThresholdDays(process.env),
          terminalStatuses: scheduler.RENEWAL_JOB_TERMINAL_STATUSES,
        })
      ).map((x) => x.id),
    );
  const tlsOptions = c.primaryTlsOptions();
  assert.ok(tlsOptions.ca, "Explicit owned CA trust required");
  try {
    server = tls.createServer(
      {
        cert: before.cert,
        key: before.key,
        SNICallback(name, callback) {
          try {
            assert.equal(name, c.domain);
            const m = material();
            callback(
              null,
              tls.createSecureContext({ cert: m.cert, key: m.key }),
            );
          } catch {
            callback(Error("Owned native profile TLS unavailable"));
          }
        },
      },
      (s) => s.end(),
    );
    server.on("connection", (s) => {
      sockets.add(s);
      s.once("close", () => sockets.delete(s));
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const peer = () =>
      new Promise((resolve, reject) => {
        let fp,
          failure = false;
        const s = tls.connect(
          {
            host: "127.0.0.1",
            port: server.address().port,
            servername: c.domain,
            ca: tlsOptions.ca,
            rejectUnauthorized: true,
          },
          () => {
            try {
              assert.equal(s.authorized, true);
              fp = sha(s.getPeerCertificate().raw);
            } catch {
              failure = true;
            }
            s.end();
          },
        );
        sockets.add(s);
        s.setTimeout(10000, () => s.destroy());
        s.on("error", () => (failure = true));
        s.once("close", () => {
          sockets.delete(s);
          if (!failure && fp) resolve(fp);
          else
            reject(
              Error("Owned native profile TLS observation failed after drain"),
            );
        });
      });
    assert.equal(await peer(), before.fp);
    assert.equal(
      (
        await query(
          "SELECT count(*)::int AS count FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
          [c.workspaceId, certificateId],
        )
      ).rows[0].count,
      0,
    );
    const readd = await c.publicSession.request(
      `${prefix}/sources/${certificateId}/readd`,
      "POST",
      { renewalProfileId: original.id, automationEnabled: true },
    );
    assert.equal(readd.status, 201);
    assert.equal(readd.body.managedCertificateId, certificateId);
    const periodId = readd.body.periodId;
    assert.match(periodId, UUID);
    assert.ok((await due()).has(certificateId));
    const toggle = async (enabled) => {
      const changed = await c.publicSession.request(
        `${prefix}/profiles/${original.id}`,
        "PATCH",
        { autoRenewEnabled: enabled },
      );
      assert.equal(changed.status, 200);
      assert.equal(changed.body.status, enabled ? "active" : "disabled");
      await samePolicy(enabled ? "active" : "disabled");
    };
    await toggle(false);
    assert.equal((await due()).has(certificateId), false);
    const submitted = await c.publicSession.request(`${prefix}/jobs`, "POST", {
      operation: "renew",
      subjectType: "managed_certificate",
      subjectId: certificateId,
      idempotencyKey: crypto.randomUUID(),
    });
    if (submitted.body?.job?.id) c.ownedJobIds.push(submitted.body.job.id);
    assert.equal(submitted.status, 201);
    const jobId = submitted.body.job.id;
    assert.match(jobId, UUID);
    const job = await c.waitUntil(async () => {
      const row = (
        await query(
          "SELECT j.status,j.operation,j.source,j.mode,j.subject_id,j.claim_id,j.claimed_by_agent_id,j.attempt_count,j.payload,j.result_metadata,a.agent_id FROM certificate_jobs j JOIN certops_agents a ON a.id=j.claimed_by_agent_id AND a.workspace_id=j.workspace_id WHERE j.workspace_id=$1 AND j.id=$2",
          [c.workspaceId, jobId],
        )
      ).rows[0];
      return ["succeeded", "failed", "cancelled", "rejected"].includes(
        row?.status,
      )
        ? row
        : null;
    });
    assert.equal(job.status, "succeeded");
    assert.equal(job.agent_id, c.agentId);
    assert.equal(job.operation, "renew");
    assert.equal(job.source, "api");
    assert.equal(job.mode, "real");
    assert.equal(job.subject_id, certificateId);
    assert.equal(job.attempt_count, 1);
    assert.match(job.claim_id, UUID);
    assert.equal(
      (
        await query(
          "SELECT count(*)::int AS count FROM certops_consumed_nonces WHERE workspace_id=$1 AND job_id=$2 AND issued_to_agent_id=$3",
          [c.workspaceId, jobId, job.claimed_by_agent_id],
        )
      ).rows[0].count,
      1,
    );
    assert.equal(job.result_metadata.keyRotated, true);
    assert.equal(job.payload.certificateId, certificateId);
    assert.ok(
      isDeepStrictEqual(
        job.payload.renewalProfile,
        original.public_metadata.renewalProfile,
      ),
      "Actual signed snapshot changed execution policy",
    );
    const after = material();
    assert.notEqual(after.fp, before.fp);
    assert.notEqual(after.spki, before.spki);
    assert.notEqual(after.leaf.serialNumber, before.leaf.serialNumber);
    assert.equal(await peer(), after.fp);
    await c.verifyDnsCleanup();
    const evidence = (
      await query(
        "SELECT metadata FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND claim_id=$3 AND evidence_type='validation.passed' AND metadata->>'step'='verify'",
        [c.workspaceId, jobId, job.claim_id],
      )
    ).rows;
    assert.ok(
      evidence.some(
        (x) =>
          String(x.metadata.fingerprintSha256)
            .replaceAll(":", "")
            .toLowerCase() === after.fp,
      ),
    );
    await samePolicy("disabled");
    assert.equal((await due()).has(certificateId), false);
    await toggle(true);
    assert.ok((await due()).has(certificateId));
    const stopped = await c.publicSession.request(
      `${prefix}/management-periods/${periodId}/stop`,
      "POST",
      {},
    );
    assert.equal(stopped.status, 200);
    assert.equal(
      (
        await query(
          "SELECT count(*)::int AS count FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
          [c.workspaceId, certificateId],
        )
      ).rows[0].count,
      0,
    );
    assert.ok(
      reader(c.certPath).equals(primaryCert) &&
        reader(c.keyPath).equals(primaryKey),
      "Original serving custody changed",
    );
    assert.equal(await c.servedFingerprint(), primaryFp);
    assert.ok(
      isDeepStrictEqual(await profile(c.certificateId), primaryProfile),
      "Original serving profile changed",
    );
    await resource.close();
    assert.ok(reader(guard, 128, guardId).equals(bytes));
    fs.unlinkSync(guard);
    active.delete(root);
    complete = true;
    const proof = {
      scope: SCOPE,
      certificateId,
      profileId: original.id,
      jobId,
      claimId: job.claim_id,
      fingerprints: [before.fp, after.fp],
      schedulerSweepQualified: false,
      backgroundWorkerQualified: false,
      ...Object.fromEntries(FLAGS.map((x) => [x, true])),
    };
    verifyAgainstBulk(proof, c.bulkProof);
    return proof;
  } finally {
    await resource.close();
  }
}
module.exports = {
  SCOPE,
  SCENARIO,
  FIELD,
  SIDECAR,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  verifyAgainstBulk,
  assertCleanupSafe,
  qualify,
};
