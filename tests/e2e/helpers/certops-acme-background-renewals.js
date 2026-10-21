/**
 * Qualification: production default-cron ACME renewal
 *
 * Start unmodified apps/worker/src/runner.js certops without cron/interval/startup/
 * one-shot overrides: the real default is a minute cron. Require one naturally due
 * global profile/active period and zero active certificate jobs before startup. Two real
 * ticks must admit agent-executed renewals with distinct CA serials/SPKIs, advanced
 * expiry, protected matching keys, trusted served TLS, current-claim leaf evidence and
 * production scheduler audit. The local observer counts starts, maintenance summaries
 * and graceful shutdown, never supplies a sweep/result. Retain the controller in a fresh
 * process group and pin its child pidfd before exec; check
 * executable/parent/session/group/birth before descriptor-only SIGTERM. Reap the child,
 * close pidfd/controller and prove group absence before private/DB cleanup. Unknown
 * descendants/birth/closure preserve sticky ownership; no numeric PID kill fallback.
 * Both clients need their own native execution; direct sweeps and pure observer checks
 * do not qualify unattended worker timing.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/** Two actual CA renewals admitted by the unmodified production worker's
 * default minute cron. No scheduler call, clock override, inventory-date write
 * or synthetic job/result is permitted. Parent owns the existing agent/TLS and
 * registers all admitted jobs before any proof assertions. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  crypto = require("node:crypto");
const { isDeepStrictEqual } = require("node:util");
const runner = require("./certops-acme-background-runner");
const SCOPE = "real-linux-acme-production-worker-default-minute-cron";
const SCENARIO =
  "real ACME: production worker default minute cron renews twice";
const FLAGS = [
  "actualDefaultCron",
  "defaultSqlNowSelection",
  "twoAutomaticRealJobs",
  "claimBoundVerification",
  "distinctCaLeavesAndSerials",
  "freshSpkiEachGeneration",
  "advancingActualExpiry",
  "actualInventoryMatchesLatest",
  "trustedTlsEachGeneration",
  "protectedLocalKeyEachGeneration",
  "unchangedStoredProfile",
  "unchangedManagementPeriod",
  "isolatedGlobalFixture",
  "ownedJobsRegistered",
  "workerStoppedAndGroupDrained",
];
const REQUIRED_SOURCES = [
  ".github/workflows/certops-real-acme.yml",
  ".github/workflows/certops-alpine-acme-qualification.yml",
  "scripts/certops-alpine-bootstrap.sh",
  "tests/e2e/helpers/certops-acme-background-renewals.js",
  "tests/e2e/helpers/certops-acme-background-runner.js",
  "tests/e2e/helpers/certops-acme-background-pidfd.py",
  "tests/e2e/acme-real-journey.js",
  "tests/e2e/certops-agent-e2e.test.js",
  "apps/worker/src/runner.js",
  "apps/worker/src/certops-worker.js",
  "apps/worker/src/db.js",
  "apps/worker/src/logger.js",
  "apps/worker/src/is-node-entrypoint.js",
  "apps/worker/src/certops-metrics.js",
  "scripts/load-root-env.js",
  "apps/api/services/certops/renewalScheduler.js",
  "apps/api/services/certops/agentDispatch.js",
  "apps/api/services/certops/jobSigning.js",
  "packages/agent/src/index.js",
  "packages/agent/src/acme/index.js",
  "packages/agent/src/keys/index.js",
  "packages/agent/src/signing/index.js",
];
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "client",
      "schedulerInvocation",
      "successfulAutomationCycles",
      "sourceProfileId",
      "sourceProfileFingerprint",
      "jobIds",
      "fingerprints",
      "serials",
      "spkiFingerprints",
      "expiryEpochs",
      "workerLifecycle",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  assert.ok(["certbot", "acme.sh"].includes(value.client));
  assert.equal(
    value.schedulerInvocation,
    "actual-production-runner-default-cron",
  );
  assert.equal(value.successfulAutomationCycles, 2);
  for (const field of FLAGS) assert.equal(value[field], true, field);
  assert.match(
    value.sourceProfileId,
    /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i,
  );
  assert.match(value.sourceProfileFingerprint, /^[a-f0-9]{64}$/);
  for (const [name, count, pattern] of [
    ["jobIds", 2, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i],
    ["fingerprints", 3, /^[a-f0-9]{64}$/],
    ["spkiFingerprints", 3, /^[a-f0-9]{64}$/],
    ["serials", 3, /^[A-F0-9]{1,64}$/],
  ]) {
    assert.ok(Array.isArray(value[name]) && value[name].length === count);
    assert.equal(
      new Set(
        value[name].map((item) =>
          name === "jobIds" ? item.toLowerCase() : item,
        ),
      ).size,
      count,
    );
    for (const item of value[name]) assert.match(item, pattern);
  }
  assert.ok(
    Array.isArray(value.expiryEpochs) &&
      value.expiryEpochs.length === 3 &&
      value.expiryEpochs.every((x) => Number.isSafeInteger(x) && x > 0),
  );
  assert.ok(
    value.expiryEpochs[0] < value.expiryEpochs[1] &&
      value.expiryEpochs[1] < value.expiryEpochs[2],
  );
  runner.validateLifecycle(value.workerLifecycle);
  return true;
}
async function qualifyBackgroundRenewals({
  pool,
  workspaceId,
  agent,
  certificateId,
  certPath,
  keyPath,
  ownedJobIds,
  waitUntil,
  verifyDnsCleanup,
  verifyNames,
  servedFingerprint,
  repoRoot,
  acmeKind,
  workDir,
  ownedWorkers,
}) {
  assert.equal(process.platform, "linux");
  assert.ok(["certbot", "acme.sh"].includes(acmeKind));
  assert.ok(Array.isArray(ownedWorkers));
  const query = (sql, args = []) => pool.query(sql, args);
  const profile = async () =>
    (
      await query(
        "SELECT cp.id,cp.status,cp.renew_before_days,cp.public_metadata,cp.updated_at FROM managed_certificates mc JOIN certificate_profiles cp ON cp.workspace_id=mc.workspace_id AND cp.id=mc.profile_id WHERE mc.workspace_id=$1 AND mc.id=$2",
        [workspaceId, certificateId],
      )
    ).rows[0];
  const management = async () =>
    (
      await query(
        "SELECT id,started_at,ended_at,automation_enabled FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 ORDER BY started_at",
        [workspaceId, certificateId],
      )
    ).rows;
  const beforeProfile = await profile(),
    beforePeriod = await management();
  assert.equal(beforeProfile.status, "active");
  assert.equal(
    beforeProfile.public_metadata.renewalProfile.keyRotationPolicy
      .rotateOnRenew,
    true,
    "Run background rotations before key-reuse variant",
  );
  assert.equal(
    beforePeriod.filter(
      (row) => row.ended_at === null && row.automation_enabled === true,
    ).length,
    1,
  );
  assert.equal(
    Number(
      (await query("SELECT count(*)::int AS count FROM certificate_profiles"))
        .rows[0].count,
    ),
    1,
  );
  assert.equal(
    Number(
      (
        await query(
          "SELECT count(*)::int AS count FROM certificate_jobs WHERE status IN ('pending','pending_approval','approved','claimed','running','awaiting_issuer')",
        )
      ).rows[0].count,
    ),
    0,
  );
  const initialIds = (
    await query(
      "SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2",
      [workspaceId, String(certificateId)],
    )
  ).rows.map((row) => row.id);
  const register = async () => {
    const rows = (
      await query(
        "SELECT id,status,operation,source,mode,claim_id,idempotency_key,payload,result_metadata FROM certificate_jobs WHERE workspace_id=$1 AND subject_id=$2 AND NOT(id=ANY($3::uuid[])) ORDER BY created_at,id",
        [workspaceId, String(certificateId), initialIds],
      )
    ).rows;
    for (const row of rows)
      if (!ownedJobIds.includes(row.id)) ownedJobIds.push(row.id);
    return rows;
  };
  const leaves = [];
  const observe = async () => {
    const leaf = new crypto.X509Certificate(fs.readFileSync(certPath));
    verifyNames(leaf);
    const st = fs.lstatSync(keyPath);
    assert.ok(st.isFile() && !st.isSymbolicLink() && st.nlink === 1);
    assert.equal(st.mode & 0o777, 0o600);
    assert.equal(st.uid, process.getuid());
    assert.ok(
      leaf.checkPrivateKey(crypto.createPrivateKey(fs.readFileSync(keyPath))),
    );
    assert.equal(await servedFingerprint(), leaf.fingerprint256);
    await verifyDnsCleanup();
    if (leaves.length) {
      assert.ok(Date.parse(leaf.validTo) > Date.parse(leaves.at(-1).validTo));
      for (const prior of leaves) {
        assert.notEqual(leaf.serialNumber, prior.serialNumber);
        assert.notEqual(leaf.fingerprint256, prior.fingerprint256);
        assert.ok(
          !leaf.publicKey
            .export({ type: "spki", format: "der" })
            .equals(prior.publicKey.export({ type: "spki", format: "der" })),
        );
      }
    }
    leaves.push(leaf);
  };
  await observe();
  const scheduler = require("../../../apps/api/services/certops/renewalScheduler");
  const due = await scheduler.findCertificatesDueForRenewal({
    db: pool,
    thresholdDays: scheduler.DEFAULT_RENEWAL_THRESHOLD_DAYS,
    terminalStatuses: scheduler.RENEWAL_JOB_TERMINAL_STATUSES,
  });
  assert.equal(
    due.length,
    1,
    "Actual default SQL-NOW scan must remain globally isolated",
  );
  assert.equal(String(due[0].id), String(certificateId));
  assert.equal(due[0].workspace_id, workspaceId);
  const initialInventory = (
    await query(
      "SELECT not_after,profile_id FROM managed_certificates WHERE workspace_id=$1 AND id=$2 AND not_after<=NOW()+INTERVAL '30 days'",
      [workspaceId, certificateId],
    )
  ).rows[0];
  assert.ok(initialInventory);
  assert.equal(
    new Date(initialInventory.not_after).getTime(),
    Date.parse(leaves[0].validTo),
  );
  const initialKey =
    require("../../../apps/api/services/certops/renewalScheduler").renewalIdempotencyKey(
      certificateId,
      initialInventory.not_after,
    );
  assert.equal(
    (
      await query(
        "SELECT 1 FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key=$2",
        [workspaceId, initialKey],
      )
    ).rows.length,
    0,
    "No automatic generation may predate the actual worker",
  );
  let resource, lifecycle;
  const jobs = [];
  try {
    resource = await runner.startOwnedRunner({
      root: workDir,
      repoRoot,
      until: waitUntil,
      onCreated: (value) => {
        resource = value;
        ownedWorkers.push(value);
      },
    });
    for (let cycle = 0; cycle < 2; cycle++) {
      const inventory =
        cycle === 0
          ? initialInventory
          : (
              await query(
                "SELECT not_after,profile_id FROM managed_certificates WHERE workspace_id=$1 AND id=$2 AND not_after<=NOW()+INTERVAL '30 days'",
                [workspaceId, certificateId],
              )
            ).rows[0];
      assert.ok(
        inventory,
        "Default SQL-NOW selection must remain naturally due",
      );
      assert.equal(
        new Date(inventory.not_after).getTime(),
        Date.parse(leaves[cycle].validTo),
      );
      const key =
        require("../../../apps/api/services/certops/renewalScheduler").renewalIdempotencyKey(
          certificateId,
          inventory.not_after,
        );
      const current = await waitUntil(async () => {
        resource.check();
        assert.equal(agent.exitCode, null);
        assert.equal(agent.signalCode, null);
        const rows = await register();
        assert.ok(rows.length <= 2, "Unexpected extra automation generation");
        const row = rows.find((item) => item.idempotency_key === key);
        if (!row) return false;
        if (
          [
            "failed",
            "rejected",
            "cancelled",
            "blocked",
            "orphaned_unknown_effect",
          ].includes(row.status)
        )
          throw new Error("Actual cron renewal terminated unsuccessfully");
        return row.status === "succeeded" ? row : false;
      }, 240000);
      assert.equal(current.source, "automation");
      assert.equal(current.mode, "real");
      assert.equal(current.operation, "renew");
      assert.ok(current.claim_id);
      assert.equal(current.payload.keyRotation, true);
      assert.equal(current.result_metadata.keyRotated, true);
      assert.equal(current.payload.acmeKind, acmeKind);
      assert.deepEqual(
        current.payload.renewalProfile,
        beforeProfile.public_metadata.renewalProfile,
      );
      assert.equal(current.payload.certPath, certPath);
      assert.ok(
        (
          await query(
            "SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.claim_id=j.claim_id AND e.evidence_type='validation.passed' AND e.metadata->>'step'='verify'",
            [workspaceId, current.id],
          )
        ).rows.length,
      );
      jobs.push(current.id);
      await observe();
      await waitUntil(async () => {
        const actual = (
          await query(
            "SELECT fingerprint_sha256,not_after,profile_id FROM managed_certificates WHERE workspace_id=$1 AND id=$2",
            [workspaceId, certificateId],
          )
        ).rows[0];
        return (
          actual &&
          String(actual.fingerprint_sha256).replace(/:/g, "").toLowerCase() ===
            sha(leaves.at(-1).raw) &&
          new Date(actual.not_after).getTime() ===
            Date.parse(leaves.at(-1).validTo) &&
          actual.profile_id === beforeProfile.id
        );
      }, 30000);
      const verification = (
        await query(
          "SELECT e.metadata FROM certificate_evidence e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.job_id WHERE e.workspace_id=$1 AND e.job_id=$2 AND e.claim_id=j.claim_id AND e.evidence_type='validation.passed' AND e.metadata->>'step'='verify'",
          [workspaceId, current.id],
        )
      ).rows;
      assert.ok(
        verification.some(
          (row) =>
            String(row.metadata.fingerprintSha256)
              .replace(/:/g, "")
              .toLowerCase() === sha(leaves.at(-1).raw) &&
            Date.parse(row.metadata.validTo) ===
              Date.parse(leaves.at(-1).validTo),
        ),
      );
      const audit = (
        await query(
          "SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_JOB_CREATED_AUTOMATIC' AND metadata->>'jobId'=$2",
          [workspaceId, current.id],
        )
      ).rows;
      assert.equal(audit.length, 1);
      assert.equal(audit[0].metadata.trigger, "renewal_scheduler");
      assert.ok(isDeepStrictEqual(await profile(), beforeProfile));
      assert.ok(isDeepStrictEqual(await management(), beforePeriod));
    }
    lifecycle = await resource.stopAndDrain();
    runner.validateLifecycle(lifecycle);
    assert.equal((await register()).length, 2);
  } finally {
    try {
      if (resource) await resource.stopAndDrain();
    } finally {
      await register();
    }
  }
  const proof = {
    scope: SCOPE,
    client: acmeKind,
    schedulerInvocation: "actual-production-runner-default-cron",
    successfulAutomationCycles: 2,
    sourceProfileId: beforeProfile.id,
    sourceProfileFingerprint: sha(JSON.stringify(beforeProfile)),
    jobIds: jobs,
    fingerprints: leaves.map((leaf) => sha(leaf.raw)),
    serials: leaves.map((leaf) => leaf.serialNumber),
    spkiFingerprints: leaves.map((leaf) =>
      sha(leaf.publicKey.export({ type: "spki", format: "der" })),
    ),
    expiryEpochs: leaves.map((leaf) => Date.parse(leaf.validTo)),
    workerLifecycle: lifecycle,
    ...Object.fromEntries(FLAGS.map((field) => [field, true])),
  };
  verifyProof(proof);
  return proof;
}
module.exports = {
  SCOPE,
  SCENARIO,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  qualifyBackgroundRenewals,
};
