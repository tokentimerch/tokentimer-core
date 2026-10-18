"use strict";
// Pure lifecycle controls: no worker, native process, service or CA is launched.
const test = require("node:test");
const assert = require("node:assert/strict");
const {
  runnerEnvironment,
  observeRecord,
  validateLifecycle,
} = require("../tests/e2e/helpers/certops-adcs-worker-runner-child");
function environment() {
  return {
    DB_HOST: "owned",
    DB_PORT: "5432",
    DB_USER: "owned",
    DB_PASSWORD: "fixture",
    DB_NAME: "owned",
    CERTOPS_SIGNING_ENCRYPTION_KEY: "a".repeat(64),
    CERTOPS_REGISTRATION_ENCRYPTION_KEY: "b".repeat(64),
  };
}
function valid() {
  return {
    failed: false,
    starts: 1,
    ticks: 2,
    finishes: 2,
    summaries: 2,
    created: 2,
    stops: 1,
    forwarded: true,
    firstTickElapsedMs: 60001,
    exitCode: 0,
    nativeDrained: true,
    bridgeReady: true,
  };
}
test("background runner preserves real default interval and strips unsafe inherited configuration", () => {
  const env = runnerEnvironment(
    {
      ...environment(),
      NODE_OPTIONS: "--require secret",
      NODE_PATH: "foreign",
      CERTOPS_ADCS_OFFICER_PASSWORD: "private",
      WORKER_CERTOPS_INTERVAL_MS: "1",
      WORKER_CERTOPS_RUN_ON_START: "true",
      WORKER_ONCE: "true",
      CERTOPS_SWEEP_RENEWALS_ENABLED: "false",
    },
    "a".repeat(32),
  );
  assert.equal(env.WORKER_CERTOPS_CRON, "interval");
  for (const key of [
    "NODE_OPTIONS",
    "NODE_PATH",
    "CERTOPS_ADCS_OFFICER_PASSWORD",
    "WORKER_CERTOPS_INTERVAL_MS",
    "WORKER_CERTOPS_RUN_ON_START",
    "WORKER_ONCE",
    "CERTOPS_SWEEP_RENEWALS_ENABLED",
  ])
    assert.equal(Object.hasOwn(env, key), false);
  assert.equal(env.CERTOPS_SIGNING_ENCRYPTION_KEY, "a".repeat(64));
  assert.throws(() =>
    runnerEnvironment(
      { ...environment(), CERTOPS_SIGNING_ENCRYPTION_KEY: "" },
      "a".repeat(32),
    ),
  );
});
test("actual lifecycle requires two real ticks, two created jobs and confirmed graceful native drain", () => {
  assert.equal(validateLifecycle(valid()), true);
  for (const [key, value] of Object.entries({
    failed: true,
    starts: 2,
    ticks: 1,
    finishes: 1,
    summaries: 1,
    created: 3,
    stops: 0,
    forwarded: false,
    firstTickElapsedMs: 59999,
    exitCode: 1,
    nativeDrained: false,
  }))
    assert.throws(() => validateLifecycle({ ...valid(), [key]: value }), key);
});
test("production lifecycle projection refuses alternate schedules and maintenance errors", () => {
  const state = {
    starts: 0,
    ticks: 0,
    finishes: 0,
    summaries: 0,
    created: 0,
    stops: 0,
    failed: false,
  };
  observeRecord(
    state,
    {
      message: "worker-runner-worker-started",
      worker: "certops",
      scheduleMode: "interval",
      intervalMs: 60000,
      runOnStart: false,
    },
    0,
  );
  observeRecord(
    state,
    {
      message: "worker-runner-job-start",
      worker: "certops",
      trigger: "interval",
    },
    60010,
  );
  assert.equal(state.firstTickElapsedMs, 60010);
  assert.throws(() =>
    observeRecord(
      state,
      {
        message: "worker-runner-worker-started",
        worker: "certops",
        scheduleMode: "interval",
        intervalMs: 1,
        runOnStart: false,
      },
      0,
    ),
  );
  assert.throws(() =>
    observeRecord(
      state,
      {
        message: "CertOps maintenance worker finished",
        renewalScheduler: { created: 1, errors: ["failed"] },
      },
      60010,
    ),
  );
  observeRecord(state, { level: "error" }, 60010);
  assert.equal(state.failed, true);
});

test("background registry cannot broaden capacity selectors and unresolved worker preserves custody", () => {
  const cleanup = require("../tests/e2e/helpers/certops-adcs-webhosting-renewal");
  const registry = [];
  const receipt = cleanup.registerBackgroundStoreCertificate(registry, {
    domain: "certops-adcs-1234567890-rsa2048.example.test",
    certificateId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    enrollmentIds: [],
  });
  assert.equal(
    cleanup.backgroundCleanupPlan(receipt, [], () => null).length,
    0,
  );
  assert.throws(() => cleanup.capacityCleanupPlan(receipt, [], () => null));
  receipt.workerPendingVerification = true;
  assert.throws(() => cleanup.backgroundCleanupPlan(receipt, [], () => null));
  assert.throws(() => cleanup.assertRegisteredCleanupComplete(registry));
});

test("later primary leaves require parent IDs and exact durable accepted store ownership", () => {
  const cleanup = require("../tests/e2e/helpers/certops-adcs-webhosting-renewal");
  const registry = [],
    id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const receipt = cleanup.registerBackgroundStoreCertificate(registry, {
    domain: "certops-adcs-1234567890-rsa2048.example.test",
    certificateId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    enrollmentIds: [],
  });
  const record = (containerName) => ({
    certificateId: receipt.certificateId,
    status: "enrolled_by_agent",
    containerName,
    jobId: id,
    acceptedStore: "My",
    acceptedThumbprint: "A".repeat(40),
  });
  const ownership = {
    workspaceId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    rows: [
      {
        id,
        workspace_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        certificate_id: receipt.certificateId,
        state: "installed",
        job_ids: [id],
      },
    ],
    readJournal: () => ({
      kind: "valid",
      journal: {
        containerName: `tokentimer-enr-${id}`,
        state: "installed",
        leafSha256: "a".repeat(64),
      },
    }),
  };
  cleanup.refreshBackgroundEnrollmentOwnership(
    registry,
    [id],
    record,
    ownership,
  );
  assert.deepEqual(receipt.enrollmentIds, [id]);
  for (const changed of [
    { ...ownership, rows: [] },
    { ...ownership, readJournal: () => ({ kind: "corrupt" }) },
    { ...ownership, rows: [{ ...ownership.rows[0], job_ids: [] }] },
  ])
    assert.throws(() =>
      cleanup.refreshBackgroundEnrollmentOwnership(
        registry,
        [id],
        record,
        changed,
      ),
    );
  const next = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  assert.throws(() =>
    cleanup.refreshBackgroundEnrollmentOwnership(
      registry,
      [next],
      (name) => ({ ...record(name), acceptedStore: "WebHosting" }),
      ownership,
    ),
  );
  assert.deepEqual(receipt.enrollmentIds, [id]);
  receipt.workerPendingVerification = true;
  assert.throws(() =>
    cleanup.refreshBackgroundEnrollmentOwnership(
      registry,
      [next],
      record,
      ownership,
    ),
  );
});
