"use strict";
/** Pure boundary tests only; synthetic timestamps never qualify a native lane. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  h = require("../tests/e2e/helpers/certops-windows-alive-grace-proof");
function fixture() {
  const base = Date.parse("2026-01-01T00:00:00.000Z"),
    iso = (ms) => new Date(base + ms).toISOString();
  return {
    scope: h.SCOPE,
    jobId: "11111111-1111-4111-8111-111111111111",
    claimId: "22222222-2222-4222-8222-222222222222",
    attemptCount: 1,
    terminalStatus: "orphaned_unknown_effect",
    defaultLeaseMs: 900000,
    defaultHardGraceMs: 3600000,
    defaultOfflineMs: 600000,
    heartbeatUptimeSeconds: [1, 1001, 4501],
    waitedMonotonicMs: 4500001,
    fingerprints: ["a".repeat(64), "b".repeat(64)],
    spkiFingerprints: ["c".repeat(64), "d".repeat(64)],
    atomicTreeContainmentQualified: false,
    claimPollingAvailabilityQualified: false,
    originalOperationAutomaticallyRecovered: false,
    deployedWorkerLoopQualified: false,
    leaseRenewedAt: iso(0),
    leaseExpiresAt: iso(900000),
    nativeCompletedAt: iso(100000),
    deferredObservedAt: iso(1000000),
    deferredHeartbeatAt: iso(999000),
    terminalObservedAt: iso(4500001),
    terminalHeartbeatAt: iso(4500000),
    ...Object.fromEntries(h.FLAGS.map((f) => [f, true])),
  };
}
test("closed default grace contract requires genuine wall and monotonic deadlines with fresh alive observations", () => {
  h.verifyProof(fixture());
  for (const patch of [
    { defaultHardGraceMs: 60000 },
    { waitedMonotonicMs: 4499999 },
    { terminalObservedAt: "2026-01-01T01:15:00.000Z" },
    { terminalHeartbeatAt: "2026-01-01T01:00:00.000Z" },
    { originalOperationAutomaticallyRecovered: true },
    { deployedWorkerLoopQualified: true },
    { terminalStatus: "succeeded" },
    { rawOutbox: "secret" },
  ])
    assert.throws(() => h.verifyProof({ ...fixture(), ...patch }));
});
test("every measured native fact remains mandatory and flags cannot substitute for the deadline", () => {
  for (const flag of h.FLAGS) {
    const p = fixture();
    delete p[flag];
    assert.throws(() => h.verifyProof(p));
    assert.throws(() => h.verifyProof({ ...fixture(), [flag]: false }));
  }
  assert.throws(() =>
    h.verifyProof({
      ...fixture(),
      leaseExpiresAt: "2026-01-01T00:15:00.0000000Z",
    }),
  );
});

test("actual reaper row validator refuses changed lease, stale agent and wrong current claim", () => {
  const r = require("../tests/e2e/helpers/certops-windows-alive-grace-reaper"),
    p = fixture(),
    ids = {
      jobId: p.jobId,
      claimId: p.claimId,
      agentRowId: "33333333-3333-4333-8333-333333333333",
    };
  const row = {
    id: ids.jobId,
    status: "running",
    executor_kind: "agent",
    attempt_count: 1,
    claim_id: ids.claimId,
    claimed_by_agent_id: ids.agentRowId,
    agent_status: "active",
    uptime_seconds: "10",
    needs_operator_reconciliation: false,
    database_now: "2026-01-01T00:20:00.000Z",
    last_seen_at: "2026-01-01T00:19:59.000Z",
    lease_renewed_at: p.leaseRenewedAt,
    lease_expires_at: p.leaseExpiresAt,
  };
  assert.equal(r.verifyRunning(row, row, ids).uptime_seconds, 10);
  for (const patch of [
    { claim_id: ids.jobId },
    { attempt_count: 2 },
    { uptime_seconds: 9 },
    { agent_status: "offline" },
    { last_seen_at: "2026-01-01T00:10:00.000Z" },
    {
      lease_renewed_at: "2026-01-01T00:00:01.000Z",
      lease_expires_at: "2026-01-01T00:15:01.000Z",
    },
    { needs_operator_reconciliation: true },
  ])
    assert.throws(() => r.verifyRunning({ ...row, ...patch }, row, ids));
});

test("actual native producer accepts only the same signed claim succeeded durable outcome", () => {
  const h = require("../tests/e2e/helpers/certops-windows-alive-grace"),
    p = fixture(),
    job = { id: p.jobId, claim_id: p.claimId },
    nonce = "public-fixture-nonce",
    entry = {
      result: {
        jobId: p.jobId,
        claimId: p.claimId,
        nonce,
        status: "succeeded",
      },
      evidence: [],
    };
  h.verifyDurableSuccess(entry, job, nonce);
  for (const patch of [
    { jobId: p.claimId },
    { claimId: p.jobId },
    { nonce: "other" },
    { status: "failed" },
  ])
    assert.throws(() =>
      h.verifyDurableSuccess(
        { ...entry, result: { ...entry.result, ...patch } },
        job,
        nonce,
      ),
    );
});

test("late in-flight lease completion can precede stable capture without rewriting completion time", () => {
  const p = fixture(),
    base = Date.parse("2026-01-01T00:00:00.000Z"),
    iso = (n) => new Date(base + n).toISOString();
  h.verifyProof({
    ...p,
    leaseRenewedAt: iso(120000),
    leaseExpiresAt: iso(1020000),
    nativeCompletedAt: iso(100000),
    deferredObservedAt: iso(1100000),
    deferredHeartbeatAt: iso(1099000),
    terminalObservedAt: iso(4620001),
    terminalHeartbeatAt: iso(4620000),
  });
});

test("actual pg BIGINT heartbeat strings normalize safely and refuse malformed or overflowing observations", () => {
  const r = require("../tests/e2e/helpers/certops-windows-alive-grace-reaper");
  assert.equal(r.uptimeSeconds("123"), 123);
  assert.equal(r.uptimeSeconds("0"), 0);
  for (const v of ["01", "1.5", "-1", "9007199254740992", "", true, null, NaN])
    assert.throws(() => r.uptimeSeconds(v));
});

test("owned command gate atomically publishes without overwriting and refuses same-byte receipt replacement", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    os = require("node:os"),
    m = require("../tests/e2e/helpers/certops-windows-alive-grace-command"),
    platform = require("../packages/agent/src/platform"),
    originalPermissions = platform.applyRestrictivePermissions;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "alive-command-public-"));
  platform.applyRestrictivePermissions = () => {};
  try {
    const c = m.createCommandBarrier({
        root,
        ownedResources: [],
        program: process.execPath,
        args: ["-e", "void 0"],
      }),
      directory = path.join(root, "alive-grace-command"),
      file = (n) => path.join(directory, n);
    c.arm();
    const arm = JSON.parse(fs.readFileSync(file("arm.json"))),
      stat = fs.lstatSync(file("arm.json"), { bigint: true }),
      ready = {
        schemaVersion: 1,
        token: arm.token,
        pid: 123,
        parentPid: 122,
        armId: `${stat.dev}:${stat.ino}`,
      };
    m.publish(file("ready.json"), ready);
    c.observe();
    const saved = path.join(root, "original-ready.json"),
      bytes = fs.readFileSync(file("ready.json"));
    fs.renameSync(file("ready.json"), saved);
    fs.writeFileSync(file("ready.json"), bytes, { flag: "wx" });
    assert.throws(() => c.observe(), /Original command receipt changed/);
    assert.ok(fs.readFileSync(file("ready.json")).equals(bytes));
    fs.unlinkSync(file("ready.json"));
    fs.renameSync(saved, file("ready.json"));
    c.release();
    m.publish(file("closed.json"), {
      schemaVersion: 1,
      token: arm.token,
      pid: 123,
      parentPid: 122,
      exitCode: 0,
      signal: null,
    });
    c.finish();
    assert.equal(c.hasOwnershipReceipt(), false);
    assert.equal(fs.existsSync(directory), false);
    const immutable = path.join(root, "immutable.json");
    m.publish(immutable, { public: true });
    const before = fs.readFileSync(immutable);
    assert.throws(
      () => m.publish(immutable, { foreign: true }),
      /EEXIST|exist/i,
    );
    assert.ok(fs.readFileSync(immutable).equals(before));
  } finally {
    platform.applyRestrictivePermissions = originalPermissions;
    fs.rmSync(root, { recursive: true });
  }
});

test("command gate constructor records sticky ownership before private directory permission failure", () => {
  const fs = require("node:fs"),
    path = require("node:path"),
    os = require("node:os"),
    m = require("../tests/e2e/helpers/certops-windows-alive-grace-command"),
    platform = require("../packages/agent/src/platform"),
    original = platform.applyRestrictivePermissions,
    root = fs.mkdtempSync(path.join(os.tmpdir(), "alive-command-failure-")),
    ownedResources = [];
  try {
    platform.applyRestrictivePermissions = () => {
      throw Error("controlled permission failure");
    };
    assert.throws(
      () =>
        m.createCommandBarrier({
          root,
          ownedResources,
          program: process.execPath,
          args: [],
        }),
      /controlled permission failure/,
    );
    assert.equal(ownedResources.length, 1);
    assert.equal(ownedResources[0].cleanupCompleted, false);
    assert.throws(() => m.assertCleanupSafe(root));
    fs.rmdirSync(path.join(root, "alive-grace-command"));
    assert.throws(() => m.assertCleanupSafe(root));
  } finally {
    platform.applyRestrictivePermissions = original;
    fs.rmSync(root, { recursive: true });
  }
});
