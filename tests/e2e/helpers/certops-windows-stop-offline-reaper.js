"use strict";
/** Actual default-clock reconciliation for the isolated stopped Windows lane.
 * This calls the production reaper directly. It does not qualify a deployed
 * worker loop, inject time, shorten a persisted lease, or override grace. */
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { setTimeout: delay } = require("node:timers/promises");
const timing = require("../../../apps/api/services/certops/leaseTiming");
const liveness = require("../../../apps/api/services/certops/agentLiveness");
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const iso = (value) => new Date(value).toISOString();
async function reconcileAfterActualOfflineDeadline({
  pool,
  workspaceId,
  jobId,
  claimId,
  agentRowId,
  assertStopped,
}) {
  for (const value of [workspaceId, jobId, claimId, agentRowId])
    assert.match(value, UUID);
  assert.equal(typeof assertStopped, "function");
  const read = async () => {
    const rows = (
      await pool.query(
        "SELECT j.id,j.status,j.executor_kind,j.attempt_count,j.claim_id,j.claimed_by_agent_id,j.lease_renewed_at,j.lease_expires_at,j.needs_operator_reconciliation,j.error_code,a.last_seen_at,a.status AS agent_status,NOW() AS database_now FROM certificate_jobs j JOIN certops_agents a ON a.id=$3 AND a.workspace_id=j.workspace_id WHERE j.workspace_id=$1 AND j.id=$2",
        [workspaceId, jobId, agentRowId],
      )
    ).rows;
    assert.equal(
      rows.length,
      1,
      "Actual stopped job and registered agent required",
    );
    return rows[0];
  };
  const isolated = async () => {
    const rows = (
      await pool.query(
        "SELECT id FROM certificate_jobs WHERE executor_kind='agent' AND status IN ('claimed','running') ORDER BY id",
      )
    ).rows;
    assert.deepEqual(
      rows.map((row) => row.id),
      [jobId],
      "Default reaper requires globally isolated actual active job",
    );
  };
  await assertStopped();
  await isolated();
  const initial = await read();
  assert.equal(initial.status, "running");
  assert.equal(initial.executor_kind, "agent");
  assert.equal(initial.attempt_count, 1);
  assert.equal(initial.claim_id, claimId);
  assert.equal(initial.claimed_by_agent_id, agentRowId);
  assert.equal(initial.agent_status, "active");
  assert.ok(
    initial.lease_renewed_at &&
      initial.lease_expires_at &&
      initial.last_seen_at,
  );
  const renewedAt = new Date(initial.lease_renewed_at).getTime();
  const expiresAt = new Date(initial.lease_expires_at).getTime();
  const lastSeenAt = new Date(initial.last_seen_at).getTime();
  const databaseAt = new Date(initial.database_now).getTime();
  assert.equal(expiresAt - renewedAt, timing.DEFAULT_JOB_LEASE_SECONDS * 1000);
  const due = Math.max(
    expiresAt,
    lastSeenAt + liveness.DEFAULT_AGENT_OFFLINE_AFTER_MS,
  );
  assert.ok(
    databaseAt < due && due - databaseAt <= 1000000,
    "Actual default deadline must still be ahead within reviewed offline fixture budget",
  );
  const began = performance.now();
  let current = initial;
  while (new Date(current.database_now).getTime() <= due) {
    assert.ok(
      performance.now() - began < 1200000,
      "Actual offline deadline wait exceeded20min bound",
    );
    await delay(1000);
    await assertStopped();
    current = await read();
    assert.equal(current.status, initial.status);
    assert.equal(current.attempt_count, initial.attempt_count);
    assert.equal(current.claim_id, claimId);
    assert.equal(current.claimed_by_agent_id, agentRowId);
    assert.equal(iso(current.lease_renewed_at), iso(initial.lease_renewed_at));
    assert.equal(iso(current.lease_expires_at), iso(initial.lease_expires_at));
    assert.equal(
      iso(current.last_seen_at),
      iso(initial.last_seen_at),
      "Stopped agent must not produce a fresh heartbeat",
    );
    assert.equal(current.agent_status, "active");
  }
  const waitedMonotonicMs = performance.now() - began;
  assert.ok(
    waitedMonotonicMs >= due - databaseAt - 1000,
    "Wall-clock movement cannot replace measured default deadline wait",
  );
  await isolated();
  await assertStopped();
  const worker = await import(
    pathToFileURL(
      path.resolve(__dirname, "../../../apps/worker/src/certops-worker.js"),
    ).href
  );
  const client = await pool.connect();
  let summary;
  try {
    // These are deliberately the production defaults: no timing, writer,
    // liveness, batch, grace or clock substitutions are supplied.
    summary = await worker.reapExpiredLeases({ client });
  } finally {
    client.release();
  }
  assert.deepEqual(summary, {
    scanned: 1,
    requeued: 0,
    failed: 1,
    deferred: 0,
  });
  await assertStopped();
  const terminal = await read();
  assert.equal(terminal.status, "orphaned_unknown_effect");
  assert.equal(terminal.attempt_count, 1);
  assert.equal(terminal.needs_operator_reconciliation, true);
  assert.equal(terminal.error_code, "effects_unknown");
  assert.equal(terminal.claim_id, null);
  assert.equal(terminal.claimed_by_agent_id, null);
  assert.equal(terminal.lease_expires_at, null);
  assert.equal(iso(terminal.lease_renewed_at), iso(initial.lease_renewed_at));
  assert.equal(iso(terminal.last_seen_at), iso(initial.last_seen_at));
  return {
    leaseRenewedAt: iso(initial.lease_renewed_at),
    leaseExpiresAt: iso(initial.lease_expires_at),
    lastSeenAt: iso(initial.last_seen_at),
    databaseObservedAt: iso(initial.database_now),
    reapedObservedAt: iso(terminal.database_now),
    waitedMonotonicMs,
    defaultLeaseMs: timing.DEFAULT_JOB_LEASE_SECONDS * 1000,
    defaultOfflineMs: liveness.DEFAULT_AGENT_OFFLINE_AFTER_MS,
    defaultHardGraceMs: timing.DEFAULT_LEASE_HARD_GRACE_MS,
    defaultAliveGraceElapsedQualified: false,
    deployedWorkerLoopQualified: false,
  };
}
module.exports = { reconcileAfterActualOfflineDeadline };
