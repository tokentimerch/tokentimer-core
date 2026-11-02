"use strict";
/** Separate default-clock alive-agent boundary. Only a real native producer may
 * call this after pinning its exact completed mutation and durable result.
 * No clock/interval/reaper substitutions or database state writes are accepted. */
const assert = require("node:assert/strict"),
  path = require("node:path"),
  { pathToFileURL } = require("node:url"),
  { setTimeout: delay } = require("node:timers/promises");
const timing = require("../../../apps/api/services/certops/leaseTiming"),
  liveness = require("../../../apps/api/services/certops/agentLiveness");
const iso = (value) => new Date(value).toISOString();
function uptimeSeconds(value) {
  if (typeof value === "string") assert.match(value, /^(0|[1-9][0-9]{0,15})$/);
  else assert.equal(typeof value, "number");
  const n = Number(value);
  assert.ok(
    Number.isSafeInteger(n) && n >= 0,
    "Actual canonical safe heartbeat uptime required",
  );
  return n;
}
function verifyRunning(row, original, { jobId, claimId, agentRowId }) {
  assert.equal(row.id, jobId);
  assert.equal(row.status, "running");
  assert.equal(row.executor_kind, "agent");
  assert.equal(row.attempt_count, 1);
  assert.equal(row.claim_id, claimId);
  assert.equal(row.claimed_by_agent_id, agentRowId);
  assert.equal(row.agent_status, "active");
  assert.equal(row.needs_operator_reconciliation, false);
  const now = Date.parse(row.database_now),
    seen = Date.parse(row.last_seen_at);
  assert.ok(
    Number.isFinite(now) &&
      Number.isFinite(seen) &&
      seen <= now &&
      now - seen < liveness.DEFAULT_AGENT_OFFLINE_AFTER_MS,
    "Actual fresh authenticated heartbeat required",
  );
  assert.equal(
    Date.parse(row.lease_expires_at) - Date.parse(row.lease_renewed_at),
    timing.DEFAULT_JOB_LEASE_SECONDS * 1000,
  );
  row = { ...row, uptime_seconds: uptimeSeconds(row.uptime_seconds) };
  if (original) {
    assert.ok(
      row.uptime_seconds >= uptimeSeconds(original.uptime_seconds),
      "Original agent heartbeat uptime must not regress",
    );
    assert.equal(iso(row.lease_expires_at), iso(original.lease_expires_at));
    assert.equal(iso(row.lease_renewed_at), iso(original.lease_renewed_at));
  }
  return row;
}
async function reconcileAfterActualAliveGrace({
  pool,
  workspaceId,
  jobId,
  claimId,
  agentRowId,
  assertAliveAndCustody,
}) {
  const ids = { jobId, claimId, agentRowId };
  for (const id of [workspaceId, ...Object.values(ids)])
    assert.match(id, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.equal(typeof assertAliveAndCustody, "function");
  const read = async () => {
    const rows = (
      await pool.query(
        "SELECT j.id,j.status,j.executor_kind,j.attempt_count,j.claim_id,j.claimed_by_agent_id,j.lease_renewed_at,j.lease_expires_at,j.needs_operator_reconciliation,j.error_code,a.last_seen_at,a.uptime_seconds::text AS uptime_seconds,a.status AS agent_status,NOW() AS database_now FROM certificate_jobs j JOIN certops_agents a ON a.id=$3 AND a.workspace_id=j.workspace_id WHERE j.workspace_id=$1 AND j.id=$2",
        [workspaceId, jobId, agentRowId],
      )
    ).rows;
    assert.equal(rows.length, 1);
    return rows[0];
  };
  const isolated = async () =>
    assert.deepEqual(
      (
        await pool.query(
          "SELECT id FROM certificate_jobs WHERE executor_kind='agent' AND status IN ('claimed','running') ORDER BY id",
        )
      ).rows.map((r) => r.id),
      [jobId],
      "Default reaper requires sole owned active agent job",
    );
  await assertAliveAndCustody();
  await isolated();
  // stopPeriodicLeaseRenewal clears its timer but does not await an already
  // in-flight HTTP renewal. Observe a genuine stable lease before freezing it.
  let initial = verifyRunning(await read(), null, ids),
    stableSince = performance.now();
  const settleBegan = stableSince;
  while (performance.now() - stableSince < 45000) {
    assert.ok(
      performance.now() - settleBegan < 90000,
      "Lease did not settle after completed execution",
    );
    await delay(5000);
    await assertAliveAndCustody();
    const current = verifyRunning(await read(), null, ids);
    assert.ok(current.uptime_seconds >= initial.uptime_seconds);
    if (
      iso(current.lease_renewed_at) !== iso(initial.lease_renewed_at) ||
      iso(current.lease_expires_at) !== iso(initial.lease_expires_at)
    )
      stableSince = performance.now();
    initial = current;
  }
  const began = performance.now();
  const expires = Date.parse(initial.lease_expires_at),
    hardDue = expires + timing.DEFAULT_LEASE_HARD_GRACE_MS;
  assert.ok(
    Date.parse(initial.database_now) < expires,
    "Genuine persisted lease must not already have expired at observation start",
  );
  const worker = await import(
    pathToFileURL(
      path.resolve(__dirname, "../../../apps/worker/src/certops-worker.js"),
    ).href
  );
  const reap = async () => {
    await isolated();
    await assertAliveAndCustody();
    const client = await pool.connect();
    try {
      return await worker.reapExpiredLeases({ client });
    } finally {
      client.release();
    }
  };
  let current = initial;
  const waitUntil = async (predicate) => {
    while (!predicate(current)) {
      assert.ok(
        performance.now() - began < 5100000,
        "Actual default-grace observation exceeded85-minute bound",
      );
      await delay(5000);
      await assertAliveAndCustody();
      current = verifyRunning(await read(), initial, ids);
    }
  };
  await waitUntil((row) => Date.parse(row.database_now) > expires);
  assert.ok(
    Date.parse(current.database_now) <= hardDue,
    "Missed genuine pre-grace reaper boundary",
  );
  assert.deepEqual(await reap(), {
    scanned: 1,
    requeued: 0,
    failed: 0,
    deferred: 1,
  });
  const deferred = verifyRunning(await read(), initial, ids);
  assert.ok(
    deferred.uptime_seconds > initial.uptime_seconds,
    "Actual heartbeat uptime must increase before defer",
  );
  // Both independent clocks must traverse the full unchanged default window.
  await waitUntil(
    (row) =>
      Date.parse(row.database_now) > hardDue &&
      performance.now() - began >=
        timing.DEFAULT_JOB_LEASE_SECONDS * 1000 +
          timing.DEFAULT_LEASE_HARD_GRACE_MS,
  );
  const beforeTerminal = verifyRunning(await read(), initial, ids);
  assert.ok(
    Date.parse(beforeTerminal.last_seen_at) > Date.parse(deferred.last_seen_at),
  );
  assert.deepEqual(await reap(), {
    scanned: 1,
    requeued: 0,
    failed: 1,
    deferred: 0,
  });
  await assertAliveAndCustody();
  const terminal = await read();
  assert.equal(terminal.status, "orphaned_unknown_effect");
  assert.equal(terminal.attempt_count, 1);
  assert.equal(terminal.needs_operator_reconciliation, true);
  assert.equal(terminal.error_code, "effects_unknown");
  assert.equal(terminal.claim_id, null);
  assert.equal(terminal.claimed_by_agent_id, null);
  assert.equal(terminal.lease_expires_at, null);
  assert.equal(iso(terminal.lease_renewed_at), iso(initial.lease_renewed_at));
  assert.equal(terminal.agent_status, "active");
  terminal.uptime_seconds = uptimeSeconds(terminal.uptime_seconds);
  assert.ok(
    Number.isSafeInteger(terminal.uptime_seconds) &&
      terminal.uptime_seconds > deferred.uptime_seconds,
    "Actual heartbeat uptime must increase before final classification",
  );
  const terminalAt = Date.parse(terminal.database_now),
    terminalSeen = Date.parse(terminal.last_seen_at);
  assert.ok(
    terminalSeen <= terminalAt &&
      terminalAt - terminalSeen < liveness.DEFAULT_AGENT_OFFLINE_AFTER_MS,
  );
  return {
    leaseRenewedAt: iso(initial.lease_renewed_at),
    leaseExpiresAt: iso(initial.lease_expires_at),
    deferredObservedAt: iso(deferred.database_now),
    deferredHeartbeatAt: iso(deferred.last_seen_at),
    terminalObservedAt: iso(terminal.database_now),
    terminalHeartbeatAt: iso(terminal.last_seen_at),
    heartbeatUptimeSeconds: [
      initial.uptime_seconds,
      deferred.uptime_seconds,
      terminal.uptime_seconds,
    ],
    waitedMonotonicMs: Math.floor(performance.now() - began),
    originalOperationAutomaticallyRecovered: false,
    deployedWorkerLoopQualified: false,
  };
}
module.exports = {
  uptimeSeconds,
  verifyRunning,
  reconcileAfterActualAliveGrace,
};
