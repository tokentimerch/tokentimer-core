"use strict";
/** Resident timing primitive for the explicit 24-hour disposable Windows lane.
 * This module supplies no certificate proof and never fabricates a collector
 * context. The native owner must supply a separately verified production ledger,
 * exact native custody/TLS oracles and task/process receipt before calling it.
 * Only the exported real production collector is used; clocks/transports/delete
 * implementations cannot be injected. No cross-process elapsed accumulation. */
const assert = require("node:assert/strict");
const { performance } = require("node:perf_hooks");
const { setTimeout: sleep } = require("node:timers/promises");
const { DAY, HOUR } = require("../../../scripts/certops-retention24h-contract");
const CLOCK_TOLERANCE_MS = 5000;
function verifyResidentSample({ startWallMs, wallMs, elapsedMs, priorElapsedMs }) {
  for (const n of [startWallMs, wallMs, elapsedMs, priorElapsedMs]) assert.ok(Number.isFinite(n) && n >= 0);
  assert.ok(elapsedMs >= priorElapsedMs, "Resident monotonic clock regressed");
  assert.ok(Math.abs(wallMs - startWallMs - elapsedMs) <= CLOCK_TOLERANCE_MS, "Wall and resident monotonic clocks disagree");
  assert.ok(elapsedMs <= DAY + HOUR, "Resident keeper exceeded reviewed drain bound");
  return true;
}
async function waitUntilMonotonic(deadline, signal) {
  assert.ok(Number.isFinite(deadline));
  while (performance.now() < deadline) {
    signal?.throwIfAborted();
    await sleep(Math.min(60000, Math.max(1, Math.ceil(deadline - performance.now()))), undefined, { signal });
  }
  signal?.throwIfAborted();
}
async function runResidentWindow({ stateDir, cleanupDeadline, signal, beforeSweep, afterSweep, verifySoleAgentStopped, beforeDueSweep }) {
  assert.equal(process.platform, "win32", "Actual native Windows runtime required");
  assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB, "1");
  assert.equal(typeof stateDir, "string"); assert.ok(stateDir.length > 0);
  for (const oracle of [beforeSweep, afterSweep, verifySoleAgentStopped, beforeDueSweep]) assert.equal(typeof oracle, "function");
  const deadline = Date.parse(cleanupDeadline), startWallMs = Date.now(), startMonoMs = performance.now();
  assert.ok(Number.isFinite(deadline) && deadline > startWallMs && deadline - startWallMs <= DAY);
  assert.ok(startWallMs - (deadline - DAY) <= 600000, "Resident handoff must follow actual cutover within ten minutes");
  const productionSweep = require("../../../packages/agent/src/index").runWindowsRetentionSweep;
  let priorElapsedMs = 0, keptSweepCount = 0, lastSweepElapsedMs, maximumSweepGapMs = 0;
  const sample = () => {
    const elapsedMs = performance.now() - startMonoMs;
    verifyResidentSample({ startWallMs, wallMs: Date.now(), elapsedMs, priorElapsedMs });
    priorElapsedMs = elapsedMs; return elapsedMs;
  };
  const sweep = async expected => {
    signal?.throwIfAborted(); const elapsed=sample(); if(lastSweepElapsedMs!==undefined){const gap=elapsed-lastSweepElapsedMs;assert.ok(gap <= HOUR+300000,"Missed bounded hourly native collector observation");maximumSweepGapMs=Math.max(maximumSweepGapMs,Math.ceil(gap));}lastSweepElapsedMs=elapsed;
    await verifySoleAgentStopped(expected);
    await beforeSweep(expected);
    // No now/execFileImpl/connectImpl or cleanup substitution is passed.
    const result = await productionSweep({ stateDir, retentionHours: 24, log: { info() {}, warn() {}, error() {}, debug() {} } });
    assert.ok(result, "Actual production retention ledger must exist");
    await afterSweep(expected, result); sample();
  };
  // Hourly sweeps stop before the genuine deadline. The last explicit kept
  // observation is at least one minute early, avoiding an accidental due sweep.
  const preDeadlineMono = startMonoMs + deadline - startWallMs - 60000;
  assert.ok(preDeadlineMono > startMonoMs, "At least one minute of actual predeadline custody required");
  await sweep("kept-before-deadline"); keptSweepCount++;
  let next = startMonoMs + HOUR;
  while (next < preDeadlineMono) {
    await waitUntilMonotonic(next, signal); sample();
    if (Date.now() >= deadline - 60000) break;
    await sweep("kept-before-deadline"); keptSweepCount++; next += HOUR;
  }
  await waitUntilMonotonic(preDeadlineMono, signal);
  assert.ok(Date.now() < deadline, "Missed genuine predeadline observation window");
  await sweep("kept-before-deadline"); keptSweepCount++;
  assert.ok(Date.now() < deadline, "Native predeadline observation finished after the genuine boundary"); const preDeadlineObservedAt=new Date().toISOString();
  // Delay the only due sweep until this same resident process independently
  // measures the full day. Boot/process death discards this local clock state.
  await waitUntilMonotonic(startMonoMs + DAY, signal);
  assert.ok(sample() >= DAY); assert.ok(Date.now() > deadline);
  await beforeDueSweep({monotonicElapsedMs:sample(),observedAt:new Date().toISOString(),cleanupDeadline});
  await sweep("removed-after-real-day");
  return { startedAt:new Date(startWallMs).toISOString(),finishedAt:new Date().toISOString(), scope: "resident-timing-only-native-oracles-required", monotonicElapsedMs: Math.floor(sample()), keptSweepCount, maximumSweepGapMs, preDeadlineObservedAt, collector: "production-default-clock", retentionHours: 24 };
}
module.exports = { CLOCK_TOLERANCE_MS, verifyResidentSample, waitUntilMonotonic, runResidentWindow };
