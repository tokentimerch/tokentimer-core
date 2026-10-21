/*
 * Qualification notes: installed-default-retention-timer
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Hosted supporting case checks actual omitted defaults168hours/21600000ms then runs production poll
 * loop at explicit100ms, real jitter, immediate plus2 delayed collector callbacks against owned empty
 * ledger; drain cancellation. This cannot qualify installed service default6hour passage/deletion.
 * Dedicated optional domain campaign uses two genuine enrollments, trusted replacement, pending
 * predecessor ledger and read-only SYSTEM observer; after restart distinguish immediate
 * pending->deferred atomic rewrite from same-process timer rewrite. Omit both retention config fields:
 * base6h/default168h, jitter4.8-7.2h after callback,5minute observation margin and wall/monotonic
 * agreement<=5s. Retain boot/process/config/ledger file identities, CNG custody, pinned API TLS/health
 * and no other jobs/profiles. Original4h artifact may authorize one16h hard lease only after
 * authenticated immutable receipt+fresh VM/task readback; final ownership/observer drainage/resource
 * absence required. It measures deferral timer, not168h/720h retention, deletion, power loss or
 * resident stopped-agent day. Ordinary6h hosted job cannot reliably contain7.2h jitter; no
 * shortened-default claim.
 */
"use strict";
/** Azure-free supporting timer wiring. The real production polling loop uses
 * an explicitly configured100ms interval and real monotonic time; its actual
 * collector sees a fixture-owned EMPTY ledger. This is neither an installed
 * service run nor evidence of six hours elapsed or native certificate removal.
 */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const { startPollLoop } = require("../../src/protocol");
const { runWindowsRetentionSweep } = require("../../src");
const { loadAgentConfig } = require("../../src/config");
const SCENARIO = "windows-retention-configured-real-timer-empty-ledger";
const SCOPE = "production-configured-real-timer-empty-ledger-supporting";
const REQUIRED_SOURCES = Object.freeze([
  "packages/agent/scripts/host/retention-configured-timer-fixture.js",
  "packages/agent/src/protocol/index.js",
  "packages/agent/src/config/index.js",
  "packages/agent/src/index.js",
  "packages/agent/scripts/host/windows-host.test.js",
]);
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "configuredIntervalMs",
      "defaultIntervalMs",
      "defaultRetentionHours",
      "actualCallbacks",
      "actualDelayedCallbacks",
      "waitedMonotonicMs",
      "defaultSixHourElapsedQualified",
      "installedServiceQualified",
      "nativeDeletionQualified",
      "productionCollectorReturnedEmpty",
      "actualAbortDrained",
      "ownedEmptyStatePreserved",
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  assert.equal(p.configuredIntervalMs, 100);
  assert.equal(p.defaultIntervalMs, 21600000);
  assert.equal(p.defaultRetentionHours, 168);
  assert.equal(p.actualCallbacks, 3);
  assert.equal(p.actualDelayedCallbacks, 2);
  assert.ok(
    Number.isSafeInteger(p.waitedMonotonicMs) &&
      p.waitedMonotonicMs >= 140 &&
      p.waitedMonotonicMs <= 5000,
  );
  for (const key of [
    "defaultSixHourElapsedQualified",
    "installedServiceQualified",
    "nativeDeletionQualified",
  ])
    assert.equal(p[key], false, key);
  for (const key of [
    "productionCollectorReturnedEmpty",
    "actualAbortDrained",
    "ownedEmptyStatePreserved",
  ])
    assert.equal(p[key], true, key);
  return true;
}
async function qualifyConfiguredTimer({ workDir }) {
  const root = path.join(workDir, "retention-configured-timer");
  fs.mkdirSync(root);
  const identity = fs.lstatSync(root, { bigint: true });
  assert.ok(
    identity.isDirectory() && !identity.isSymbolicLink() && identity.ino > 0n,
  );
  const file = path.join(root, "config.json"),
    base = { serverUrl: "https://owned-configured-timer.invalid" };
  fs.writeFileSync(file, JSON.stringify(base), { flag: "wx", mode: 0o600 });
  const fileIdentity = fs.lstatSync(file, { bigint: true });
  const same = () => {
    const current = fs.lstatSync(root, { bigint: true }),
      entry = fs.lstatSync(file, { bigint: true });
    assert.ok(
      current.isDirectory() &&
        !current.isSymbolicLink() &&
        current.dev === identity.dev &&
        current.ino === identity.ino,
    );
    assert.ok(
      entry.isFile() &&
        !entry.isSymbolicLink() &&
        entry.dev === fileIdentity.dev &&
        entry.ino === fileIdentity.ino,
    );
    assert.deepEqual(fs.readdirSync(root), ["config.json"]);
  };
  let configBytes = fs.readFileSync(file);
  const initial = loadAgentConfig({ configDir: root });
  assert.equal(initial.windows.sweepIntervalMs, 21600000);
  assert.equal(initial.windows.supersededRetentionHours, 168);
  same();
  fs.writeFileSync(
    file,
    JSON.stringify({ ...base, windows: { sweepIntervalMs: 100 } }),
  );
  configBytes = fs.readFileSync(file);
  same();
  const configured = loadAgentConfig({ configDir: root });
  assert.equal(configured.windows.sweepIntervalMs, 100);
  assert.equal(configured.windows.supersededRetentionHours, 168);
  const controller = new AbortController(),
    ticks = [],
    started = performance.now();
  let timeout = false,
    tickError;
  const deadline = setTimeout(() => {
    timeout = true;
    controller.abort();
  }, 5000);
  try {
    await startPollLoop({
      intervalMs: configured.windows.sweepIntervalMs,
      signal: controller.signal,
      startImmediately: true,
      onTick: async () => {
        same();
        assert.ok(fs.readFileSync(file).equals(configBytes));
        assert.equal(
          await runWindowsRetentionSweep({
            stateDir: root,
            retentionHours: configured.windows.supersededRetentionHours,
          }),
          null,
        );
        ticks.push(performance.now());
        if (ticks.length === 3) controller.abort();
      },
      onError: (error) => {
        tickError = error;
        controller.abort();
      },
    });
    assert.equal(timeout, false, "Bounded configured timer did not finish");
    assert.ifError(tickError);
    assert.equal(ticks.length, 3);
    assert.ok(ticks[1] > ticks[0] && ticks[2] > ticks[1]);
    same();
    assert.ok(fs.readFileSync(file).equals(configBytes));
    const proof = {
      scope: SCOPE,
      configuredIntervalMs: 100,
      defaultIntervalMs: initial.windows.sweepIntervalMs,
      defaultRetentionHours: initial.windows.supersededRetentionHours,
      actualCallbacks: ticks.length,
      actualDelayedCallbacks: ticks.length - 1,
      waitedMonotonicMs: Math.floor(performance.now() - started),
      defaultSixHourElapsedQualified: false,
      installedServiceQualified: false,
      nativeDeletionQualified: false,
      productionCollectorReturnedEmpty: true,
      actualAbortDrained: true,
      ownedEmptyStatePreserved: true,
    };
    verifyProof(proof);
    fs.unlinkSync(file);
    fs.rmdirSync(root);
    return proof;
  } finally {
    clearTimeout(deadline);
    controller.abort();
  }
}
module.exports = {
  SCENARIO,
  SCOPE,
  REQUIRED_SOURCES,
  verifyProof,
  qualifyConfiguredTimer,
};
