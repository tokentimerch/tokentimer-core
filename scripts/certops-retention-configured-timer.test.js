"use strict";
/** Supporting real timers/production empty-ledger path only. Owned public temp
 * files; no CNG, certificate, service, IIS, CA, cloud or simulated clock. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os");
const h = require("../packages/agent/scripts/host/retention-configured-timer-fixture");
test("actual configured polling loop dispatches production empty-ledger collector twice after immediate run and drains abort", async () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "configured-retention-timer-"),
  );
  try {
    const p = await h.qualifyConfiguredTimer({ workDir: root });
    assert.equal(h.verifyProof(p), true);
    assert.deepEqual(fs.readdirSync(root), []);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
test("configured timer cannot promote default six-hour elapsed or native cleanup qualification", () => {
  const p = {
    scope: h.SCOPE,
    configuredIntervalMs: 100,
    defaultIntervalMs: 21600000,
    defaultRetentionHours: 168,
    actualCallbacks: 3,
    actualDelayedCallbacks: 2,
    waitedMonotonicMs: 200,
    defaultSixHourElapsedQualified: false,
    installedServiceQualified: false,
    nativeDeletionQualified: false,
    productionCollectorReturnedEmpty: true,
    actualAbortDrained: true,
    ownedEmptyStatePreserved: true,
  };
  h.verifyProof(p);
  for (const k of Object.keys(p)) {
    const bad = { ...p };
    delete bad[k];
    assert.throws(() => h.verifyProof(bad));
  }
  for (const k of [
    "defaultSixHourElapsedQualified",
    "installedServiceQualified",
    "nativeDeletionQualified",
  ])
    assert.throws(() => h.verifyProof({ ...p, [k]: true }));
  assert.throws(() => h.verifyProof({ ...p, configuredIntervalMs: 21600000 }));
  assert.throws(() => h.verifyProof({ ...p, waitedMonotonicMs: 0 }));
  assert.throws(() => h.verifyProof({ ...p, clock: "fake" }));
});
test("installed production timer wiring retains real configured interval and immediate collector", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "../packages/agent/src/index.js"),
    "utf8",
  );
  assert.match(
    source,
    /intervalMs: config\.windows\.sweepIntervalMs,[\s\S]{0,250}startImmediately: true,[\s\S]{0,250}runWindowsRetentionSweep\(/,
  );
});
