"use strict";
/** Scope and native ABI checks only; no native entry point is invoked. */
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs");
test("observer cannot invoke the collector or supply a fake clock", () => {
  const runtime = fs.readFileSync(
    require.resolve("./certops-retention-cadence-runtime"),
    "utf8",
  );
  assert.doesNotMatch(
    runtime,
    /retention\.(?:sweepLedger|recordSuperseded|writeLedgerRow)\s*\(/,
  );
  assert.doesNotMatch(runtime, /runWindowsRetentionSweep\s*\(/);
  assert.match(runtime, /performance\.now\(\)/);
  assert.match(runtime, /Date\.now\(\)/);
  const prepare = fs.readFileSync(
    require.resolve("../tests/e2e/certops-adcs-retention-cadence-prepare"),
    "utf8",
  );
  assert.match(prepare, /windows:\s*\{\}/);
  assert.doesNotMatch(prepare, /sweepIntervalMs\s*:/);
  assert.doesNotMatch(prepare, /supersededRetentionHours\s*:/);
});
test("busy native timer children use a bounded explicit retry while other failures remain fatal", () => {
  const native = fs.readFileSync(
    require.resolve("./certops-retention-cadence-native.ps1"),
    "utf8",
  );
  assert.match(native, /RETENTION_CADENCE_NATIVE_CHILD_BUSY/);
  assert.doesNotMatch(
    native,
    /\b(?:Stop-Process|Stop-Service|Start-Service|Remove-Item|certutil)\b/,
  );
  const runtime = fs.readFileSync(
    require.resolve("./certops-retention-cadence-runtime"),
    "utf8",
  );
  assert.match(runtime, /idleDeadline\s*=\s*performance\.now\(\)\s*\+\s*60000/);
  assert.match(
    runtime,
    /stderr\.includes\("RETENTION_CADENCE_NATIVE_CHILD_BUSY"\)/,
  );
});
