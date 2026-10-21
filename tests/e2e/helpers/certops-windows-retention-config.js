/*
 * Qualification notes: retention-configuration-refusals
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Production accepts integer retentionHours24..720 and positive integer sweepIntervalMs. Fault
 * only23,721hours and0interval in unchanged original UTF8 config. Stopped SYSTEM retained-file startup
 * with recovery disabled must fail each exact reader validation and drain child while
 * CNG/binding/TLS/API state remain fixed. Exact restore,new SYSTEM child and authenticated heartbeat
 * precede sticky guard release. Portable loader tests do not execute SCM/collector or qualify
 * default6h timer,elapsed windows/deletion; native source required in ten cells.
 */
"use strict";
/** Real installed startup boundary variants. These owned JSON copies alter only
 * the supported retention policy; the native startup/preservation engine is
 * shared with encoding refusals. No timer/deletion or shortened retention is
 * qualified, and importing this source performs no native operation. */
const assert = require("node:assert/strict");
const SCENARIO = "windows-installed-retention-policy-startup-refusals";
const SCOPE = "installed-system-invalid-retention-policy-startup-refusal";
const CASES = Object.freeze([
  "below-minimum-hours",
  "above-maximum-hours",
  "zero-sweep-interval",
]);
const FLAGS = Object.freeze([
  "threeActualSystemValidationFailures",
  "freshStoppedServiceForEach",
  "credentialAndPinPreserved",
  "nativeCngAndBindingPreserved",
  "trustedTlsPreserved",
  "noNewAgentOrJob",
  "exactOriginalConfigurationRestored",
  "actualRepairedSystemChild",
  "freshAuthenticatedHeartbeat",
  "ownedPolicyGuardCleared",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-retention-config.js",
  ...require("./certops-windows-config-encoding").REQUIRED_SOURCES,
]);
function policyCases(original) {
  assert.ok(
    Buffer.isBuffer(original) &&
      original.length > 0 &&
      original.length <= 1048576,
  );
  const text = new TextDecoder("utf-8", { fatal: true }).decode(original);
  assert.ok(Buffer.from(text).equals(original));
  const parsed = JSON.parse(text);
  assert.ok(parsed && typeof parsed === "object" && !Array.isArray(parsed));
  const variants = [
    { supersededRetentionHours: 23 },
    { supersededRetentionHours: 721 },
    { sweepIntervalMs: 0 },
  ];
  return variants.map((change, index) => ({
    id: CASES[index],
    content: Buffer.from(
      JSON.stringify({
        ...parsed,
        windows: { ...(parsed.windows || {}), ...change },
      }),
    ),
    expectedError:
      index < 2
        ? "windows.supersededRetentionHours must be an integer"
        : "windows.sweepIntervalMs must be a positive integer",
  }));
}
function verifyProof(proof) {
  assert.ok(proof && typeof proof === "object" && !Array.isArray(proof));
  assert.deepEqual(
    Object.keys(proof).sort(),
    [
      "scope",
      "policies",
      "startupFailureCount",
      "retentionTimerQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(proof.scope, SCOPE);
  assert.deepEqual(proof.policies, CASES);
  assert.equal(proof.startupFailureCount, 3);
  assert.equal(proof.retentionTimerQualified, false);
  for (const flag of FLAGS) assert.equal(proof[flag], true, flag);
  return true;
}
const qualifyRetentionConfig = (context) =>
  require("./certops-windows-config-encoding").qualifyRetentionConfig(context);
module.exports = {
  qualifyRetentionConfig,
  SCENARIO,
  SCOPE,
  CASES,
  FLAGS,
  REQUIRED_SOURCES,
  policyCases,
  verifyProof,
};
