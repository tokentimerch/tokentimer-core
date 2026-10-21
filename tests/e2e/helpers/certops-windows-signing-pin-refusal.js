/*
 * Qualification notes: installed-signing-pin-refusal
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * Corrupt present pin with malformed JSON and invalid required fields; real stopped/drained SYSTEM
 * startup must expose specific reader error without unsigned startup or replacement identity. Retained
 * original descriptor owns exact writes/repair; preserve config/credential/service
 * paths/CNG/binding/TLS. New actual SYSTEM child plus authenticated heartbeat and exact original bytes
 * precede releasing private backup/sticky guard. Idle present-file corruption only: no missing-pin
 * bootstrap, key rotation or in-flight recovery. Supporting reader/proof tests do not establish native
 * ten-cell execution.
 */
"use strict";
/** Present corrupt signing pins must fail actual installed-agent startup rather
 * than silently become unsigned. Only the fixture-owned public pin changes;
 * credential/configuration and all native custody remain independently bound. */
const assert = require("node:assert/strict");
const SCENARIO = "windows-installed-signing-pin-startup-refusals";
const SCOPE = "installed-system-corrupt-signing-pin-startup-refusal";
const CASES = Object.freeze(["malformed-pin-json", "invalid-pin-shape"]);
const FLAGS = Object.freeze([
  "twoActualSystemPinFailures",
  "freshStoppedServiceForEach",
  "configurationAndCredentialPreserved",
  "nativeCngAndBindingPreserved",
  "trustedTlsPreserved",
  "noNewAgentOrJob",
  "exactOriginalPinRestored",
  "actualRepairedSystemChild",
  "freshAuthenticatedHeartbeat",
  "ownedPinGuardCleared",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-signing-pin-refusal.js",
  ...require("./certops-windows-config-encoding").REQUIRED_SOURCES,
]);
function pinCases(original) {
  assert.ok(
    Buffer.isBuffer(original) &&
      original.length > 0 &&
      original.length <= 1048576,
    "Bounded original public pin required",
  );
  const value = JSON.parse(original.toString("utf8"));
  assert.ok(
    value &&
      typeof value.signingKeyId === "string" &&
      value.signingKeyId.length > 0 &&
      typeof value.publicKeyPem === "string" &&
      value.publicKeyPem.includes("BEGIN PUBLIC KEY"),
    "Original persisted pin must already be valid",
  );
  return [
    {
      id: CASES[0],
      content: Buffer.from("{owned-public-malformed-pin"),
      expectedError: "failed to parse signing key pin",
    },
    {
      id: CASES[1],
      content: Buffer.from(
        JSON.stringify({
          signingKeyId: "",
          publicKeyPem: "owned-public-invalid-key",
        }),
      ),
      expectedError: "is corrupted (expected",
    },
  ];
}
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "pins",
      "startupFailureCount",
      "missingPinQualified",
      "inFlightMutationQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  assert.deepEqual(p.pins, CASES);
  assert.equal(p.startupFailureCount, 2);
  assert.equal(p.missingPinQualified, false);
  assert.equal(p.inFlightMutationQualified, false);
  for (const flag of FLAGS) assert.equal(p[flag], true);
  return true;
}
const qualifySigningPinRefusal = (context) =>
  require("./certops-windows-config-encoding").qualifySigningPinRefusal(
    context,
  );
module.exports = {
  SCENARIO,
  SCOPE,
  CASES,
  FLAGS,
  REQUIRED_SOURCES,
  pinCases,
  verifyProof,
  qualifySigningPinRefusal,
};
