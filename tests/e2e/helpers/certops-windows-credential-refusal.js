/*
 * Qualification notes: credential-startup-refusals
 * Shared setup, dispatch and evidence rules: docs/certops/e2e-qualification.md.
 * An already registered service must explicitly refuse empty or malformed present credentials before
 * registration/polling, rather than silently replacing identity. Retain original credential privately
 * and require exact production reader errors. Reuse stopped SYSTEM retained-file startup engine with
 * original-file guard and fresh child drainage; config/pin/server jobs/CNG/binding/TLS remain
 * unchanged. Restore exact credential and require repaired authenticated SYSTEM child before guard
 * release. Supporting temporary reader tests and ten-cell native source do not qualify missing-file
 * registration, bootstrap replacement, in-flight work or automatic recovery from compromise.
 */
"use strict";
/** Installed credential-reader startup refusal prerequisites. Only the owned
 * credential file is changed; original secret bytes stay in the private fixture
 * and are never part of public proof. No registration identity is fabricated. */
const assert = require("node:assert/strict");
const SCENARIO = "windows-installed-credential-startup-refusals";
const SCOPE = "installed-system-invalid-credential-startup-refusal";
const CASES = Object.freeze(["empty-credential", "malformed-credential"]);
const FLAGS = Object.freeze([
  "twoActualSystemCredentialFailures",
  "freshStoppedServiceForEach",
  "configurationAndPinPreserved",
  "nativeCngAndBindingPreserved",
  "trustedTlsPreserved",
  "noNewAgentOrJob",
  "exactOriginalCredentialRestored",
  "actualRepairedSystemChild",
  "freshAuthenticatedHeartbeat",
  "ownedCredentialGuardCleared",
]);
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-credential-refusal.js",
  ...require("./certops-windows-config-encoding").REQUIRED_SOURCES,
]);
function credentialCases(original) {
  assert.ok(
    Buffer.isBuffer(original) &&
      original.length > 0 &&
      original.length <= 1048576,
    "Bounded original owned credential required",
  );
  return [
    {
      id: CASES[0],
      content: Buffer.alloc(0),
      expectedError: "credential must be a non-empty string",
    },
    {
      id: CASES[1],
      content: Buffer.from("owned-public-invalid-credential"),
      expectedError: "credential does not match the expected ttagent_",
    },
  ];
}
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(
    Object.keys(p).sort(),
    [
      "scope",
      "credentials",
      "startupFailureCount",
      "inFlightMutationQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(p.scope, SCOPE);
  assert.deepEqual(p.credentials, CASES);
  assert.equal(p.startupFailureCount, 2);
  assert.equal(p.inFlightMutationQualified, false);
  for (const flag of FLAGS) assert.equal(p[flag], true, flag);
  return true;
}
const qualifyCredentialRefusal = (context) =>
  require("./certops-windows-config-encoding").qualifyCredentialRefusal(
    context,
  );
module.exports = {
  qualifyCredentialRefusal,
  SCENARIO,
  SCOPE,
  CASES,
  FLAGS,
  REQUIRED_SOURCES,
  credentialCases,
  verifyProof,
};
