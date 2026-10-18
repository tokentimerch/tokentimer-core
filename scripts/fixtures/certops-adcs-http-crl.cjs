"use strict";
// Synthetic public proof for strict-report tests, never native execution.
const h = require("../../tests/e2e/helpers/certops-adcs-http-intermediate-crl");
function proof() {
  return {
    scope: h.SCOPE,
    transport: "http",
    revocationTarget: "intermediate",
    nativeHelperSha256: "a".repeat(64),
    publicCrlSha256: "b".repeat(64),
    leafFingerprint: "c".repeat(64),
    nativeVerdicts: ["valid", "revocation_unknown", "valid"],
    installedAgentQualified: false,
    httpOnlyLeafQualified: false,
    ocspQualified: false,
    ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
  };
}
module.exports = { proof };
