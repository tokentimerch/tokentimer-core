/*
 * Qualification notes: ipv4-wildcard-sni-precedence
 * Shared setup, dispatch and evidence rules: .github/maintainers/certops/e2e-qualification.md.
 * Own an IPv4 wildcard HTTP.sys binding and independent SNI endpoint, observe actual selector
 * precedence with trusted TLS, verify the successful cutover, and preserve the sibling. Only exact owned wildcard tuple is
 * removable; this fixture is the narrow explicit exception, never authority for blanket netsh reset or
 * arbitrary0.0.0.0 cleanup. Require native source-bound report and owned absence, not portable proof
 * alone.
 */
"use strict";
/** Real supporting IPv4 wildcard precedence control. The shared native engine
 * owns sites/endpoints and borrows only independently verified fixture custody.
 * This source requires actual trusted TLS and a real cutover, not synthetic bind results;
 * it does not qualify installed-agent jobs or CA issuance. */
const base = require("./ipv6-shadow-fixture");
const VARIANT = "ipv4-wildcard";
const SCOPE = base.variantContract(VARIANT).scope;
const SCENARIOS = Object.freeze(["windows-iis-ipv4-wildcard-sni-precedence"]);
const FLAGS = Object.freeze(base.flagsForVariant(VARIANT));
const REQUIRED_SOURCES = Object.freeze([
  "packages/agent/scripts/host/ipv4-wildcard-fixture.js",
  ...base.REQUIRED_SOURCES,
]);
function verifyProof(proof) {
  return base.verifyVariantProof(proof, VARIANT);
}
async function qualifyIpv4Wildcard(context) {
  const proof = await base.qualifyIpv6ShadowVariant(context, VARIANT);
  verifyProof(proof);
  return proof;
}
module.exports = {
  SCOPE,
  SCENARIOS,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  qualifyIpv4Wildcard,
  assertCleanupSafe: base.assertCleanupSafe,
};
