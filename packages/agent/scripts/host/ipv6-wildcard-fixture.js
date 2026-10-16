"use strict";
/** Separate IPv6-wildcard supporting scope over the reviewed owned lifecycle.
 * Both IP stacks must have no target-port listener, every native selector on
 * the target/sibling ports is refused, and the existing sticky guard serializes
 * this case with the concrete fixture. This does not qualify IPv4 wildcards. */
const assert = require("node:assert/strict"),
  base = require("./ipv6-shadow-fixture");
const SCOPE = base.WILDCARD_SCOPE;
const SCENARIOS = Object.freeze(["windows-iis-ipv6-wildcard-shadow-rollback"]);
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    "packages/agent/scripts/host/ipv6-wildcard-fixture.js",
    ...base.REQUIRED_SOURCES,
  ]),
]);
const FLAGS = base.FLAGS;
function verifyProof(proof) {
  return base.verifyVariantProof(proof, "wildcard");
}
async function qualifyIpv6Wildcard(context) {
  assert.equal(base.variantContract("wildcard").address, "[::]");
  const proof = await base.qualifyIpv6ShadowVariant(context, "wildcard");
  verifyProof(proof);
  return proof;
}
module.exports = {
  SCOPE,
  SCENARIOS,
  REQUIRED_SOURCES,
  FLAGS,
  verifyProof,
  qualifyIpv6Wildcard,
  assertCleanupSafe: base.assertCleanupSafe,
};
