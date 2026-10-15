"use strict";
/** Synthetic supporting fixture; never native execution evidence. */
const h = require("../../packages/agent/scripts/host/iis-public-only-fixture");
function fixture() {
  return {
    scope: h.SCOPE,
    refusalCode: "BIND_FAILED",
    installedSignedJobQualified: false,
    candidateFingerprint: "a".repeat(64),
    predecessorFingerprint: "b".repeat(64),
    ...Object.fromEntries(h.FLAGS.map((k) => [k, true])),
  };
}
module.exports = { fixture };
