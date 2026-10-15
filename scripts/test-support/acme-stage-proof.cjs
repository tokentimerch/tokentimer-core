"use strict";
/** Synthetic offline schema fixtures, never native execution evidence. */
const helper = require("../../tests/e2e/helpers/certops-acme-stage-faults");
function proof(client = "certbot") {
  const id = (c) =>
    `${c.repeat(8)}-${c.repeat(4)}-4${c.repeat(3)}-8${c.repeat(3)}-${c.repeat(12)}`;
  return {
    schemaVersion: 1,
    scope: helper.SCOPE,
    client,
    failureOrigin: "owned-proxy-before-upstream-forwarding",
    cases: helper.STAGES.map((stage, index) => ({
      stage,
      jobId: id(index ? "b" : "a"),
      certificateId: id(index ? "d" : "c"),
      refusedRequests: 1,
      forwardedFaultRequests: 0,
      acceptedAccounts: 1,
      acceptedOrders: index,
      authorizationCount: index ? 3 : 0,
      validAuthorizationCount: index ? 3 : 0,
      identifiersSha256: "a".repeat(64),
    })),
    positiveJobId: id("e"),
    positiveFingerprint: "b".repeat(64),
    ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
  };
}
module.exports = { proof };
