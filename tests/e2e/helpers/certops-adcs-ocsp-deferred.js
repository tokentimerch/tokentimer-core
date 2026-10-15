"use strict";
// Preserve the reviewed OCSP entry point while sharing the transport-neutral
// signed continuation checks with the HTTP-only CRL composition.
const shared = require("./certops-adcs-deferred-continuation");
module.exports = {
  ...shared,
  continueDeferredOcsp: shared.continueDeferredIssuedLeaf,
};
