"use strict";
/** Bounded reader for the native renewal-failure SMTP sidecar. Offline bytes are not a native run. */
const helper = require("../tests/e2e/helpers/certops-acme-renewal-alert");
const {
  SCOPE,
  MAIN,
  createProofReader,
} = require("./certops-acme-bulk-report");
const { FIELD, SIDECAR } = helper;
const readProof = createProofReader(
  SIDECAR,
  helper.verifyProof,
  "Owned native renewal alert proof changed during read",
);

module.exports = { SCOPE, MAIN, FIELD, SIDECAR, readProof };
