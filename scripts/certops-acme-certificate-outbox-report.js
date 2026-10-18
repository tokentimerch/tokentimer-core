"use strict";
/** Bounded reader for public facts from actual native certificate result restart. */
const helper = require("../tests/e2e/helpers/certops-acme-certificate-outbox");
const {
  SCOPE,
  MAIN,
  createProofReader,
} = require("./certops-acme-bulk-report");
const { FIELD, SIDECAR } = helper;
const readProof = createProofReader(
  SIDECAR,
  helper.verifyProof,
  "Owned native certificate result restart proof changed during read",
);

module.exports = { SCOPE, MAIN, FIELD, SIDECAR, readProof };
