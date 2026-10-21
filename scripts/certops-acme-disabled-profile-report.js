"use strict";
/** Bounded reader for public facts from actual native disabled-profile manual renewal. */
const helper = require("../tests/e2e/helpers/certops-acme-disabled-profile");
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
