"use strict";
/** Bounded reader for public facts from actual native renewal setup. */
const helper = require("../tests/e2e/helpers/certops-acme-native-adoption");
const {
  SCOPE,
  MAIN,
  createProofReader,
} = require("./certops-acme-bulk-report");
const FIELD = "nativeAcmeRenewalSetup",
  SIDECAR = "qualification-results/acme-native-renewal-setup-proof.json";
const readProof = createProofReader(
  SIDECAR,
  helper.verifyProof,
  "Owned native renewal setup proof changed during read",
);

module.exports = { SCOPE, MAIN, FIELD, SIDECAR, readProof };
