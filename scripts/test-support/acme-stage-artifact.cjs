"use strict";
/** Synthetic current-source stack fixtures for offline schema checks only. */
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const root = path.resolve(__dirname, "../..");
const CANDIDATE = "a".repeat(40);
function artifact(scope = "real-agent-acme-filesystem") {
  const slot =
    require("../../docs/certops/qualification-suites.json").slots.find(
      (row) => row.suite === scope,
    );
  const client = scope.includes("acmesh") ? "acme.sh" : "certbot";
  const source = (file) => ({
    file,
    sha256: crypto
      .createHash("sha256")
      .update(fs.readFileSync(path.join(root, file)))
      .digest("hex"),
  });
  const names = [
    ...require(path.join(root, slot.requiredInventory)).requiredTests,
    ...slot.requiredTests,
  ];
  const environment = { ...slot.environment, measurement: "native" };
  const events = names.map((name) => ({
    type: "test:pass",
    name,
    file: slot.source,
    scope,
    candidateSha: CANDIDATE,
    qualificationEnvironment: environment,
    artifactQualification: "workflow-checkout-source",
    fixtureSource: source(slot.source),
    fixtureSources: slot.requiredSources.map(source),
    skip: false,
    todo: false,
  }));
  const main = events.find(
    (event) => event.name === require("../certops-acme-stage-report").JOURNEY,
  );
  main.nativeAcmeStageFaults = require("./acme-stage-proof.cjs").proof(client);
  const reuse = require("../../tests/e2e/helpers/certops-acme-key-reuse"),
    id = (c) =>
      `${c.repeat(8)}-${c.repeat(4)}-4${c.repeat(3)}-8${c.repeat(3)}-${c.repeat(12)}`;
  main.nativeAcmeKeyReuse = {
    scope: reuse.scope,
    materialPaths: {scope:reuse.MATERIAL_PATH_SCOPE,observedGenerations:3,spaceAndUnicodeInEveryPath:true,...Object.fromEntries(reuse.MATERIAL_PATH_FLAGS.map(flag=>[flag,true])),...Object.fromEntries(reuse.MATERIAL_PATH_LIMITS.map(flag=>[flag,false]))},
    client,
    ...Object.fromEntries(reuse.fields.map((key) => [key, true])),
    fingerprints: ["a", "b", "c"].map((c) => c.repeat(64)),
    serials: ["A1", "B2", "C3"],
    spkiFingerprint: "d".repeat(64),
    sourceProfileFingerprint: "e".repeat(64),
    sourceProfileId: id("c"),
    jobIds: [id("1"), id("2")],
  };
  main.nativeAcmeBackgroundRenewals = require("./acme-background-proof.cjs").proof(client,main.nativeAcmeKeyReuse);
  if(scope==="real-agent-acme-filesystem"){main.nativeAcmeBulkRenewal=require("./acme-bulk-proof.cjs").proof(main.nativeAcmeKeyReuse);main.nativeAcmeRenewalSetup=require("./acme-native-adoption-proof.cjs").proof(main.nativeAcmeBulkRenewal);main.nativeAcmeCertificateOutbox=require("./acme-certificate-outbox-proof.cjs").proof(main.nativeAcmeBulkRenewal);main.nativeAcmeDisabledProfile=require("./acme-disabled-profile-proof.cjs").proof(main.nativeAcmeBulkRenewal);main.nativeAcmeRenewalAlert=require("./acme-renewal-alert-proof.cjs").proof(main.nativeAcmeCertificateOutbox);}
  return { kind: "stack", suite: scope, environment, events };
}
module.exports = { artifact, CANDIDATE };
