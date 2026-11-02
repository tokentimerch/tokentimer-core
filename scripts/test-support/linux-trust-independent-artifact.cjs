"use strict";
const {sourceIdentity} = require("./qualification-artifact.cjs");
const {reportFacts} = require("./qualification-artifact.cjs");
/** Synthetic schema fixtures for offline verifier tests; never execution evidence. */

const helper = require("../certops-linux-trust-independent-roots");

const SUITE = "linux-trust-host",
  CANDIDATE = "a".repeat(40);
const contract = require("../certops-qualification-manifest");
const IDS = contract.suites[SUITE],
  CAPS = contract.requiredCapabilities[SUITE];
function nativeProof(version = "24.04") {
  return {
    schemaVersion: 1,
    scope: helper.SCOPE,
    family: version === "9.6" ? "rhel" : "debian",
    derivedReferenceKind:
      version === "9.6"
        ? "native-derived-certificate"
        : "native-source-symlink",
    rootFingerprints: ["a", "b"].map((c) => c.repeat(64)),
    leafFingerprints: ["c", "d"].map((c) => c.repeat(64)),
    ...Object.fromEntries(helper.FLAGS.map((n) => [n, true])),
  };
}

function conflictProof(version="24.04"){const h=require("../certops-linux-trust-receipt-conflict");return {schemaVersion:1,scope:h.SCOPE,family:version==="9.6"?"rhel":"debian",writerCount:2,serializationQualified:false,partialWriteRecoveryQualified:false,detachedDescendantContainmentQualified:false,losingFailureCategory:"receipt_finalize_conflict",firstJobId:"11111111-1111-4111-8111-111111111111",secondJobId:"22222222-2222-4222-8222-222222222222",fingerprints:["a".repeat(64),"b".repeat(64)],...Object.fromEntries(h.FLAGS.map(name=>[name,true]))};}
function artifact(version = "24.04") {
  const environment = {
    osFamily: "linux",
    distribution: version === "9.6" ? "almalinux" : "ubuntu",
    osVersion: version,
    measurement: "native",
    executionSurface:
      version === "9.6" ? "disposable-container" : "disposable-vm",
  };
  const source = sourceIdentity;
  const startedAt = "2026-10-15T01:00:00.000Z",
    finishedAt = "2026-10-15T01:01:00.000Z";
  const report = {
    ...reportFacts({ids: IDS, capabilities: CAPS, evidenceLevel: "real-host", startedAt: startedAt, finishedAt: finishedAt}),
    suite: SUITE,
    platform: "linux",
    architecture: "x64",
    nodeVersion: "v24.11.0",
    candidateSha: CANDIDATE,
    evidenceLevel: "real-host",
    startedAt,
    finishedAt,
    artifactQualification: "workflow-checkout-source",
    qualificationEnvironment: environment,
    fixtureSource: source("scripts/certops-linux-trust.js"),
    fixtureSources: [...new Set([...helper.REQUIRED_SOURCES,...require("../certops-linux-trust-receipt-conflict").REQUIRED_SOURCES])].map(source),
    nativeTrustReceiptConflict: conflictProof(version),
    nativeIndependentTrustRoots: nativeProof(version)
  };
  return { kind: "host", suite: SUITE, environment, report };
}
function slot(version = "24.04") {
  return require("../certops-qualification-manifest").slots.find(
    (row) => row.suite === SUITE && row.environment.osVersion === version,
  );
}

module.exports = { artifact, slot, nativeProof, conflictProof, SUITE, CANDIDATE, IDS, CAPS };
