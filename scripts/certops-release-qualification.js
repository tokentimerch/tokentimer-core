"use strict";
/**
 * Validates collected reports against the committed release matrix and candidate/source identity.
 * Invoked by the release collector and its CLI; consumes evidence only and never runs host tests
 * or enables a feature. Supporting fixtures cannot substitute for required native evidence.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { verifyReport } = require("./certops-qualification-report");
const { verify: verifyStack } = require("./certops-stack-report");
const { verify: verifyDatabase } = require("./certops-integration-report");
const matrix = require("../docs/certops/qualification-suites.json");
const catalog = require("../docs/certops/qualification-suites.json");
// These registrations describe local contracts, with no native qualifying
// producer. A passed outer envelope must never upgrade their simulated proofs.
// A future native implementation must deliberately replace this eligibility gate.
const localContractSuites = new Set(["adcs-install-interruption", "adcs-lost-submit", "adcs-cmc-renewal", "adcs-safety-variants", "adcs-crash-experiments"]);
function catalogCoverage(specification = catalog) {
  const errors = require("./certops-qualification-catalog").validateCatalog(specification);
  if (errors.length) throw new Error("Invalid committed scenario catalog");
  const counts = { total: specification.scenarios.length, planned: 0, partial: 0, implemented: 0 };
  for (const row of specification.scenarios) counts[row.status]++;
  return { ...counts, implementationStatus: counts.implemented === counts.total ? "all-specifications-implemented" : "incomplete", executionEvidence: "reported-separately" };
}
function validateQualificationSummary(summary, specification = catalog, environmentMatrix = matrix) {
  const expected = catalogCoverage(specification);
  const errors = [];
  if(summary?.qualificationProfile !== undefined){
    try{require("./certops-qualification-profiles").validateProfileSummary(summary,environmentMatrix);}catch{errors.push("Declared qualification profile does not match committed selected/omitted environments");}
  }else if(summary?.qualificationScope!=="committed-mandatory-matrix")errors.push("Unknown qualification scope");
  if(summary?.allFeaturesQualified!==false)errors.push("Matrix evidence cannot declare all certificate features qualified");
  if (!summary?.catalogCoverage || Object.keys(summary.catalogCoverage).length !== Object.keys(expected).length || !Object.entries(expected).every(([key, value]) => summary.catalogCoverage[key] === value)) errors.push("Catalog implementation summary mismatch");
  return errors;
}

function validateMatrix(specification = matrix) {
  const errors = [];
  if (specification?.schemaVersion !== 1 || !Array.isArray(specification.slots) || !specification.slots.length) return ["Invalid committed release matrix"];
  // Match the collector's reviewed 512-slot/1024-item ceiling before any
  // qualification lab starts; collection headroom grows below this bound.
  if (specification.slots.length > 512) return ["Committed release matrix exceeds 512-slot collection policy"];
  const ids = new Set(); const identities = new Set();
  for (const slot of specification.slots) {
    if (!slot?.id || ids.has(slot.id)) { errors.push("Duplicate or missing matrix slot identity"); continue; } ids.add(slot.id);
    if (!["host", "stack", "database"].includes(slot.kind) || !slot.suite || !slot.source || !slot.environment || !["windows", "linux"].includes(slot.environment.osFamily)) errors.push(`${slot.id}: invalid environment specification`);
    if (typeof slot.source !== "string" || path.isAbsolute(slot.source) || slot.source.split(/[\\/]/).includes("..")) errors.push(`${slot.id}: source must remain inside the repository`);
    if (slot.requiredSources !== undefined && (!Array.isArray(slot.requiredSources) ||
        !slot.requiredSources.length || slot.requiredSources.length > 256 || new Set(slot.requiredSources).size !== slot.requiredSources.length ||
        slot.requiredSources.some(source => typeof source !== "string" || !source || path.isAbsolute(source) || /^[A-Za-z]:|^[\\/]/.test(source) || source.split(/[\\/]/).includes("..")))) {
      errors.push(`${slot.id}: invalid supporting source inventory`);
    }
    const identity = JSON.stringify([slot.kind, slot.suite, Object.entries(slot.environment || {}).sort()]);
    if (identities.has(identity)) errors.push(`${slot.id}: duplicate suite/environment specification`); identities.add(identity);
    if (slot.kind === "host" && !require("../docs/certops/qualification-suites.json").suites[slot.suite]) errors.push(`${slot.id}: unknown mandatory suite`);
    if (slot.kind === "stack" && !slot.requiredInventory && !slot.requiredTests?.length) errors.push(`${slot.id}: mandatory tests are missing`);
    if (slot.kind === "database" && !require("../tests/integration/certops-qualification-groups.json")[slot.requiredGroup]) errors.push(`${slot.id}: unknown mandatory database group`);
  }
  for (const suite of Object.keys(require("../docs/certops/qualification-suites.json").suites)) if (!specification.slots.some((slot) => slot.kind === "host" && slot.suite === suite) && !(specification.deferredSlots || []).some(slot => slot.suite === suite)) errors.push(`Mandatory suite has no release environment: ${suite}`);
  for (const group of Object.keys(require("../tests/integration/certops-qualification-groups.json"))) if (!specification.slots.some((slot) => slot.kind === "database" && slot.requiredGroup === group)) errors.push(`Mandatory database group has no release environment: ${group}`);
  return errors;
}

function verifyMatrix(artifacts, { candidateSha, root = path.resolve(__dirname, ".."), specification = matrix } = {}) {
  const errors = [];
  if (!/^[a-f0-9]{40}$/i.test(candidateSha || "")) errors.push("Explicit candidate SHA required");
  if (!Array.isArray(artifacts)) return [...errors, "Artifact collection must be an array"];
  if (specification.schemaVersion !== 1 || !Array.isArray(specification.slots) || !specification.slots.length) return [...errors, "Invalid committed release matrix"];
  const ids = new Set();
  for (const slot of specification.slots) {
    if (!slot?.id || ids.has(slot.id)) { errors.push("Duplicate or missing matrix slot identity"); continue; } ids.add(slot.id);
    if (!slot.environment || typeof slot.environment !== "object" || Array.isArray(slot.environment)) { errors.push(`${slot.id}: invalid host environment`); continue; }
    if (!["host", "stack", "database"].includes(slot.kind)) { errors.push(`${slot.id}: unsupported artifact kind`); continue; }
    const matches = artifacts.filter((artifact) => artifact?.kind === slot.kind && artifact?.suite === slot.suite && Object.entries(slot.environment).every(([key, value]) => artifact?.environment?.[key] === value));
    if (matches.length !== 1) { errors.push(`${slot.id}: requires exactly one matching environment artifact`); continue; }
    const artifact = matches[0];
    try {
      const entries = slot.kind === "stack" ? artifact.events : [artifact.report];
      if (!Array.isArray(entries) || !entries.length) throw new Error("Empty artifact evidence");
      const expectedDigest = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, slot.source))).digest("hex");
      for (const entry of entries) {
        if (entry.fixtureSources !== undefined && (!Array.isArray(entry.fixtureSources) || entry.fixtureSources.length > 256 || new Set(entry.fixtureSources.map(item => item?.file)).size !== entry.fixtureSources.length || entry.fixtureSources.some(item => typeof item?.file !== "string" || path.isAbsolute(item.file) || /^[A-Za-z]:/.test(item.file) || item.file.split(/[\\/]/).includes("..")))) throw new Error("Supporting source inventory exceeds bounds or ownership");
        if (entry.qualificationStatus === "not-qualified" || entry.experimental === true) throw new Error("Experimental evidence cannot qualify a release");
        if (entry.candidateSha !== candidateSha) throw new Error("Candidate identity mismatch");
        if (entry.qualificationEnvironment?.measurement !== "native" || !Object.entries(slot.environment).every(([key, value]) => entry.qualificationEnvironment?.[key] === value)) throw new Error("Host measurement mismatch");
        if (slot.kind !== "database" && (entry.fixtureSource?.file !== slot.source || entry.fixtureSource?.sha256 !== expectedDigest)) throw new Error("Current source identity mismatch");
        for (const source of slot.requiredSources || []) {
          const digest = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, source))).digest("hex");
          const records = Array.isArray(entry.fixtureSources) ? entry.fixtureSources.filter(record => record?.file === source) : [];
          if (records.length !== 1 || records[0].sha256 !== digest) throw new Error("Supporting source identity mismatch");
        }
        if (entry.artifactQualification !== "workflow-checkout-source") throw new Error("Release evidence must come from a workflow checkout");
      }
      if (slot.kind === "host") {
        if (artifact.report.suite !== slot.suite) throw new Error("Suite mismatch");
        if (verifyReport(artifact.report, undefined, { expectedSha: candidateSha }).length) throw new Error("Mandatory runtime evidence incomplete");
        if (localContractSuites.has(slot.suite)) throw new Error("Local-contract-only suite has no native qualifying producer");





        if (slot.suite === "enterprise-adcs-real") require("../tests/e2e/helpers/certops-adcs-pending-ca-renewal").verifyCrossProof(artifact.report.nativePendingCaRenewal,artifact.report.nativeAdcsCapacity);
        if (slot.suite === "enterprise-adcs-real") require("../tests/e2e/helpers/certops-adcs-pending-ca-key-change").verifyCrossProof(artifact.report.nativePendingCaKeyChange,artifact.report.nativePendingCaRenewal);
        if (slot.suite === "enterprise-adcs-hierarchy-real") require("../tests/e2e/helpers/certops-adcs-http-intermediate-crl").verifyProof(artifact.report.nativeHttpIntermediateCrl);
        if (["enterprise-adcs-real", "enterprise-adcs-hierarchy-real"].includes(slot.suite)) {
          require("../tests/e2e/helpers/certops-adcs-issued-revocation").verifyProof(artifact.report.nativeIssuedRevocation);
          require("../tests/e2e/helpers/certops-adcs-cancelled-late-approval").verifyProof(artifact.report.nativeCancelledLateApproval);
          require("../tests/e2e/helpers/certops-adcs-cancelled-late-approval").verifySameCertificateProof(artifact.report.nativeSameCertificateLateApproval);
          require("../tests/e2e/helpers/certops-adcs-issued-san-boundary").verifyProof(artifact.report.nativeIssuedSanBoundary);
          require("../tests/e2e/helpers/certops-adcs-browser-abandon").verifyProof(artifact.report.nativeBrowserAbandon);
          require("../tests/e2e/helpers/certops-adcs-browser-admin-boundary").verifyProof(artifact.report.nativeBrowserAdminBoundary);
          if (artifact.report.nativeBrowserAdminBoundary.enrollmentId !== artifact.report.nativeBrowserAbandon.enrollmentId) throw new Error("Role boundary must bind the genuine abandoned enrollment");
          require("../tests/e2e/helpers/certops-adcs-browser-reconcile").verifyCrossProof(artifact.report.nativeBrowserReconcile, artifact.report.nativeUncertainOperatorAmbiguity);
          require("../tests/e2e/helpers/certops-adcs-public-foreign-spki").verifyCrossProof(artifact.report.nativePublicForeignSpki, artifact.report.nativeUncertainOperatorAmbiguity);
          require("../tests/e2e/helpers/certops-adcs-template-required-attributes").verifyProof(artifact.report.nativeRequiredTemplateAttributes);
          require("../tests/e2e/helpers/certops-adcs-live-enroll-acl").verifyProof(artifact.report.nativeLiveEnrollAcl);
          require("../tests/e2e/helpers/certops-adcs-http-leaf-crl").verifyProof(artifact.report.nativeHttpOnlyLeafCrl);
          require("../tests/e2e/helpers/certops-adcs-ocsp-proof").verifyProof(artifact.report.nativeOcspResponder);
          require("../tests/e2e/helpers/certops-adcs-ocsp-revoked").verifyCrossProof(artifact.report.nativeOcspRevoked, artifact.report.nativeOcspResponder);
          require("../tests/e2e/helpers/certops-adcs-result-outbox").verifyProof(artifact.report.nativeAdcsResultOutbox);
          require("../tests/e2e/helpers/certops-adcs-capacity").verifyProof(artifact.report.nativeAdcsCapacity);
          require("../tests/e2e/helpers/certops-adcs-browser-cancel").verifyCrossProof(artifact.report.nativeBrowserCancel, artifact.report.nativeAdcsCapacity);
          require("../tests/e2e/helpers/certops-adcs-browser-job-approval").verifyCrossProof(artifact.report.nativeBrowserJobApproval, artifact.report.nativeAdcsCapacity);
          require("../tests/e2e/helpers/certops-adcs-webhosting-renewal").verifyProof(artifact.report.nativeWebHostingRenewal);
          require("../tests/e2e/helpers/certops-adcs-algorithm-boundaries").verifyProof(artifact.report.nativeAlgorithmBoundaries);
          require("../tests/e2e/helpers/certops-adcs-cmc-signature-copy").verifyProof(artifact.report.nativeCmcBoundaries);
          require("../tests/e2e/helpers/certops-adcs-browser-journey").verifyProof(artifact.report.nativeBrowserAdcs);
          require("../tests/e2e/helpers/certops-adcs-local-rules").verifyPairProof(artifact.report.nativeLocalRulePairs);
          require("../tests/e2e/helpers/certops-adcs-local-rules").verifyTighteningProof(artifact.report.nativeLocalRuleTightening);
          require("../tests/e2e/helpers/certops-adcs-local-rules").verifySurvivorProof(artifact.report.nativePendingKeySurvivor);
          require("../tests/e2e/helpers/certops-adcs-native-reconcile").verifyForeignProof(artifact.report.nativeForeignSpkiCandidate);
          const browserDispatch = artifact.report.browserNativePreflightDispatch;
          if (!browserDispatch || Object.keys(browserDispatch).sort().join(",") !== "count,jobIds" || browserDispatch.count !== 2 || !Array.isArray(browserDispatch.jobIds) || browserDispatch.jobIds.length !== 2 ||
              !browserDispatch.jobIds.every(id => typeof id === "string" && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(id)) || new Set(browserDispatch.jobIds.map(id => id.toLowerCase())).size !== 2) throw new Error("Browser native preflight dispatch accounting incomplete");
          require("../tests/e2e/helpers/certops-adcs-two-renewals").verifyProof(artifact.report.nativeAdcsTwoRenewals);
          require("../tests/e2e/helpers/certops-adcs-background-renewals").verifyProof(artifact.report.nativeAdcsBackgroundRenewals);
          require("../tests/e2e/helpers/certops-adcs-uncertain-abandon").assertProof(artifact.report.nativeUncertainAbandon);
          require("../tests/e2e/helpers/certops-adcs-uncertain-operator-ambiguity").verifyProof(artifact.report.nativeUncertainOperatorAmbiguity);
          require("../tests/e2e/helpers/certops-adcs-uncertain-operator-unique").verifyProof(artifact.report.nativeUncertainOperatorUnique);
          require("../tests/e2e/helpers/certops-adcs-issued-cancellation").verifyIssuedCancellationFacts(artifact.report.nativeIssuedCancellation);
          const expiry = artifact.report.nativeValidationExpiry;
          if (!expiry || expiry.configuredTimeoutSeconds !== 300 || expiry.defaultTimeoutSeconds !== 86400 ||
              !Number.isFinite(expiry.storedWindowSeconds) || expiry.storedWindowSeconds < 270 || expiry.storedWindowSeconds > 300 ||
              !Number.isFinite(expiry.monotonicObservedWaitSeconds) || expiry.monotonicObservedWaitSeconds < 300 || expiry.monotonicObservedWaitSeconds > 86400 ||
              typeof expiry.actualDeadline !== "string" || !Number.isFinite(Date.parse(expiry.actualDeadline)) ||
              typeof expiry.requestId !== "string" || !/^[1-9][0-9]{0,9}$/.test(expiry.requestId) || Number(expiry.requestId) > 0xffffffff ||
              typeof expiry.snapshotSha256 !== "string" || !/^[a-f0-9]{64}$/.test(expiry.snapshotSha256) ||
              !["actualNativeRevocationUnknown", "actualSignedContinuationExpired", "persistedDeadlineSurvivedRestartAndPolicyRestoration", "exactUnacceptedKeyFreed", "noCertificateAccepted", "noCaResubmission", "outgoingTrustedTlsPreserved", "chainCacheValueRestored"].every(key => expiry[key] === true) ||
              expiry.nativeAndCaClocks !== "actual" || expiry.qualificationScope !== "configured-five-minute-window-not-default-24-hour-elapsed") throw new Error("Actual configured native validation deadline evidence incomplete");
          const count = artifact.report.primaryNativePreflightDispatchCount, cohorts = artifact.report.nativePreflightCohorts;
          if (!Number.isInteger(count) || count < 2 || count > 20 || count - browserDispatch.count > 18 || !Array.isArray(cohorts) || cohorts.length > 128) throw new Error("Native preflight budget evidence incomplete");
          const workspaces = new Set(), agents = new Set();
          for (const cohort of cohorts) {
            if (!cohort || ![cohort.workspaceId, cohort.agentId].every(id => typeof id === "string" && /^[a-f0-9-]{36}$/i.test(id)) ||
                workspaces.has(cohort.workspaceId) || agents.has(cohort.agentId) || !Number.isInteger(cohort.dispatchCount) || cohort.dispatchCount < 1 || cohort.dispatchCount > 18 ||
                cohort.dispatchLimit !== 18 || cohort.nativeIdentity !== "LocalSystem" || cohort.runtime !== "candidate-cli") throw new Error("Native preflight cohort evidence invalid");
            workspaces.add(cohort.workspaceId); agents.add(cohort.agentId);
          }
          const mutations = artifact.report.nativeTemplateMutations;
          const mutationCases = require("../docs/certops/qualification-suites.json").suites[slot.suite].filter(id => id.startsWith("adcs-real-mutated-template-")).map(id => id.slice("adcs-real-mutated-template-".length, -"-native-refused".length));
          if (!Array.isArray(mutations) || mutations.length !== mutationCases.length) throw new Error("Native template mutation evidence incomplete");
          for (const caseId of mutationCases) {
            const rows = mutations.filter(item => item?.caseId === caseId);
            if (rows.length !== 1 || rows[0].template !== "TTQualificationRSAShort" || !["unsafe", "unreadable"].includes(rows[0].preflightVerdict) ||
                !["originalConfirmedIssuerReused", "actualSignedJobRefused", "noCaRequestAllocated", "noKeyGenerated", "outgoingTrustedTlsPreserved"].every(key => rows[0][key] === true)) throw new Error("Native template mutation refusal evidence invalid");
          }
        }

        if (slot.suite === "native-adcs-issuer-reassignment") {
          const proof = artifact.report.nativeIssuerReassignment;
          require("../tests/e2e/helpers/certops-native-issuer-reassignment").verifyNativeProof(proof);
          const n = artifact.report.qualificationEnvironment;
          if (artifact.report.nativeCell !== "qualified" || artifact.report.cleanup?.status !== "passed" || artifact.report.platform !== "win32" || artifact.report.architecture !== "x64" || n.osVersion !== "2022" || n.nativeLanguage !== "en-US" || n.osFamily !== "windows" || n.identity !== "LocalSystem" || n.measurement !== "native") throw new Error("Native issuer reassignment requires completed SYSTEM Server2022 two-CA execution and cleanup");
        }
        if(slot.suite === "adcs-browser-enrollment"){
          require("../tests/e2e/helpers/certops-adcs-browser-enrollment").verifyNativeProof(artifact.report.nativeAdcsBrowserEnrollment);
          const n=artifact.report.qualificationEnvironment;
          if(artifact.report.platform!=="win32"||artifact.report.architecture!=="x64"||n.osFamily!=="windows"||n.osVersion!=="2022"||n.nativeLanguage!=="en-US"||n.identity!=="LocalSystem"||n.measurement!=="native"||artifact.report.cleanup?.status!=="passed")throw new Error("Native browser enrollment requires completed SYSTEM root-domain Server2022 execution");
        }
        if(slot.suite === "adcs-uncertain-abandon"){
          require("./certops-adcs-uncertain-abandon-native").verifyNativeProof(artifact.report.nativeAdcsUncertainAbandon);
          const n=artifact.report.qualificationEnvironment;
          if(artifact.report.platform!=="win32"||artifact.report.architecture!=="x64"||n.osFamily!=="windows"||n.osVersion!=="2022"||n.nativeLanguage!=="en-US"||n.identity!=="LocalSystem"||n.measurement!=="native"||artifact.report.cleanup?.status!=="passed")throw new Error("Native uncertain abandon requires completed SYSTEM root-domain Server2022 execution");
        }
        if (slot.suite === "enterprise-adcs-elapsed-pending-real") {
          require("./certops-adcs-pending-elapsed-report").verify(artifact.report, { expectedSha: candidateSha });
          const count = artifact.report.primaryNativePreflightDispatchCount;
          if (count !== undefined && (!Number.isInteger(count) || count < 0 || count > 18)) throw new Error("Elapsed AD CS preflight budget cannot claim the browser exception");
        }

      } else if (slot.kind === "stack") {


        const required = slot.requiredInventory ? require(path.join(root, slot.requiredInventory)).requiredTests : [];
        verifyStack(entries.map((entry) => JSON.stringify(entry)).join("\n"), [...required, ...(slot.requiredTests || [])], path.basename(slot.source), slot.suite, candidateSha);
      } else if (slot.kind === "database") {
        const definition = require("../tests/integration/certops-qualification-groups.json")[slot.requiredGroup];
        if (!definition || artifact.report.evidenceLevel !== "integration") throw new Error("Unknown database evidence classification");
        if (!Array.isArray(artifact.report.fixtureSources) || artifact.report.fixtureSources.length !== definition.files.length) throw new Error("Database source inventory mismatch");
        for (const file of definition.files) {
          const relative = `tests/integration/${file}`;
          const expected = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, relative))).digest("hex");
          if (artifact.report.fixtureSources.filter((source) => source?.file === relative && source.sha256 === expected).length !== 1) throw new Error("Database source identity mismatch");
        }
        verifyDatabase(artifact.report, definition.requiredTests, candidateSha, slot.suite);
      }
    } catch (error) { errors.push(`${slot.id}: ${error.message}`); }
  }
  // Extra evidence may be retained, but a repeated identical environment/suite
  // cannot satisfy a slot or conceal a failed attempt by choosing a green one.
  return errors;
}
function readArtifact(file) {
  const raw = fs.readFileSync(file, "utf8");
  if (path.extname(file) === ".jsonl") {
    const events = raw.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
    return { kind: "stack", suite: events[0]?.scope, environment: events[0]?.qualificationEnvironment, events };
  }
  const report = JSON.parse(raw);
  if (typeof report.scope === "string" && Array.isArray(report.tests)) return { kind: "database", suite: report.scope, environment: report.qualificationEnvironment, report };
  return { kind: "host", suite: report.suite, environment: report.qualificationEnvironment, report };
}
if (require.main === module) {
  try {
    const profiles=require("./certops-qualification-profiles");
    const parsed=profiles.parseArguments(process.argv.slice(2));
    const [candidateSha, ...files] = parsed.rest;
    const selection=profiles.selectProfile(matrix,parsed.profile);
    if (!files.length) throw new Error("Usage: certops-release-qualification.js <candidate-sha> <reports...>");
    const matrixErrors = validateMatrix();
    if (matrixErrors.length) throw new Error(matrixErrors.join("\n"));
    const errors = verifyMatrix(files.map(readArtifact), { candidateSha, specification:selection.specification });
    if (errors.length) throw new Error(errors.join("\n"));
    const summary = { schemaVersion: 1, status: "passed", candidateSha, mandatoryEnvironments: selection.selectedSlotIds.length, ...profiles.summaryFields(selection,true), allFeaturesQualified: false, catalogCoverage: catalogCoverage() };
    const summaryErrors = validateQualificationSummary(summary);
    profiles.validateProfileSummary(summary,matrix);
    if (summaryErrors.length) throw new Error(summaryErrors.join("\n"));
    console.log(JSON.stringify(summary));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { verifyMatrix, readArtifact, validateMatrix, catalogCoverage, validateQualificationSummary };
