"use strict";
/**
 * Validates collected reports against the committed release matrix and candidate/source identity.
 * Invoked by the release collector and its CLI; consumes evidence only and never runs host tests
 * or enables a feature. Supporting fixtures cannot substitute for required native evidence.
 */
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { verifyReport } = require("./certops-qualification-report");
const { verify: verifyStack } = require("./certops-stack-report");
const { verify: verifyDatabase } = require("./certops-integration-report");
const matrix = require("../docs/certops/release-qualification-matrix.json");
const catalog = require("../docs/certops/e2e-scenario-catalog.json");
function catalogCoverage(specification = catalog) {
  const errors = require("./certops-qualification-catalog").validateCatalog(specification);
  if (errors.length) throw new Error("Invalid committed scenario catalog");
  const counts = { total: specification.scenarios.length, planned: 0, partial: 0, implemented: 0 };
  for (const row of specification.scenarios) counts[row.status]++;
  return { ...counts, implementationStatus: counts.implemented === counts.total ? "all-specifications-implemented" : "incomplete", executionEvidence: "reported-separately" };
}
function validateQualificationSummary(summary, specification = catalog) {
  const expected = catalogCoverage(specification);
  const errors = [];
  if (summary?.qualificationScope !== "committed-mandatory-matrix" || summary?.allFeaturesQualified !== false) errors.push("Matrix evidence cannot declare all certificate features qualified");
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
        !slot.requiredSources.length || new Set(slot.requiredSources).size !== slot.requiredSources.length ||
        slot.requiredSources.some(source => typeof source !== "string" || !source || path.isAbsolute(source) || source.split(/[\\/]/).includes("..")))) {
      errors.push(`${slot.id}: invalid supporting source inventory`);
    }
    const identity = JSON.stringify([slot.kind, slot.suite, Object.entries(slot.environment || {}).sort()]);
    if (identities.has(identity)) errors.push(`${slot.id}: duplicate suite/environment specification`); identities.add(identity);
    if (slot.kind === "host" && !require("../docs/certops/qualification-suites.json").suites[slot.suite]) errors.push(`${slot.id}: unknown mandatory suite`);
    if (slot.kind === "stack" && !slot.requiredInventory && !slot.requiredTests?.length) errors.push(`${slot.id}: mandatory tests are missing`);
    if (slot.kind === "database" && !require("../tests/integration/certops-qualification-groups.json")[slot.requiredGroup]) errors.push(`${slot.id}: unknown mandatory database group`);
  }
  for (const suite of Object.keys(require("../docs/certops/qualification-suites.json").suites)) if (!specification.slots.some((slot) => slot.kind === "host" && slot.suite === suite)) errors.push(`Mandatory suite has no release environment: ${suite}`);
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
        if (slot.suite === "dns-provider-errors") require("./certops-dns-provider-errors-report").verifyDnsErrors(artifact.report);
        if (slot.suite === "kubernetes-host") {
          const evidence = artifact.report.nativeCompaction;
          if (!evidence || evidence.expiredStatus !== 410 || !["productionClient", "productionObserver", "controlPlaneRestarted", "ownedSingleNodeCluster"].every(key => evidence[key] === true) ||
              !["originalResourceVersion", "compactedRevision", "observedResourceVersion"].every(key => typeof evidence[key] === "string" && /^[1-9][0-9]{0,19}$/.test(evidence[key])) ||
              typeof evidence.certificateUid !== "string" || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(evidence.certificateUid) || BigInt(evidence.originalResourceVersion) > BigInt(evidence.compactedRevision) || BigInt(evidence.observedResourceVersion) <= BigInt(evidence.compactedRevision)) throw new Error("Native watch compaction and recovery evidence incomplete");
        }
        if (slot.suite === "agent-log-maintenance-worker") require("./certops-log-maintenance-report").verify(artifact.report, root, candidateSha);
        if (slot.suite === "windows-host") { require("../packages/agent/scripts/host/cng-export-fixture").verifyCustodyProof(artifact.report.cngCustody); require("../packages/agent/scripts/host/iis-shared-port-fixture").verifyIsolationFacts(artifact.report.nativeSamePortSni); require("../packages/agent/scripts/host/enrollment-contention-fixture").verifyContentionFacts(artifact.report.nativeEnrollmentContention); }
        if (slot.suite === "browser-agent-console") require("./certops-completed-console-proof").verifyProof(artifact.report.completedConsolePrivacy);
        if (slot.suite === "windows-canonical-root-lifecycle") require("../tests/e2e/helpers/certops-windows-fixed-root").verifyProof(artifact.report.nativeCanonicalRoot);
        if (slot.suite === "windows-installer-first-rename-refusal") require("../tests/e2e/helpers/certops-windows-rename-refusal").verifyProof(artifact.report.nativeRenameRefusal);
        if (slot.suite === "windows-activation-second-rename") require("../tests/e2e/helpers/certops-windows-second-rename").verifyProof(artifact.report.nativeSecondRename);
        if (slot.suite === "windows-installer-cli-second-rename") require("../tests/e2e/helpers/certops-windows-cli-second-rename").verifyProof(artifact.report.nativeCliSecondRename);
        if (slot.suite === "windows-two-unattended-renewals") require("../tests/e2e/helpers/certops-windows-two-renewals").verifyProof(artifact.report.nativeTwoRenewals);
        if (slot.suite === "windows-certificate-dry-run") require("../tests/e2e/helpers/certops-windows-certificate-dry-run").verifyProof(artifact.report.nativeCertificateDryRun);
        if (slot.suite === "windows-host") require("./certops-native-key-survivor-proof").verifyProof(artifact.report.nativeKeySurvivors);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/cng-key-usage-proof").verifyProof(artifact.report.nativeKeyUsage);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/retention-ledger-atomic-fixture").verifyAtomicProof(artifact.report.nativeRetentionAtomicReplace);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/retention-elapsed-fixture").verifyElapsedProof(artifact.report.nativeElapsedRetention);
        if (slot.suite === "linux-systemd-published-upgrade") require("../tests/e2e/helpers/linux-systemd-published-upgrade").verifyProof(artifact.report.nativePublishedLinuxUpgrade);
        if (slot.suite === "linux-systemd-reapply") require("../tests/e2e/helpers/linux-systemd-reapply").verifyProof(artifact.report.nativeInstallerReapply);
        if (slot.suite === "native-agent-api") {
          require("../tests/e2e/helpers/certops-native-certificate-dry-run").verifyFacts(artifact.report.nativeCertificateDryRun);
          require("../tests/e2e/helpers/certops-native-dispatch-timing").verifyTimingFacts(artifact.report.nativeDispatchTiming);
          const privacy = artifact.report.nativeChildOutputPrivacy;
          if (!privacy || privacy.executedChildren !== 2 || !["stdoutEmitted", "stderrEmitted", "rawChildOutputWithheld", "genericExecutionMarkerPersisted", "jobSucceeded"].every(key => privacy[key] === true)) throw new Error("Native child-output confidentiality evidence incomplete");
          const cases = require("../docs/certops/qualification-suites.json").suites[slot.suite].filter(id => id.startsWith("native-agent-log-"));
          const rows = artifact.report.nativeLogFaults;
          if (!Array.isArray(rows) || rows.length !== cases.length) throw new Error("Native log transport fault evidence incomplete");
          for (const id of cases) {
            const found = rows.filter(row => row?.scenario === id);
            if (found.length !== 1 || !["actualNativeConsole", "jobSucceeded", "finalAcknowledged"].every(key => found[0][key] === true) ||
                found[0].attempts !== 1 || !Number.isInteger(found[0].persistedLines) || found[0].persistedLines < 1 || found[0].persistedLines > 1000 ||
                found[0].serverDroppedLines !== 0 || found[0].agentGapLines !== (id === "native-agent-log-413-drop-accounting" ? 1 : 0)) throw new Error("Native log transport persistence or gap evidence invalid");
          }
        }
        if (["enterprise-adcs-real", "enterprise-adcs-hierarchy-real"].includes(slot.suite)) {
          require("../tests/e2e/helpers/certops-adcs-browser-journey").verifyProof(artifact.report.nativeBrowserAdcs);
          const browserDispatch = artifact.report.browserNativePreflightDispatch;
          if (!browserDispatch || Object.keys(browserDispatch).sort().join(",") !== "count,jobIds" || browserDispatch.count !== 2 || !Array.isArray(browserDispatch.jobIds) || browserDispatch.jobIds.length !== 2 ||
              !browserDispatch.jobIds.every(id => typeof id === "string" && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(id)) || new Set(browserDispatch.jobIds.map(id => id.toLowerCase())).size !== 2) throw new Error("Browser native preflight dispatch accounting incomplete");
          require("../tests/e2e/helpers/certops-adcs-two-renewals").verifyProof(artifact.report.nativeAdcsTwoRenewals);
          require("../tests/e2e/helpers/certops-adcs-uncertain-abandon").assertProof(artifact.report.nativeUncertainAbandon);
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
        if (slot.suite === "linux-systemd-writepath") {
          const evidence = artifact.report.nativeWritePath;
          if (evidence?.freshExecStartPreEvidence !== true || evidence.hostDacWriteVerified !== true ||
              evidence.allowedWrite !== true || evidence.deniedError !== "EROFS" || evidence.samePeerDacMode !== "0777" ||
              !Number.isInteger(evidence.nonRootUid) || evidence.nonRootUid <= 0) throw new Error("Native systemd write-path isolation evidence incomplete");
        }
        if (slot.suite === "windows-historical-source-upgrade") require("../tests/e2e/helpers/certops-windows-source-upgrade").verifySourceUpgradeReport(artifact.report, { expectedSha: candidateSha });
        if (slot.suite === "windows-acme-wrong-spki") require("../tests/e2e/helpers/certops-windows-wrong-leaf").verifyProof(artifact.report.nativeWrongSpki);
        if (slot.suite === "windows-native-child-output-privacy") require("../tests/e2e/helpers/certops-windows-output-privacy").verifyPrivacyReport(artifact.report, { expectedSha: candidateSha });
        if (slot.suite === "enterprise-adcs-elapsed-pending-real") {
          require("./certops-adcs-pending-elapsed-report").verify(artifact.report, { expectedSha: candidateSha });
          const count = artifact.report.primaryNativePreflightDispatchCount;
          if (count !== undefined && (!Number.isInteger(count) || count < 0 || count > 18)) throw new Error("Elapsed AD CS preflight budget cannot claim the browser exception");
        }
        if (slot.suite === "core-api-migration-upgrade") {
          require("./certops-migration-upgrade-report").verifyEvidence(artifact.report);
          if (artifact.report.sourceIdentity?.candidate?.sha !== candidateSha) throw new Error("Migration candidate differs from release candidate");
          const lockDigest = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "pnpm-lock.yaml"))).digest("hex");
          if (artifact.report.sourceIdentity.candidate.lockfileSha256 !== lockDigest ||
              artifact.report.sourceIdentity.candidate.version !== require("../package.json").version) {
            throw new Error("Migration candidate package identity differs from the current candidate");
          }
        }
      } else if (slot.kind === "stack") {
        if (slot.suite.startsWith("real-agent-windows-acme-iis/")) {
          const native = entries.filter(entry => entry.name === "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence");
          if (native.length !== 1 || native[0].type !== "test:pass") throw new Error("Actual Windows native journey evidence missing");
          require("../tests/e2e/helpers/certops-windows-public-issuance").verifyPublicIssuanceFacts(native[0].windowsPublicIssuance);
        }
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
    const [candidateSha, ...files] = process.argv.slice(2);
    if (!files.length) throw new Error("Usage: certops-release-qualification.js <candidate-sha> <reports...>");
    const matrixErrors = validateMatrix();
    if (matrixErrors.length) throw new Error(matrixErrors.join("\n"));
    const errors = verifyMatrix(files.map(readArtifact), { candidateSha });
    if (errors.length) throw new Error(errors.join("\n"));
    const summary = { schemaVersion: 1, status: "passed", candidateSha, mandatoryEnvironments: matrix.slots.length, qualificationScope: "committed-mandatory-matrix", allFeaturesQualified: false, catalogCoverage: catalogCoverage() };
    const summaryErrors = validateQualificationSummary(summary);
    if (summaryErrors.length) throw new Error(summaryErrors.join("\n"));
    console.log(JSON.stringify(summary));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { verifyMatrix, readArtifact, validateMatrix, catalogCoverage, validateQualificationSummary };
