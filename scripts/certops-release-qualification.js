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
const matrix = require("../docs/certops/release-qualification-matrix.json");
const catalog = require("../docs/certops/e2e-scenario-catalog.json");
// These registrations describe local contracts, with no native qualifying
// producer. A passed outer envelope must never upgrade their simulated proofs.
// A future native implementation must deliberately replace this eligibility gate.
const localContractSuites = new Set([
  ...require("./_registration/adcs-coverage.json").suites.map(item => item.id).filter(id => !["adcs-browser-enrollment","adcs-uncertain-abandon"].includes(id)),
  ...require("./_registration/cross-coverage.json").suites.map(item => item.id),
  ...require("./_registration/windows-coverage.json").contracts.map(item => item.suiteId),
]);
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
        if (slot.suite === "dns-provider-errors") require("./certops-dns-provider-errors-report").verifyDnsErrors(artifact.report);
        if(slot.suite==="linux-native-acme-browser-lifecycle"){
          require("../tests/e2e/helpers/certops-acme-browser-lifecycle").verifyProof(artifact.report.nativeAcmeBrowserLifecycle);
          require("../tests/e2e/helpers/certops-native-file-discovery").verifyProof(artifact.report.nativeFileDiscoveryRefusals);
          const n=artifact.report.qualificationEnvironment;
          if(artifact.report.platform!=="linux"||artifact.report.architecture!=="x64"||n.osFamily!=="linux"||n.distributionId!=="ubuntu"||n.distributionVersion!=="24.04"||n.executionSurface!=="host"||n.libc!=="glibc")throw new Error("Native browser issue/renew lifecycle requires exact Ubuntu host scope");
        }
        if(slot.suite==="linux-installed-file-discovery"){
          require("../tests/e2e/helpers/certops-linux-installed-discovery").verifyProof(artifact.report.nativeInstalledFileDiscovery);
          const native=artifact.report.qualificationEnvironment;
          if(artifact.report.platform!=="linux"||artifact.report.architecture!=="x64"||native.measurement!=="native"||native.osFamily!=="linux"||native.distributionId!=="ubuntu"||!["22.04","24.04"].includes(native.distributionVersion)||native.executionSurface!=="host")throw new Error("Installed discovery requires the declared native Ubuntu systemd host");
        }
        if (slot.suite === "dns-routing-host") {
          require("./certops-dns-resolver-views").verifyProof(artifact.report.nativeResolverViews);
          require("./certops-dns-hook-interruption").verifyProof(artifact.report.nativeDnsHookInterruption);
          if (!artifact.report.scenarios.some(row => row.id === require("./certops-dns-hook-interruption").SCENARIO && row.status === "passed")) throw new Error("Native DNS interruption scenario required");
          const native=artifact.report.qualificationEnvironment;
          if(artifact.report.platform!=="linux" || artifact.report.architecture!=="x64" || native.osFamily!=="linux" || native.distributionId!=="ubuntu" || native.distributionVersion!=="24.04" || native.executionSurface!=="host")throw new Error("Native configured DNS resolver views require the owned Ubuntu host");
        }
        if (slot.suite === "kubernetes-host") {
          require("./certops-kubernetes-rbac").verifyProof(artifact.report.nativeKubernetesRbacStartupRecovery);
          const evidence = artifact.report.nativeCompaction;
          if (!evidence || evidence.expiredStatus !== 410 || !["productionClient", "productionObserver", "controlPlaneRestarted", "ownedSingleNodeCluster"].every(key => evidence[key] === true) ||
              !["originalResourceVersion", "compactedRevision", "observedResourceVersion"].every(key => typeof evidence[key] === "string" && /^[1-9][0-9]{0,19}$/.test(evidence[key])) ||
              typeof evidence.certificateUid !== "string" || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(evidence.certificateUid) || BigInt(evidence.originalResourceVersion) > BigInt(evidence.compactedRevision) || BigInt(evidence.observedResourceVersion) <= BigInt(evidence.compactedRevision)) throw new Error("Native watch compaction and recovery evidence incomplete");
        }
        if (slot.suite === "agent-log-maintenance-worker") require("./certops-log-maintenance-report").verify(artifact.report, root, candidateSha);
        if (slot.suite === "windows-host") { require("../packages/agent/scripts/host/cng-export-fixture").verifyCustodyProof(artifact.report.cngCustody); require("../packages/agent/scripts/host/iis-shared-port-fixture").verifyIsolationFacts(artifact.report.nativeSamePortSni); require("../packages/agent/scripts/host/enrollment-contention-fixture").verifyContentionFacts(artifact.report.nativeEnrollmentContention); }
        if (slot.suite === "browser-agent-console") require("./certops-completed-console-proof").verifyProof(artifact.report.completedConsolePrivacy);
        if (slot.suite === "windows-domain-adcs-default-ttl24h") {
          const helper = require("./certops-adcs-ttl24h-proof"); helper.verifyProof(artifact.report[helper.FIELD]);
          if (artifact.report[helper.FIELD].candidateSha !== candidateSha || artifact.report.platform !== "win32" || artifact.report.architecture !== "x64" || artifact.report.cleanup?.status !== "passed") throw new Error("Actual TTL native environment, candidate and cleanup required");
        }
        if (slot.suite === "windows-domain-installed-retention-default-timer") {
          const native = require("./certops-retention-cadence-proof").verifyProof(artifact.report.nativeRetentionCadence);
          if (native.candidateSha !== candidateSha || artifact.report.platform !== "win32" || artifact.report.architecture !== "x64" || artifact.report.cleanup?.status !== "passed") throw new Error("Installed timer native environment, original candidate and cleanup required");
        }
        if (slot.suite === "windows-domain-adcs-retention24h") require("./certops-retention24h-proof").verifyProof(artifact.report.nativeRetention24h);
        if (slot.suite === "windows-canonical-root-lifecycle") {
          if (artifact.report.nativeCanonicalRoot?.scope !== "unmodified-candidate-cli-canonical-root-same-version-reapplication") throw new Error("Native canonical-root lifecycle proof required; local contract cannot qualify");
          require("../tests/e2e/helpers/certops-windows-fixed-root").verifyProof(artifact.report.nativeCanonicalRoot);
        }
        if (slot.suite === "windows-installer-first-rename-refusal") require("../tests/e2e/helpers/certops-windows-rename-refusal").verifyProof(artifact.report.nativeRenameRefusal);
        if (slot.suite === "windows-activation-second-rename") {
          if (artifact.report.nativeSecondRename?.scope !== "production-activation-functions-not-installer-cli") throw new Error("Native second-rename activation proof required; local contract cannot qualify");
          require("../tests/e2e/helpers/certops-windows-second-rename").verifyProof(artifact.report.nativeSecondRename);
        }
        if (slot.suite === "windows-installer-cli-second-rename") require("../tests/e2e/helpers/certops-windows-cli-second-rename").verifyProof(artifact.report.nativeCliSecondRename);
        if (slot.suite === "windows-arm64-installed-agent") require("./certops-arm64-installed-proof").verifyRuntimeReport(artifact.report);
        if (slot.suite === "windows-arm64-packaged-scm") require("./certops-arm64-scm-proof").verifyRuntimeReport(artifact.report);
        if (slot.suite === "windows-arm64-cng-runtime") require("./certops-arm64-runtime-proof").verifyRuntimeReport(artifact.report);
        if (slot.suite === "windows-two-unattended-renewals") require("../tests/e2e/helpers/certops-windows-two-renewals").verifyProof(artifact.report.nativeTwoRenewals);
        if (slot.suite === "windows-certificate-dry-run") require("../tests/e2e/helpers/certops-windows-certificate-dry-run").verifyProof(artifact.report.nativeCertificateDryRun);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/iis-public-only-fixture").verifyProof(artifact.report.nativeIisPublicOnly);
        if (slot.suite === "windows-host") require("./certops-native-key-survivor-proof").verifyProof(artifact.report.nativeKeySurvivors);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/cng-key-usage-proof").verifyProof(artifact.report.nativeKeyUsage);
        if (slot.suite === "windows-installed-alive-grace-renewal") require("../tests/e2e/helpers/certops-windows-alive-grace-proof").verifyProof(artifact.report.nativeWindowsAliveGrace);
        if (slot.suite === "windows-installed-failed-rollback-renewal") require("../tests/e2e/helpers/certops-windows-installed-failed-rollback").verifyProof(artifact.report.nativeInstalledFailedRollback);
        if (["windows-installed-stop-offline-renewal","windows-installed-alive-grace-renewal","windows-installed-failed-rollback-renewal","windows-installed-bind-failure-rollback","windows-installed-interruption-recovery"].includes(slot.suite)) {
          if(slot.suite === "windows-installed-stop-offline-renewal") require("../tests/e2e/helpers/certops-windows-stop-offline-proof").verifyProof(artifact.report.nativeWindowsStoppedOffline);
          const env=artifact.report.qualificationEnvironment;
          if(artifact.report.cleanup?.status!=="passed" || artifact.report.platform!=="win32" || artifact.report.architecture!=="x64" || env.osFamily!=="windows" || !["2022","2025"].includes(env.osVersion) || ![2,3].includes(env.productType) || env.identity!=="LocalSystem" || env.nativeLanguage!=="en-US" || env.measurement!=="native" || env.architecture!=="x64") throw new Error("Actual SYSTEM Server stopped/offline native environment and cleanup required");
        }
        if (slot.suite === "windows-webhosting-retention") { if (artifact.report.cleanup?.status !== "passed") throw new Error("WebHosting owned cleanup incomplete"); require("../packages/agent/scripts/host/retention-webhosting-fixture").verifyProof(artifact.report.nativeWebHostingRetention); }
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/iis-client-settings-fixture").verifyProof(artifact.report.nativeHttpSysClientSettings);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/packaged-helper-runtime-fixture").verifyProof(artifact.report.nativePackagedChainRuntime);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/retention-ledger-atomic-fixture").verifyAtomicProof(artifact.report.nativeRetentionAtomicReplace);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/retention-elapsed-fixture").verifyElapsedProof(artifact.report.nativeElapsedRetention);
        if (slot.suite === "windows-host") {
          const policies = artifact.report.nativeRetentionPolicyExpiry;
          assert.deepEqual(Object.keys(policies || {}).sort(), ["168", "720"]);
          const helper = require("../packages/agent/scripts/host/retention-policy-expiry-proof");
          for (const hours of helper.POLICIES) { assert.equal(policies[String(hours)].configuredRetentionHours, hours); helper.verifyProof(policies[String(hours)]); }
        }
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/retention-reference-fixture").verifyProof(artifact.report.nativeRetentionReferences);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/credential-weak-acl-fixture").verifyProof(artifact.report.nativeCredentialWeakAcl);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/state-read-refusal-fixture").verifyProof(artifact.report.nativeStateReadRefusals);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/journal-read-refusal-fixture").verifyProof(artifact.report.nativeJournalReadRefusals);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/retention-ledger-read-refusal-fixture").verifyProof(artifact.report.nativeLedgerReadRefusals);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/orphan-journal-fixture").verifyProof(artifact.report.nativeOrphanJournalProtection);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/orphan-journal-acl-fixture").verifyProof(artifact.report.nativeCngJournalAcl);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/retention-configured-timer-fixture").verifyProof(artifact.report.supportingConfiguredRetentionTimer);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/ipv6-shadow-fixture").verifyProof(artifact.report.nativeIpv6SniShadow);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/ipv6-wildcard-fixture").verifyProof(artifact.report.nativeIpv6WildcardShadow);
        if (slot.suite === "windows-host") require("../packages/agent/scripts/host/ipv4-wildcard-fixture").verifyProof(artifact.report.nativeIpv4WildcardShadow);
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
        if (["nginx-host","apache-host","haproxy-host"].includes(slot.suite)) {
          const p=artifact.report.nativeDaemonCoordinatorRollback,n=artifact.report.qualificationEnvironment;require("./certops-daemon-coordinator-rollback").verifyProof(p);
          const served=artifact.report.nativeDaemonServedLeafMismatch;require("./certops-daemon-served-leaf-mismatch").verifyProof(served);if(served.service!==p.service || JSON.stringify(served.fingerprints)!==JSON.stringify(p.fingerprints))throw new Error("Native served-leaf mismatch original fixture binding required");
          if(p.service+"-host"!==slot.suite || artifact.report.platform!=="linux" || artifact.report.architecture!=="x64" || n.osFamily!=="linux" || n.distributionId!=="ubuntu" || !["22.04","24.04"].includes(n.distributionVersion) || n.executionSurface!=="host")throw new Error("Native consuming-daemon rollback environment required");
        }
        if (slot.suite === "linux-public-signed-trust-lifecycle") {
          const h=require("./certops-linux-signed-trust-proof");h.verifyProof(artifact.report[h.FIELD]);
          const n=artifact.report.qualificationEnvironment;
          if(artifact.report.platform!=="linux"||artifact.report.architecture!=="x64"||n.osFamily!=="linux"||n.distribution!=="ubuntu"||n.osVersion!=="24.04"||n.measurement!=="native"||n.executionSurface!=="disposable-vm")throw new Error("Native Ubuntu24 signed trust evidence required");
        }
        if (slot.suite === "native-certificate-signing-rotation") {
          require("../tests/e2e/helpers/certops-acme-certificate-signing").verifyProof(artifact.report.nativeCertificateSigningRotation);
          const n = artifact.report.qualificationEnvironment;
          if (artifact.report.platform !== "linux" || artifact.report.architecture !== "x64" || n.osFamily !== "linux" || n.distributionId !== "ubuntu" || n.distributionVersion !== "24.04" || n.distribution !== "ubuntu" || n.osVersion !== "24.04" || n.executionSurface !== "host" || n.measurement !== "native") throw new Error("Ubuntu24 certificate signing rotation evidence required");
        }
        if (slot.suite === "windows-installed-bind-failure-rollback") require("../tests/e2e/helpers/certops-windows-installed-bind-failure-native").verifyProof(artifact.report.nativeInstalledBindFailure);
        if (slot.suite === "windows-installed-interruption-recovery") require("../tests/e2e/helpers/certops-windows-interruption-native").verifyProof(artifact.report.nativeInstalledInterruption);
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
        const adcsLocalContracts = {
          "adcs-install-interruption": ["../tests/e2e/helpers/certops-adcs-install-interruption", "nativeAdcsInstallInterruption"],
          "adcs-lost-submit": ["../tests/e2e/helpers/certops-adcs-lost-submit", "nativeAdcsLostSubmit"],
          "adcs-cmc-renewal": ["../tests/e2e/helpers/certops-adcs-cmc-renewal", "nativeAdcsCmcRenewal"],
          "adcs-safety-variants": ["../tests/e2e/helpers/certops-adcs-safety-variants", "nativeAdcsSafetyVariants"],
          "adcs-crash-experiments": ["../tests/e2e/helpers/certops-adcs-crash-experiments", "nativeAdcsCrashExperiments"],
        };
        if (adcsLocalContracts[slot.suite]) {
          const [modulePath, field] = adcsLocalContracts[slot.suite];
          const proof = artifact.report[field];
          require(modulePath).verifyProof(proof);
          if (proof.disposableForestRan !== false || proof.nativeExecutionQualified !== false || proof.hostCapabilityAbsentIsPass !== false) throw new Error("AD CS local contract stays unqualified without a disposable forest");
          if (slot.suite === "adcs-crash-experiments" && proof.releaseQualificationSatisfied !== false) throw new Error("AD CS crash experiments cannot satisfy release qualification");
        }
        const crossLocalContracts = {
          "acme-key-reuse-variants": ["../tests/e2e/helpers/certops-acme-key-reuse", "nativeAcmeKeyReuseVariants", "variants"],
          "dns-interruption": ["../tests/e2e/helpers/certops-dns-interruption", "nativeDnsInterruption"],
          "issuer-adoption-capacity": ["../tests/e2e/helpers/certops-issuer-adoption-capacity", "nativeIssuerAdoptionCapacity"],
          "linux-reboot-upgrade": ["../tests/e2e/helpers/certops-linux-reboot-upgrade", "nativeLinuxRebootUpgrade"],
          "fs-symlink-rollback": ["../tests/e2e/helpers/certops-fs-symlink-rollback", "nativeFsSymlinkRollback"],
          "trust-concurrency": ["../tests/e2e/helpers/certops-trust-concurrency", "nativeTrustConcurrency"],
          "k8s-rbac-outage": ["../tests/e2e/helpers/certops-k8s-rbac-outage", "nativeK8sRbacOutage"],
          "browser-audit-redaction": ["../tests/e2e/helpers/certops-browser-audit-redaction", "nativeBrowserAuditRedaction"],
        };
        if (crossLocalContracts[slot.suite]) {
          const [modulePath, field, exportName] = crossLocalContracts[slot.suite];
          const loaded = require(modulePath);
          const verifier = exportName ? loaded[exportName] : loaded;
          const proof = artifact.report[field];
          verifier.verifyProof(proof);
          if (proof.hostCapabilityAbsentIsPass !== false) throw new Error("Cross-platform local contract cannot pass on a missing host");
          if (slot.suite === "dns-interruption" && proof.liveDnsQualified !== false) throw new Error("Live DNS stays unqualified");
          if (slot.suite === "k8s-rbac-outage" && (proof.kubernetesQualified !== false || proof.talkedToCluster !== false)) throw new Error("Kubernetes coverage stays unqualified without a cluster");
          if (slot.suite === "issuer-adoption-capacity" && proof.nativeCell !== "pending") throw new Error("Issuer adoption stays pending");
          if (slot.suite === "linux-reboot-upgrade" && proof.realRebootQualified !== false) throw new Error("Linux reboot stays unqualified");
          if (slot.suite === "acme-key-reuse-variants" && (proof.nativeExecutionQualified !== false || proof.sharedFleetQualified !== false || proof.liveCertbot !== "pending")) throw new Error("ACME key reuse stays a local contract");
        }
        const windowsLocalContracts = {
          "windows-fixed-root-unmodified-contract": ["../tests/e2e/helpers/certops-windows-fixed-root", "unmodifiedFixedRoot", "verifyLocalContract"],
          "windows-full-installer-second-rename-contract": ["../tests/e2e/helpers/certops-windows-second-rename", "fullInstallerSecondRename", "verifyLocalContract"],
          "windows-published-package-upgrade-contract": ["../tests/e2e/helpers/certops-windows-published-upgrade", "publishedPackageUpgrade"],
          "windows-native-arm64-execution-contract": ["../tests/e2e/helpers/certops-windows-arm64-execution", "nativeArm64Execution"],
          "windows-acl-path-env-contract": ["../tests/e2e/helpers/certops-windows-acl-path-env", "aclPathEnvironment"],
          "windows-operation-interruption-contract": ["../tests/e2e/helpers/certops-windows-operation-interruption", "operationInterruption"],
          "windows-reregister-custody-contract": ["../tests/e2e/helpers/certops-windows-reregister-custody", "reregisterCustody"],
          "windows-retention-boundary-contract": ["../tests/e2e/helpers/certops-windows-retention-boundaries", "retentionBoundaries"],
          "windows-protected-recovery-contract": ["../tests/e2e/helpers/certops-windows-protected-recovery", "protectedKeyRecovery"],
          "windows-crash-dump-containment-contract": ["../tests/e2e/helpers/certops-windows-crash-dump", "crashDumpContainment"],
        };
        if (windowsLocalContracts[slot.suite]) {
          const [modulePath, field, exportName] = windowsLocalContracts[slot.suite];
          const loaded = require(modulePath);
          const proof = artifact.report[field];
          (exportName ? loaded[exportName] : loaded.verifyProof)(proof);
          if (proof.nativeExecutionQualified !== false || proof.hostCapabilityAbsentIsPass !== false || proof.powerLossDurabilityQualified === true || proof.realRebootQualified === true || proof.inUseKeyDeleted === true || proof.crashDumpContainmentQualified === true) throw new Error("Windows local contract stays unqualified");
          if (slot.suite === "windows-retention-boundary-contract" && proof.twentyFourHourElapsedQualified !== false) throw new Error("Retention elapsed qualification cannot be shortened");
          if (slot.suite === "windows-native-arm64-execution-contract" && proof.nativeArm64ExecutionQualified !== false) throw new Error("Native ARM64 execution stays unqualified");
          if (slot.suite === "windows-published-package-upgrade-contract" && proof.publishedPackageMigrationQualified !== false) throw new Error("Published package migration stays blocked");
        }
        if (slot.suite === "linux-trust-host") {
          const conflict=artifact.report.nativeTrustReceiptConflict;require("./certops-linux-trust-receipt-conflict").verifyProof(conflict);
          if(conflict.family!==artifact.report.nativeIndependentTrustRoots?.family)throw new Error("Native receipt conflict family differs from trust host");
          const h=require("./certops-linux-trust-independent-roots"),p=artifact.report.nativeIndependentTrustRoots,n=artifact.report.qualificationEnvironment;h.verifyProof(p);
          if(artifact.report.platform!=="linux" || artifact.report.architecture!=="x64" || n.osFamily!=="linux" || !((p.family==="debian" && n.distribution==="ubuntu" && ["22.04","24.04"].includes(n.osVersion) && n.executionSurface==="disposable-vm")||(p.family==="rhel" && n.distribution==="almalinux" && n.osVersion==="9.6" && n.executionSurface==="disposable-container")))throw new Error("Native independent trust platform required");
        }
        if (slot.suite === "filesystem-host") {
          require("./certops-filesystem-host").verifyRollbackProof(artifact.report.nativeFilesystemPairedRollback);
          require("./certops-filesystem-concurrent").verifyProof(artifact.report.nativeFilesystemConcurrency);
          require("./certops-filesystem-backup-alias").verifyProof(artifact.report.nativeFilesystemBackupAlias);
          require("./certops-filesystem-backup-retention").verifyProof(artifact.report.nativeFilesystemBackupRetention);
          if (artifact.report.nativeFilesystemBackupAlias.aliasKind !== (artifact.report.platform === "win32" ? "junction" : "symlink")) throw new Error("Native backup alias kind differs from host");
          const native = artifact.report.qualificationEnvironment;
          if (artifact.report.architecture !== "x64" || !((artifact.report.platform === "linux" && native.osFamily === "linux" && native.distributionId === "ubuntu" && ["22.04", "24.04"].includes(native.distributionVersion) && native.executionSurface === "host") || (artifact.report.platform === "win32" && native.osFamily === "windows" && ["2022", "2025"].includes(native.osVersion) && [2,3].includes(native.productType)))) throw new Error("Native filesystem concurrency environment required");
        }
        if (slot.suite === "filesystem-linux-backup-dac-host") {
          require("./certops-linux-filesystem-permission").verifyProof(artifact.report.nativeLinuxBackupDac);
          const native = artifact.report.qualificationEnvironment;
          if (artifact.report.platform !== "linux" || artifact.report.architecture !== "x64" || native.distributionId !== "ubuntu" || !["22.04", "24.04"].includes(native.distributionVersion) || native.executionSurface !== "disposable-vm") throw new Error("Native Ubuntu nonroot backup-DAC evidence required");
        }
        if (slot.suite === "linux-native-acme-browser-console") {
          require("../tests/e2e/helpers/certops-acme-browser-console").verifyProof(artifact.report.nativeAcmeBrowserConsole);
          const native = artifact.report.qualificationEnvironment;
          if (artifact.report.platform !== "linux" || artifact.report.architecture !== "x64" || native.osFamily !== "linux" || native.distributionId !== "ubuntu" || native.distributionVersion !== "24.04" || native.executionSurface !== "host" || native.libc !== "glibc") throw new Error("Native Ubuntu24 certbot browser console evidence required");
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
        if (["real-agent-acme-filesystem", "real-agent-acme-eab-filesystem", "real-agent-acmesh-filesystem", "real-agent-acmesh-eab-filesystem", "real-agent-alpine-acmesh"].includes(slot.suite)) {
          const native = entries.filter(entry => entry.name === "real ACME: agent discovers public files registers claims issues renews deploys and persists independently verified certificate evidence");
          if (native.length !== 1 || native[0].type !== "test:pass") throw new Error("Actual Linux ACME journey evidence missing");
          require("../tests/e2e/helpers/certops-acme-key-reuse").verifyProof(native[0].nativeAcmeKeyReuse);
          require("./certops-acme-stage-report").verifyForScope(native[0].nativeAcmeStageFaults,slot.suite);
          require("./certops-acme-background-report").verifyForScope(native[0].nativeAcmeBackgroundRenewals,native[0].nativeAcmeKeyReuse,slot.suite);
          if(slot.suite==='real-agent-acme-filesystem'){const bulk=require('./certops-acme-bulk-report');bulk.verifyForScope(native[0].nativeAcmeBulkRenewal,slot.suite,native[0].qualificationEnvironment);bulk.verifyCrossJourney(native[0].nativeAcmeBulkRenewal,native[0].nativeAcmeKeyReuse,native[0].nativeAcmeBackgroundRenewals);require("../tests/e2e/helpers/certops-acme-native-adoption").verifyAgainstBulk(native[0].nativeAcmeRenewalSetup,native[0].nativeAcmeBulkRenewal);require("../tests/e2e/helpers/certops-acme-certificate-outbox").verifyAgainstJourney(native[0].nativeAcmeCertificateOutbox,native[0].nativeAcmeBulkRenewal,native[0].nativeAcmeRenewalSetup);require("../tests/e2e/helpers/certops-acme-disabled-profile").verifyAgainstBulk(native[0].nativeAcmeDisabledProfile,native[0].nativeAcmeBulkRenewal);require("../tests/e2e/helpers/certops-acme-renewal-alert").verifyAgainstOutbox(native[0].nativeAcmeRenewalAlert,native[0].nativeAcmeCertificateOutbox);}
          if (native[0].nativeAcmeKeyReuse.client !== (slot.suite.includes("acmesh") ? "acme.sh" : "certbot")) throw new Error("ACME key reuse client scope mismatch");
        }
        if (slot.suite.startsWith("real-agent-windows-acme-iis/")) {
          const native = entries.filter(entry => entry.name === "real Windows: installed agent claims ACME CNG IIS deployment and persists independently verified certificate evidence");
          if (native.length !== 1 || native[0].type !== "test:pass") throw new Error("Actual Windows native journey evidence missing");
          require("../tests/e2e/helpers/certops-windows-public-issuance").verifyPublicIssuanceFacts(native[0].windowsPublicIssuance);
          require("../tests/e2e/helpers/certops-windows-installed-handoff").verifyProof(native[0].nativeInstalledStateHandoff);
          require("../tests/e2e/helpers/certops-windows-key-reuse-refusal").verifyProof(native[0].nativeWindowsKeyReuseRefusal);
          require("../tests/e2e/helpers/certops-windows-installed-iis-refusal").verifyProof(native[0].nativeInstalledIisRefusal);
          require("../tests/e2e/helpers/certops-windows-owned-process").verifyPublicProof(native[0].nativeInstalledCrash);
          require("../tests/e2e/helpers/certops-windows-installed-verify-rollback").verifyProof(native[0].nativeInstalledVerifyRollback);
          require("../tests/e2e/helpers/certops-windows-installed-paths").verifyProof(native[0].nativeInstalledPaths);
          require("../tests/e2e/helpers/certops-windows-multi-target-admission-refusal").verifyProof(native[0].nativeWindowsMultiTargetAdmission);
          require("../tests/e2e/helpers/certops-windows-active-service-controls").verifyProof(native[0].nativeInstalledActiveServiceControls);
          require("../tests/e2e/helpers/certops-windows-service-controls").verifyProof(native[0].nativeInstalledServiceControls);
          require("../tests/e2e/helpers/certops-windows-config-encoding").verifyProof(native[0].nativeInstalledConfigEncoding);
          require("../tests/e2e/helpers/certops-windows-public-retirement").verifyProof(native[0].nativeInstalledPublicRetirement);
          require("../tests/e2e/helpers/certops-windows-retention-config").verifyProof(native[0].nativeInstalledRetentionConfig);
          require("../tests/e2e/helpers/certops-windows-signing-pin-refusal").verifyProof(native[0].nativeInstalledSigningPinRefusal);
          require("../tests/e2e/helpers/certops-windows-credential-refusal").verifyProof(native[0].nativeInstalledCredentialRefusal);
          require("../tests/e2e/helpers/certops-windows-installed-weak-acl").verifyProof(native[0].nativeInstalledWeakCredentialAcl);
          require("../tests/e2e/helpers/certops-windows-source-junction").verifyProof(native[0].nativeInstalledSourceJunction);
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
