/**
 * Regression coverage: a complete mandatory matrix cannot promote incomplete feature specifications.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { verifyMatrix, validateMatrix } = require("./certops-release-qualification");
const { catalogCoverage, validateQualificationSummary } = require("./certops-release-qualification");
const contract = require("../docs/certops/qualification-suites.json");
const root = path.resolve(__dirname, "..");
function retentionReferenceProof(){const helper=require("../packages/agent/scripts/host/retention-reference-fixture");return {scope:"native-collector-supporting-ledger-reference-lifecycle",elapsed24HourQualified:false,...Object.fromEntries(helper.fields.map(field=>[field,true]))};}
const candidateSha = "a".repeat(40);
const source = "tests/e2e/certops-job-decisions-e2e.test.js";
const environment = { osFamily: "linux" };
function keyUsageProof() {
  const { CASES, CERTIFICATE_USAGE, SCOPE } = require("../packages/agent/scripts/host/cng-key-usage-proof");
  return { scope: SCOPE, copiedActualCsrExtensions: true, privateKeyUsageClaim: "signing-permitted-not-exact-default-ncrypt-mask", cases: CASES.map(caseId => ({ caseId, certificateUsageFlags: CERTIFICATE_USAGE[caseId.split("/")[0]], cngAllowedOperations: 0x00ffffff })) };
}
function localPairsProof(){const helper=require("../tests/e2e/helpers/certops-adcs-local-rules");return helper.pairCases.map(caseId=>({caseId,...Object.fromEntries(helper.pairFlags.map(flag=>[flag,true]))}));}
function browserAdcsProof() {
  const { FLAGS, SCOPE } = require("../tests/e2e/helpers/certops-adcs-browser-journey");
  const uuid = value => `${value.repeat(8)}-${value.repeat(4)}-4${value.repeat(3)}-8${value.repeat(3)}-${value.repeat(12)}`;
  return { ...Object.fromEntries(FLAGS.map(key => [key, true])), scope: SCOPE, lifecycle: "renew-existing-inventory-not-first-issue-or-manual-job", scheduler: "production-default-sweep-not-background-worker-loop", browserEngine: "chromium", browserMutationCount: 6, successfulEnrollments: 1,
    fingerprints: ["a", "b"].map(value => value.repeat(64)), spkiFingerprints: ["c", "d"].map(value => value.repeat(64)), requestId: "17", enrollmentId: uuid("a"), jobId: uuid("b"), profileId: uuid("c"), issuerId: uuid("d") };
}
function twoAdcsRenewalsProof() {
  const { FLAGS } = require("../tests/e2e/helpers/certops-adcs-two-renewals");
  return { scope: "two-native-adcs-default-scheduler-cycles-not-expiry-cleanup", renewalProtocol: "fresh-enrollment-with-new-key-and-csr", schedulerInvocation: "qualification-invoked-production-default-sweep", workerIntervalQualified: false,
    successfulAutomationCycles: 2, expiryCleanupQualified: false, ...Object.fromEntries(FLAGS.map(key => [key, true])), requestIds: ["17", "18", "19"], caRequestCounts: [7, 8, 9],
    fingerprints: ["a", "b", "c"].map(value => value.repeat(64)), spkiFingerprints: ["d", "e", "f"].map(value => value.repeat(64)), serialNumbers: ["a1", "b2", "c3"],
    containerNames: ["a", "b", "c"].map(value => `tokentimer-enr-${value.repeat(8)}-${value.repeat(4)}-4${value.repeat(3)}-8${value.repeat(3)}-${value.repeat(12)}`), expiryEpochs: [1792497600000, 1792497601000, 1792497602000] };
}
test("a complete mandatory matrix cannot promote incomplete feature specifications", () => {
  const catalog = { schemaVersion: 1, scenarios: [{ id: "fixture.not-yet-covered", outcome: "Still requires native qualification", status: "planned", evidenceLevel: "unassigned", requiredEnvironments: [], implementation: null }] };
  const coverage = catalogCoverage(catalog);
  assert.equal(coverage.total, 1); assert.equal(coverage.planned, 1); assert.equal(coverage.implementationStatus, "incomplete");
  const summary = { qualificationScope: "committed-mandatory-matrix", allFeaturesQualified: false, catalogCoverage: coverage };
  assert.deepEqual(validateQualificationSummary(summary, catalog), []);
  assert.ok(validateQualificationSummary({ ...summary, allFeaturesQualified: true }, catalog).length);
  assert.ok(validateQualificationSummary({ ...summary, qualificationScope: "all-features" }, catalog).length);
  assert.ok(validateQualificationSummary({ ...summary, catalogCoverage: { ...coverage, implementationStatus: "all-specifications-implemented" } }, catalog).length);
});
const specification = { schemaVersion: 1, slots: [{ id: "fixture", kind: "host", suite: "job-decisions-api", source, environment }] };

test("cheap matrix validation refuses growth beyond the reviewed collection ceiling", () => {
  const committed = require("../docs/certops/release-qualification-matrix.json");
  const slots = [...committed.slots];
  while (slots.length < 512) slots.push({ ...committed.slots[0], id: `collection-boundary-${slots.length}`, environment: { ...committed.slots[0].environment, fixtureIndex: slots.length } });
  assert.deepEqual(validateMatrix({ ...committed, slots }), []);
  assert.match(validateMatrix({ ...committed, slots: [...slots, { ...slots[0], id: "over-budget" }] }).join("\n"), /512-slot collection policy/);
});
test("dedicated elapsed-pending release slot requires actual-hour evidence", () => {
  const suite = "enterprise-adcs-elapsed-pending-real";
  const slot = require("../docs/certops/release-qualification-matrix.json").slots.find(row => row.suite === suite);
  const report = { ...artifact().report, suite, evidenceLevel: "real-host",
    startedAt: "2026-10-14T12:00:00.000Z", finishedAt: "2026-10-14T13:00:01.000Z",
    qualificationEnvironment: { ...slot.environment, measurement: "native" },
    requiredScenarios: contract.suites[suite], requiredCapabilities: contract.requiredCapabilities[suite],
    capabilities: Object.fromEntries(contract.requiredCapabilities[suite].map(name => [name, { available: true }])),
    fixtureSource: { file: slot.source, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, slot.source))).digest("hex") },
    fixtureSources: slot.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") })) };
  report.scenarios = contract.suites[suite].map(id => ({ id, status: "passed", evidenceLevel: "real-host", startedAt: report.startedAt, finishedAt: report.finishedAt }));
  const item = { kind: "host", suite, environment: report.qualificationEnvironment, report };
  const spec = { schemaVersion: 1, slots: [slot] };
  assert.ok(verifyMatrix([item], { candidateSha, specification: spec }).length);
  report.nativePendingElapsed = { pendingTimeoutSeconds: 3600, pollIntervalSeconds: 60,
    monotonicWaitSeconds: 3601, databaseElapsedSeconds: 3601, clocks: "actual-host-and-database",
    schedulerClock: "default-real-now", databaseDatesRewritten: false, journalRewritten: false,
    qualificationScope: "configured-one-hour-not-default-fourteen-days", pendingSince: report.startedAt,
    requestId: "17", snapshotSha256: "a".repeat(64) };
  for (const field of ["snapshotAndCsrStableAcrossRestart", "keyProtectedBeforeDeadline", "signedTerminalCleanup", "exactKeyAbsent", "noCertificateAccepted", "noCaResubmission", "lateApprovalTerminalRefusal", "lateIssuedCertificateRevoked", "outgoingTrustedTlsUnchanged"]) report.nativePendingElapsed[field] = true;
  assert.deepEqual(verifyMatrix([item], { candidateSha, specification: spec }), []);
  report.primaryNativePreflightDispatchCount = 18;
  assert.deepEqual(verifyMatrix([item], { candidateSha, specification: spec }), []);
  for (const count of [19, 20, true, "18"]) {
    const invalid = structuredClone(item); invalid.report.primaryNativePreflightDispatchCount = count; invalid.report.nativeBrowserAdcs = browserAdcsProof();
    assert.ok(verifyMatrix([invalid], { candidateSha, specification: spec }).length);
  }
  report.nativePendingElapsed.monotonicWaitSeconds = 3599;
  assert.ok(verifyMatrix([item], { candidateSha, specification: spec }).length);
});
function artifact() {
  const suite = "job-decisions-api";
  const now = new Date().toISOString();
  const report = { schemaVersion: 1, suite, candidateSha, startedAt: now, finishedAt: now, status: "passed", strict: true, evidenceLevel: "integration", requiredCapabilities: contract.requiredCapabilities[suite], capabilities: { api: { available: true }, postgres: { available: true } }, requiredScenarios: contract.suites[suite], missingCapabilities: [], missingScenarios: [], scenarios: contract.suites[suite].map((id) => ({ id, status: "passed", evidenceLevel: "integration", startedAt: now, finishedAt: now })), qualificationEnvironment: { ...environment, measurement: "native" }, artifactQualification: "workflow-checkout-source", fixtureSource: { file: source, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, source))).digest("hex") } };
  return { kind: "host", suite, environment: report.qualificationEnvironment, report };
}
test("explicit matrix candidate survives a different collector workflow SHA", () => {
  const previous = process.env.GITHUB_SHA;
  try {
    process.env.GITHUB_SHA = "e".repeat(40);
    assert.deepEqual(verifyMatrix([artifact()], { candidateSha, specification }), []);
    assert.ok(verifyMatrix([artifact()], { candidateSha: "b".repeat(40), specification }).length);
  } finally {
    if (previous === undefined) delete process.env.GITHUB_SHA;
    else process.env.GITHUB_SHA = previous;
  }
});
function suiteArtifact(suite, file, fields) {
  const value = artifact(); value.suite = suite;
  Object.assign(value.report, { suite, evidenceLevel: contract.suiteEvidenceLevels[suite], requiredCapabilities: contract.requiredCapabilities[suite], capabilities: Object.fromEntries(contract.requiredCapabilities[suite].map(name => [name, { available: true }])), requiredScenarios: contract.suites[suite], scenarios: contract.suites[suite].map(id => ({ ...value.report.scenarios[0], id, evidenceLevel: contract.scenarioEvidenceLevels[suite][id] })), fixtureSource: { file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }, ...fields });
  return value;
}

test("Windows two-cycle evidence requires both native generations and refuses expiry cleanup promotion", () => {
  const suite = "windows-two-unattended-renewals", helper = require("../tests/e2e/helpers/certops-windows-two-renewals");
  const slots = require("../docs/certops/release-qualification-matrix.json").slots.filter(item => item.suite === suite);
  assert.equal(slots.length, 10);
  const fields = ["automaticSourceAndRealMode", "naturallyDueGenerations", "distinctIdempotencyKeys", "leafAndSpkiChangedTwice", "nativeBindingMatchesLatest", "nativeKeyProfilesVerified", "persistedEvidenceBothCycles", "inventoryMatchesActualLeaf", "profileAndManagementLineagePreserved", "retentionLineageMatchesBothCutovers", "predecessorCustodyPreserved", "noExpiryOrClockOverrides"];
  const proof = { ...Object.fromEntries(fields.map(field => [field, true])), successfulAutomationCycles: 2, expiryCleanupQualified: false, scope: "two-unattended-cycles-and-preserved-predecessors-not-expiry-cleanup" };
  for (const slot of slots) {
    assert.deepEqual(slot.requiredSources, helper.requiredSources);
    const value = suiteArtifact(suite, slot.source, { nativeTwoRenewals: proof });
    value.environment = value.report.qualificationEnvironment = { ...slot.environment, measurement: "native" };
    value.report.fixtureSources = slot.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
    const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
    assert.deepEqual(verifyMatrix([value], options), []);
    for (const field of fields) { const invalid = structuredClone(value); invalid.report.nativeTwoRenewals[field] = false; assert.ok(verifyMatrix([invalid], options).length, field); }
    for (const change of [{ successfulAutomationCycles: 1 }, { expiryCleanupQualified: true }, { scope: "complete-cleanup" }]) { const invalid = structuredClone(value); Object.assign(invalid.report.nativeTwoRenewals, change); assert.ok(verifyMatrix([invalid], options).length); }
    const missing = structuredClone(value); delete missing.report.nativeTwoRenewals; assert.ok(verifyMatrix([missing], options).length);
    const stale = structuredClone(value); stale.report.fixtureSources[0].sha256 = "0".repeat(64); assert.ok(verifyMatrix([stale], options).length);
  }
});

test("Windows certificate dry-run requires native observations in every server and key-profile cell", () => {
  const helper = require("../tests/e2e/helpers/certops-windows-certificate-dry-run");
  const slots = require("../docs/certops/release-qualification-matrix.json").slots.filter(slot => slot.suite === helper.suite);
  assert.equal(slots.length, 10);
  const proof = { scope: helper.scope, admission: "production-service-explicit-mode", deployPlanSteps: 3, renewPlanSteps: 6, ...Object.fromEntries(helper.fields.map(field => [field, true])) };
  for (const slot of slots) {
    assert.deepEqual(slot.requiredSources, helper.requiredSources);
    const value = suiteArtifact(helper.suite, slot.source, { nativeCertificateDryRun: proof });
    value.environment = value.report.qualificationEnvironment = { ...slot.environment, measurement: "native" };
    value.report.fixtureSources = slot.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
    const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
    assert.deepEqual(verifyMatrix([value], options), []);
    for (const field of Object.keys(proof)) { const invalid = structuredClone(value); delete invalid.report.nativeCertificateDryRun[field]; assert.ok(verifyMatrix([invalid], options).length, field); }
    const stale = structuredClone(value); stale.report.fixtureSources[0].sha256 = "0".repeat(64); assert.ok(verifyMatrix([stale], options).length);
  }
});

test("browser audit requires all six executions and current UI/API source evidence", () => {
  const suite = "browser-certificate-audit", slot = require("../docs/certops/release-qualification-matrix.json").slots.find(item => item.suite === suite);
  const value = suiteArtifact(suite, slot.source, {});
  value.environment = value.report.qualificationEnvironment = { ...slot.environment, measurement: "native" };
  value.report.fixtureSources = slot.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
  assert.deepEqual(verifyMatrix([value], options), []);
  for (const mutate of [report => report.scenarios.pop(), report => { report.scenarios[0].status = "skipped"; }, report => { report.fixtureSources = []; }, report => { report.fixtureSources.find(source => source.file.endsWith("Audit.jsx")).sha256 = "0".repeat(64); }, report => { report.artifactQualification = "local-worktree-source-baseline-sha-only"; }]) {
    const invalid = structuredClone(value); mutate(invalid.report); assert.ok(verifyMatrix([invalid], options).length);
  }
});
test("systemd reapplication and real-elapsed worker facts cannot be omitted or weakened", () => {
  const cases = [
    ["linux-systemd-published-upgrade", {nativePublishedLinuxUpgrade:{baselineVersion:"0.17.2",publishedAssetId:612562598,publishedArchiveSha256:"c602fe36825c74d423c2c9b89680df3b1ac76542f71804de14dc5e2ec5aa85bf",publishedArchiveSize:410054,candidateVersion:require("../packages/agent/package.json").version,candidateArchiveSha256:"a".repeat(64),publishedFilesVerified:true,baselineJobExecuted:true,candidateFilesVerified:true,configBytesPreserved:true,credentialBytesPreserved:true,sameRegistration:true,bootstrapUnconsumed:true,freshHeartbeat:true,candidateJobExecuted:true,oldJobHistoryUnchanged:true,oldReplayEntryPreserved:true,privatePermissionsPreserved:true,originalConfigRestored:true,beforePid:100,afterPid:101,rollbackClaimed:false}},value=>{value.report.nativePublishedLinuxUpgrade.publishedAssetId=1;}],
    ["linux-systemd-reapply", { nativeInstallerReapply: { installation: "same-candidate-reapplication", operatorConfigBytesPreserved: true, credentialBytesPreserved: true, candidatePackageInstalled: true, dropinPreserved: true, privatePermissionsPreserved: true, sameRegistration: true, spareBootstrapUnconsumed: true, bootstrapFileAbsent: true, bootstrapAbsentAfterFreshRestart: true, freshAuthenticatedHeartbeat: true, originalConfigRestored: true, beforePid: 100, reappliedPid: 101, freshRestartPid: 102, nativeUid: 1001 } }, value => { value.report.nativeInstallerReapply.reappliedPid = 100; }],
    ["agent-log-maintenance-worker", { maintenance: { defaultGraceMs: 300000, observedMonotonicMs: 300100, actualDatabaseExpired: true, originalJobSucceeded: true, lateUploadRefused: true, tombstoneRetained: true, onlySelectedWorkerSweeps: true, timestampsRewritten: false, abandonedStreams: 1, purgedLines: 2, repeatedPurgeDeleted: 0, retentionDays: 0, scope: "actual-default-five-minute-grace-and-supported-retention-zero" } }, value => { value.report.maintenance.observedMonotonicMs = 299999; }],
  ];
  for (const [suite, facts, mutate] of cases) {
    const slot = require("../docs/certops/release-qualification-matrix.json").slots.find(item => item.suite === suite);
    const value = suiteArtifact(suite, slot.source, facts);
    value.environment = value.report.qualificationEnvironment = { ...slot.environment, measurement: "native" };
    value.report.fixtureSources = slot.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
    const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
    assert.deepEqual(verifyMatrix([value], options), []);
    mutate(value); assert.ok(verifyMatrix([value], options).length);
  }
});
test("Windows child-output proof requires native profile identity bounded facts and current sources", () => {
  const suite = "windows-native-child-output-privacy";
  const slot = require("../docs/certops/release-qualification-matrix.json").slots.find(item => item.suite === suite);
  const fields = { actualNativeIdentity: "LocalSystem", actualStdoutAndStderrEmission: true, actualDelegatedSuccess: true, actualAcmeSuccessLogObserved: true, actualHttpUploadsSecretFree: true, persistedLogsEvidenceResultsSecretFree: true, scmConsoleSecretFree: true, childOutputPolicy: "captured-and-withheld-not-live-forwarded", nativeCertificateOutcome: "parent-independent-CNG-IIS-trusted-TLS", receiptCount: 1, jobLogCount: 1, evidenceCount: 1, httpUploadCount: 1 };
  const value = suiteArtifact(suite, slot.source, fields);
  value.environment = value.report.qualificationEnvironment = { ...slot.environment, measurement: "native", build: "20348", keyAlgorithm: "rsa", keySize: 2048 };
  value.report.fixtureSources = slot.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
  assert.deepEqual(verifyMatrix([value], options), []);
  for (const mutate of [item => { item.report.receiptCount = 33; }, item => { item.report.actualHttpUploadsSecretFree = false; }, item => { item.report.qualificationEnvironment.keySize = 4096; }, item => { item.report.fixtureSources.pop(); }]) {
    const invalid = structuredClone(value); mutate(invalid); assert.ok(verifyMatrix([invalid], options).length);
  }
});

test("native Kubernetes compaction needs actual expired cursor and newer observed revision", () => {
  const suite = "kubernetes-host", file = "scripts/certops-kubernetes-host.js";
  const value = suiteArtifact(suite, file, { nativeCompaction: { expiredStatus: 410, originalResourceVersion: "10", compactedRevision: "20", observedResourceVersion: "21", certificateUid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", productionClient: true, productionObserver: true, controlPlaneRestarted: true, ownedSingleNodeCluster: true } });
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [{ id: "compaction", kind: "host", suite, source: file, environment }] } };
  assert.deepEqual(verifyMatrix([value], options), []);
  for (const mutate of [item => { delete item.report.nativeCompaction; }, item => { item.report.nativeCompaction.expiredStatus = 200; }, item => { item.report.nativeCompaction.productionObserver = false; }, item => { item.report.nativeCompaction.observedResourceVersion = "20"; }, item => { item.report.nativeCompaction.originalResourceVersion = "30"; }, item => { item.report.nativeCompaction.certificateUid = "-".repeat(36); }]) {
    const invalid = structuredClone(value); mutate(invalid); assert.ok(verifyMatrix([invalid], options).length);
  }
});

test("native console fault evidence requires exact persisted gap and unchanged job outcome", () => {
  const suite = "native-agent-api", file = "tests/e2e/certops-native-agent-e2e.test.js";
  const nativeDispatchTiming = {fixtureLifetimeSeconds:2,localToleranceMs:1,heldMonotonicMs:5001,originalDispatchLifetimeSeconds:3600,issuedAt:"2026-10-14T12:00:00.000Z",expiresAt:"2026-10-14T12:00:02.000Z",releasedAt:"2026-10-14T12:00:05.001Z",clocks:"actual-host-monotonic-and-database",fixture:"production-signer-short-lifetime-and-delayed-HTTP-delivery",databaseDatesRewritten:false,journalRewritten:false,nativeClockRefusalObserved:true,executionSuccessAbsent:true,nonceUnconsumed:true,freshClaimRecoverySucceeded:true,credentialAndPinUnchanged:true,leaseCallsBeforeRefusal:0,expiredNonceResultStatus:409,expiredNonceResultCode:"CERTOPS_AGENT_RESULT_NONCE_REJECTED",actualServerJobState:"claimed",actualRejectedOutbox:"dead-letter",qualificationScope:"native-Linux-shortened-dispatch-fixture-not-stock-TTL-or-Windows-SCM"};
  const value = suiteArtifact(suite, file, { nativeDispatchTiming, nativeChildOutputPrivacy: { executedChildren: 2, stdoutEmitted: true, stderrEmitted: true, rawChildOutputWithheld: true, genericExecutionMarkerPersisted: true, jobSucceeded: true }, nativeLogFaults: contract.suites[suite].filter(id => id.startsWith("native-agent-log-")).map(scenario => ({ scenario, actualNativeConsole: true, jobSucceeded: true, attempts: 1, persistedLines: 3, agentGapLines: scenario === "native-agent-log-413-drop-accounting" ? 1 : 0, serverDroppedLines: 0, finalAcknowledged: true })) });
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [{ id: "native-console", kind: "host", suite, source: file, environment }] } };
  const dryRun = require("../tests/e2e/helpers/certops-native-certificate-dry-run");
  value.report.nativeCertificateDryRun = { scope: dryRun.scope, admission: "production-service-explicit-mode", dryRunOperations: 2, deployPlanSteps: 3, renewPlanSteps: 6, validateCalls: 1, reloadCalls: 1, caSentinelCalls: 1, dnsSentinelCalls: 1, ...Object.fromEntries(dryRun.trueFields.map(field => [field, true])) };
  assert.deepEqual(verifyMatrix([value], options), []);
  for (const field of Object.keys(value.report.nativeCertificateDryRun)) {
    const invalid = structuredClone(value); delete invalid.report.nativeCertificateDryRun[field];
    assert.ok(verifyMatrix([invalid], options).length, `Missing certificate dry-run proof: ${field}`);
  }
  for (const mutate of [item => { delete item.report.nativeCertificateDryRun; }, item => { item.report.nativeCertificateDryRun.caSentinelCalls = 0; }, item => { item.report.nativeCertificateDryRun.scope = "real-acme-qualified"; }, item => { item.report.nativeCertificateDryRun.servedLeafUnchangedDuringDryRun = false; }]) {
    const invalid = structuredClone(value); mutate(invalid); assert.ok(verifyMatrix([invalid], options).length);
  }
  for (const mutate of [item => { item.report.nativeDispatchTiming.heldMonotonicMs = 0; }, item => { item.report.nativeDispatchTiming.nonceUnconsumed = false; }, item => { item.report.nativeDispatchTiming.expiredNonceResultStatus = 200; }, item => { delete item.report.nativeChildOutputPrivacy; }, item => { item.report.nativeChildOutputPrivacy.rawChildOutputWithheld = false; }, item => { item.report.nativeLogFaults.pop(); }, item => { item.report.nativeLogFaults[0].jobSucceeded = false; }, item => { item.report.nativeLogFaults[0].agentGapLines = 1; }, item => { item.report.nativeLogFaults[0].attempts = 2; }]) {
    const invalid = structuredClone(value); mutate(invalid); assert.ok(verifyMatrix([invalid], options).length);
  }
});
test("release matrix accepts complete source-bound evidence, rejects missing and repeated environments", () => {
  const options = { candidateSha, specification };
  assert.deepEqual(verifyMatrix([artifact()], options), []);
  assert.ok(verifyMatrix([], options).length);
  assert.ok(verifyMatrix([artifact(), artifact()], options).length);
  assert.ok(verifyMatrix([artifact()], { specification }).length);
});

test("native ADCS cohort dispatch budgets cannot be omitted duplicated or exceeded", () => {
  const suite = "enterprise-adcs-real", file = "tests/e2e/certops-adcs-real-e2e.test.js";
  const value = artifact(); value.suite = suite; Object.assign(value.report, {
    suite, evidenceLevel: "real-host", requiredCapabilities: contract.requiredCapabilities[suite],
    capabilities: Object.fromEntries(contract.requiredCapabilities[suite].map(name => [name, { available: true }])),
    requiredScenarios: contract.suites[suite], scenarios: contract.suites[suite].map(id => ({ ...value.report.scenarios[0], id, evidenceLevel: "real-host" })),
    fixtureSource: { file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") },
    nativeIssuedCancellation: { requestId: "17", snapshotSha256: "a".repeat(64), pollIntervalSeconds: 900, schedulerClock: "default-real-now", actualCaIssuedBeforeCancel: true, caLeafSignatureAndCsrSpkiVerified: true, controlPlaneStillPendingBeforeCancel: true, nonExportableKeyPresentBeforeCancel: true, signedTerminalCleanupSucceeded: true, exactUnacceptedKeyAbsent: true, certificateNeverAccepted: true, sameRequestSnapshotAndCsrPreserved: true, noAdditionalCaRequest: true, outgoingTrustedTlsUnchanged: true, terminalReconcileRefused: true, unusedIssuedLeafRevoked: true, databaseDatesRewritten: false, journalRewritten: false },
    nativeAdcsTwoRenewals: twoAdcsRenewalsProof(),
    nativeLocalRulePairs: localPairsProof(),
    nativeBrowserAdcs: browserAdcsProof(),
    browserNativePreflightDispatch: { count: 2, jobIds: ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"] },
    nativeUncertainAbandon: { leaseRemainingAtFaultMs: 60000, recoveryWaitBudgetMs: 150000, actualLeaseWaitMs: 61000, scope: "native-zero-request-uncertain-abandon", resolvedIssuingCaAddress: "10.64.0.4", ownedObserverDrained: true, ownedTransportBlock: true, observedSubmittingTermination: true, actualLeaseExpiry: true, acknowledgedPublicRecovery: true, sameCsrAndKey: true, noAutomaticResubmit: true, publicAbandonAudited: true, unacceptedKeyRemoved: true, originalOrphanPreserved: true, recoveryPolicyUnchanged: true, caRequestsAtFault: 0, caRequestsAfterRecovery: 0, caRequestsAfterAbandon: 0 },
    nativeValidationExpiry: { configuredTimeoutSeconds: 300, defaultTimeoutSeconds: 86400, storedWindowSeconds: 299, monotonicObservedWaitSeconds: 301, actualDeadline: new Date().toISOString(), requestId: "17", snapshotSha256: "a".repeat(64), actualNativeRevocationUnknown: true, actualSignedContinuationExpired: true, persistedDeadlineSurvivedRestartAndPolicyRestoration: true, exactUnacceptedKeyFreed: true, noCertificateAccepted: true, noCaResubmission: true, outgoingTrustedTlsPreserved: true, chainCacheValueRestored: true, nativeAndCaClocks: "actual", qualificationScope: "configured-five-minute-window-not-default-24-hour-elapsed" },
    primaryNativePreflightDispatchCount: 20,
    nativePreflightCohorts: [{ workspaceId: "a".repeat(36), agentId: "b".repeat(36), dispatchCount: 18, dispatchLimit: 18, nativeIdentity: "LocalSystem", runtime: "candidate-cli" }],
    nativeTemplateMutations: contract.suites[suite].filter(id => id.startsWith("adcs-real-mutated-template-")).map(id => ({ caseId: id.slice("adcs-real-mutated-template-".length, -"-native-refused".length), template: "TTQualificationRSAShort", preflightVerdict: "unsafe", originalConfirmedIssuerReused: true, actualSignedJobRefused: true, noCaRequestAllocated: true, noKeyGenerated: true, outgoingTrustedTlsPreserved: true })),
  });
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [{ id: "cohort", kind: "host", suite, source: file, environment }] } };
  assert.deepEqual(verifyMatrix([value], options), []);
  const hierarchy = structuredClone(value), hierarchyOptions = structuredClone(options), hierarchySuite = "enterprise-adcs-hierarchy-real";
  hierarchy.suite = hierarchy.report.suite = hierarchyOptions.specification.slots[0].suite = hierarchySuite;
  hierarchy.report.requiredScenarios = contract.suites[hierarchySuite]; hierarchy.report.scenarios = contract.suites[hierarchySuite].map(id => ({ ...value.report.scenarios[0], id }));
  assert.deepEqual(verifyMatrix([hierarchy], hierarchyOptions), []);
  const missingHierarchyBrowser = structuredClone(hierarchy); delete missingHierarchyBrowser.report.nativeBrowserAdcs; assert.ok(verifyMatrix([missingHierarchyBrowser], hierarchyOptions).length);
  for (const [key, prior] of Object.entries(value.report.nativeBrowserAdcs)) {
    const missing = structuredClone(value); delete missing.report.nativeBrowserAdcs[key]; assert.ok(verifyMatrix([missing], options).length, key);
    const changed = structuredClone(value); changed.report.nativeBrowserAdcs[key] = Array.isArray(prior) ? [prior[0], prior[0]] : typeof prior === "boolean" ? false : typeof prior === "number" ? prior + 1 : "unqualified";
    assert.ok(verifyMatrix([changed], options).length, key);
  }
  for (const count of [2, 18, 19, 20]) { const good = structuredClone(value); good.report.primaryNativePreflightDispatchCount = count; assert.deepEqual(verifyMatrix([good], options), []); }
  for (const mutate of [item => { delete item.report.nativeBrowserAdcs; }, item => { delete item.report.browserNativePreflightDispatch; }, item => { item.report.browserNativePreflightDispatch.count = 3; }, item => { item.report.browserNativePreflightDispatch.count = true; }, item => { item.report.browserNativePreflightDispatch.jobIds.pop(); }, item => { item.report.browserNativePreflightDispatch.jobIds[1] = item.report.browserNativePreflightDispatch.jobIds[0]; }, item => { item.report.browserNativePreflightDispatch.jobIds = ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"]; }, item => { item.report.browserNativePreflightDispatch.jobIds[0] = "invalid"; }, item => { item.report.primaryNativePreflightDispatchCount = 1; }, item => { item.report.primaryNativePreflightDispatchCount = 21; }, item => { item.report.nativeBrowserAdcs.requestId = "4294967296"; }, item => { item.report.nativeBrowserAdcs.scheduler = "continuous-worker-qualified"; }, item => { item.report.nativeBrowserAdcs.privateKey = "unexpected"; }]) {
    const invalid = structuredClone(value); mutate(invalid); assert.ok(verifyMatrix([invalid], options).length);
  }
  for(const flag of require("../tests/e2e/helpers/certops-adcs-local-rules").pairFlags){
    for(const wrong of [false,1,null,"true"]){const bad=structuredClone(value);bad.report.nativeLocalRulePairs[0][flag]=wrong;assert.ok(verifyMatrix([bad],options).length,flag);}
    const missing=structuredClone(value);delete missing.report.nativeLocalRulePairs[0][flag];assert.ok(verifyMatrix([missing],options).length,flag);
  }
  for(const rows of [undefined,[],[localPairsProof()[0],localPairsProof()[0],localPairsProof()[2]],localPairsProof().map(row=>({...row,rawKey:"private"}))]){const bad=structuredClone(value);bad.report.nativeLocalRulePairs=rows;assert.ok(verifyMatrix([bad],options).length);}
  for (const [key, prior] of Object.entries(value.report.nativeAdcsTwoRenewals)) {
    const missing = structuredClone(value); delete missing.report.nativeAdcsTwoRenewals[key]; assert.ok(verifyMatrix([missing], options).length, key);
    const changed = structuredClone(value); changed.report.nativeAdcsTwoRenewals[key] = Array.isArray(prior) ? [...prior, prior[0]] : typeof prior === "boolean" ? !prior : typeof prior === "number" ? 1 : "unqualified";
    assert.ok(verifyMatrix([changed], options).length, key);
  }
  for (const key of ["requestIds", "fingerprints", "spkiFingerprints", "serialNumbers", "containerNames", "expiryEpochs"]) {
    const duplicate = structuredClone(value); duplicate.report.nativeAdcsTwoRenewals[key][2] = duplicate.report.nativeAdcsTwoRenewals[key][1];
    assert.ok(verifyMatrix([duplicate], options).length, key);
  }
  for (const change of [{ requestIds: ["17", "18", "4294967296"] }, { caRequestCounts: [999, 1000, 1001] }, { caRequestCounts: [7, 8, 10] }, { caRequestCounts: [true, 2, 3] }, { expiryEpochs: [1, 2, Number.MAX_SAFE_INTEGER + 1] }, { workerIntervalQualified: true }, { expiryCleanupQualified: true }, { schedulerInvocation: "background-worker-interval-qualified" }, { privateKey: "unexpected field" }]) {
    const invalid = structuredClone(value); Object.assign(invalid.report.nativeAdcsTwoRenewals, change); assert.ok(verifyMatrix([invalid], options).length);
  }
  for (const key of Object.keys(value.report.nativeUncertainAbandon)) {
    const invalid = structuredClone(value); delete invalid.report.nativeUncertainAbandon[key];
    assert.ok(verifyMatrix([invalid], options).length, key);
    const changed = structuredClone(value); const prior = changed.report.nativeUncertainAbandon[key];
    changed.report.nativeUncertainAbandon[key] = typeof prior === "boolean" ? false : typeof prior === "number" ? 1 : "unqualified";
    assert.ok(verifyMatrix([changed], options).length, key);
  }
  const requiredSources = [...new Set([...require("../tests/e2e/helpers/certops-adcs-uncertain-abandon").REQUIRED_SOURCES, ...require("../tests/e2e/helpers/certops-adcs-two-renewals").REQUIRED_SOURCES, ...require("../tests/e2e/helpers/certops-adcs-browser-journey").REQUIRED_SOURCES])];
  const sourceOptions = structuredClone(options); sourceOptions.specification.slots[0].requiredSources = requiredSources;
  const sourced = structuredClone(value); sourced.report.fixtureSources = requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
  assert.deepEqual(verifyMatrix([sourced], sourceOptions), []);
  for (const file of requiredSources) {
    const missing = structuredClone(sourced); missing.report.fixtureSources = missing.report.fixtureSources.filter(row => row.file !== file);
    assert.ok(verifyMatrix([missing], sourceOptions).length, file);
    const stale = structuredClone(sourced); stale.report.fixtureSources.find(row => row.file === file).sha256 = "0".repeat(64);
    assert.ok(verifyMatrix([stale], sourceOptions).length, file);
  }
  for (const mutate of [item => { item.report.nativeIssuedCancellation.unusedIssuedLeafRevoked = false; }, item => { item.report.nativeIssuedCancellation.certificateNeverAccepted = false; }, item => { delete item.report.nativePreflightCohorts; }, item => { item.report.primaryNativePreflightDispatchCount = 21; }, item => { item.report.nativePreflightCohorts[0].dispatchCount = 19; }, item => { item.report.nativePreflightCohorts.push(item.report.nativePreflightCohorts[0]); }, item => { item.report.nativePreflightCohorts[0].runtime = "mock"; }]) {
    const invalid = structuredClone(value); mutate(invalid); assert.ok(verifyMatrix([invalid], options).length);
  }
  for (const mutate of [item => { item.report.nativeValidationExpiry.monotonicObservedWaitSeconds = 299; }, item => { item.report.nativeValidationExpiry.exactUnacceptedKeyFreed = false; }, item => { item.report.nativeValidationExpiry.qualificationScope = "default-24-hour-elapsed"; }, item => { item.report.nativeTemplateMutations.pop(); }, item => { item.report.nativeTemplateMutations[0].noKeyGenerated = false; }, item => { item.report.nativeTemplateMutations[0].preflightVerdict = "safe"; }]) {
    const invalid = structuredClone(value); mutate(invalid); assert.ok(verifyMatrix([invalid], options).length);
  }
});
test("release matrix rejects mislabeled hosts, stale source, local evidence, skips and candidate mismatch", () => {
  const options = { candidateSha, specification };
  for (const mutate of [
    (value) => { value.report.candidateSha = "b".repeat(40); },
    (value) => { value.report.fixtureSource.sha256 = "0".repeat(64); },
    (value) => { value.report.qualificationEnvironment.osFamily = "windows"; },
    (value) => { value.report.qualificationEnvironment.measurement = "selected-input"; },
    (value) => { value.report.artifactQualification = "local-worktree-source-baseline-sha-only"; },
    (value) => { value.report.qualificationStatus = "not-qualified"; },
    (value) => { value.report.scenarios[0].status = "skipped"; },
    (value) => { value.report.requiredCapabilities = []; value.report.capabilities = {}; },
  ]) { const value = artifact(); mutate(value); assert.ok(verifyMatrix([value], options).length); }
});
test("release matrix refuses duplicate specifications and malformed artifact collections", () => {
  assert.ok(verifyMatrix(null, { candidateSha, specification }).length);
  assert.ok(verifyMatrix([artifact()], { candidateSha, specification: { ...specification, slots: [specification.slots[0], specification.slots[0]] } }).length);
  assert.ok(verifyMatrix([], { candidateSha, specification: { schemaVersion: 1, slots: [] } }).length);
});
test("supporting helper sources require unique current fingerprints", () => {
  const files = ["tests/e2e/helpers/certops-windows-reregistration.js", "tests/e2e/helpers/certops-windows-capability-refresh.js"];
  const specificationWithHelpers = { ...specification, slots: [{ ...specification.slots[0], requiredSources: files }] };
  const value = artifact();
  value.report.fixtureSources = files.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
  assert.deepEqual(verifyMatrix([value], { candidateSha, specification: specificationWithHelpers }), []);
  for (const mutate of [
    report => { delete report.fixtureSources; },
    report => { report.fixtureSources.pop(); },
    report => { report.fixtureSources[0].sha256 = "0".repeat(64); },
    report => { report.fixtureSources.push(report.fixtureSources[0]); },
  ]) {
    const copy = structuredClone(value); mutate(copy.report);
    assert.ok(verifyMatrix([copy], { candidateSha, specification: specificationWithHelpers }).length);
  }
  assert.ok(validateMatrix({ ...specification, slots: [{ ...specification.slots[0], requiredSources: ["../outside.js"] }] }).some(error => error.includes("supporting source")));
});
test("committed release matrix covers all mandatory suites and rejects escaped sources", () => {
  assert.deepEqual(validateMatrix(), []);
  assert.ok(validateMatrix({ schemaVersion: 1, slots: [{ ...specification.slots[0], source: "../outside.js" }] }).some((error) => error.includes("inside")));
  assert.ok(validateMatrix({ schemaVersion: 1, slots: [] }).length);
  assert.ok(verifyMatrix([], { candidateSha, specification: { schemaVersion: 1, slots: [null, { id: "invalid" }] } }).length);
});
test("migration slot requires historical schema and transition evidence beyond generic scenario success", () => {
  const value = artifact();
  const suite = "core-api-migration-upgrade", source = "scripts/certops-migration-upgrade.js";
  value.suite = suite; value.report.suite = suite; value.report.evidenceLevel = "e2e";
  value.report.requiredCapabilities = contract.requiredCapabilities[suite];
  value.report.capabilities = Object.fromEntries(contract.requiredCapabilities[suite].map(name => [name, { available: true }]));
  value.report.requiredScenarios = contract.suites[suite];
  value.report.scenarios = contract.suites[suite].map(id => ({ id, status: "passed", evidenceLevel: "e2e", startedAt: value.report.startedAt, finishedAt: value.report.finishedAt }));
  value.report.fixtureSource = { file: source, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, source))).digest("hex") };
  const specification = { schemaVersion: 1, slots: [{ id: suite, kind: "host", suite, source, environment }] };
  assert.ok(verifyMatrix([value], { candidateSha, specification }).length);
  value.report.sourceProvenance = "historical-source-build-to-candidate-source";
  value.report.sourceIdentity = {
    baseline: { sha: require("./certops-migration-upgrade").BASELINE, version: "0.17.3", lockfileSha256: "b".repeat(64) },
    candidate: { sha: candidateSha, version: require("../package.json").version, lockfileSha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "pnpm-lock.yaml"))).digest("hex") },
  };
  value.report.databaseRuntime = { imageId: "sha256:" + "c".repeat(64), serverVersion: "16.6" };
  value.report.baselineSchema = { tables: 1, columns: 2, migrations: [{ version: 1, name: "core_schema" }] };
  value.report.candidateSchema = { tables: 2, columns: 4, migrations: [{ version: 1, name: "core_schema" }, { version: 2, name: "additional_schema" }] };
  value.report.actualTlsObservedPromotion = true; value.report.repeatMigrationSchemaUnchanged = true;
  assert.deepEqual(verifyMatrix([value], { candidateSha, specification }), []);
  value.report.sourceIdentity.candidate.lockfileSha256 = "0".repeat(64);
  assert.ok(verifyMatrix([value], { candidateSha, specification }).some(error => error.includes("package identity")));
});
test("stack matrix validates exact mandatory journey names and refuses skipped or foreign-scope events", () => {
  const event = { ...artifact().report, type: "test:pass", name: "fixture mandatory journey", file: path.join(root, source), scope: "fixture-stack", skip: false, todo: false };
  const slot = { id: "stack-fixture", kind: "stack", suite: event.scope, source, environment, requiredTests: [event.name] };
  const specification = { schemaVersion: 1, slots: [slot] };
  const stack = { kind: "stack", suite: event.scope, environment: event.qualificationEnvironment, events: [event] };
  assert.deepEqual(verifyMatrix([stack], { candidateSha, specification }), []);
  for (const mutation of [{ skip: true }, { scope: "foreign-scope" }, { name: "unrequired journey" }, { type: "test:fail" }]) {
    assert.ok(verifyMatrix([{ ...stack, events: [{ ...event, ...mutation }] }], { candidateSha, specification }).length);
  }
});
test("Windows wrong-SPKI sidecars require preaccept custody and configuration restoration", () => {
  const suite = "windows-acme-wrong-spki";
  const slot = require("../docs/certops/release-qualification-matrix.json").slots.find(row => row.suite === suite);
  const proof = Object.fromEntries(["actualSignedRenewalFailed", "actualCsrDiffersFromReturnedLeaf", "genuineCaIssuedLeafReused", "rejectedUnacceptedKeyRemoved", "predecessorCustodyUnchanged", "bindingAndTrustedTlsUnchanged", "storedProfileUnchanged", "configurationRestored"].map(field => [field, true]));
  const value = suiteArtifact(suite, slot.source, { nativeWrongSpki: proof });
  value.environment = value.report.qualificationEnvironment = { ...slot.environment, measurement: "native" };
  value.report.fixtureSources = slot.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
  assert.deepEqual(verifyMatrix([value], options), []);
  for (const field of Object.keys(proof)) { const bad = structuredClone(value); bad.report.nativeWrongSpki[field] = false; assert.ok(verifyMatrix([bad], options).length); }
  const missing = structuredClone(value); delete missing.report.nativeWrongSpki; assert.ok(verifyMatrix([missing], options).length);
});

test("Windows native stack slots require public admission proof beyond service-created jobs", () => {
  const slot = require("../docs/certops/release-qualification-matrix.json").slots.find(row => row.kind === "stack" && row.suite === "real-agent-windows-acme-iis/rsa-2048");
  const names = [...require(path.join(root, slot.requiredInventory)).requiredTests, ...slot.requiredTests];
  const digest = file => crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex");
  const events = names.map(name => ({ type: "test:pass", name, file: slot.source, scope: slot.suite, candidateSha, qualificationEnvironment: { ...slot.environment, measurement: "native" }, artifactQualification: "workflow-checkout-source", fixtureSource: { file: slot.source, sha256: digest(slot.source) }, fixtureSources: slot.requiredSources.map(file => ({ file, sha256: digest(file) })), skip: false, todo: false }));
  const value = { kind: "stack", suite: slot.suite, environment: events[0].qualificationEnvironment, events };
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
  assert.ok(verifyMatrix([value], options).length);
  const facts = { anonymousAdmissionRefused: true, viewerAdmissionRefused: true, authorizedAdmissionCreated: true, idempotentSameJob: true, publicRequesterPreserved: true, serverDerivedOsStoreKeyMode: true, publicPayloadPreserved: true, nativeJobSucceeded: true, nativeCngIisTrustedTlsVerified: true, ownedActorCleanup: true, anonymousStatus: 401, viewerStatus: 403, createStatus: 201, replayStatus: 201, source: "api", mode: "real", authorizedRole: "workspace_manager" };
  events.at(-1).windowsPublicIssuance = facts;
  assert.deepEqual(verifyMatrix([value], options), []);
  for (const change of [{ ownedActorCleanup: false }, { serverDerivedOsStoreKeyMode: false }, { source: "automation" }, { authorizedRole: "admin" }, { viewerStatus: 201 }, { idempotentSameJob: false }]) {
    const bad = structuredClone(value); Object.assign(bad.events.at(-1).windowsPublicIssuance, change);
    assert.ok(verifyMatrix([bad], options).length);
  }
  const stale = structuredClone(value); stale.events[0].fixtureSources = stale.events[0].fixtureSources.filter(row => row.file !== "tests/e2e/helpers/certops-windows-public-issuance.js");
  assert.ok(verifyMatrix([stale], options).length);
});

test("database matrix requires every committed case and source digest without promoting supporting evidence", () => {
  const definition = require("../tests/integration/certops-qualification-groups.json").adcs;
  const suite = "adcs-database-integration";
  const sources = definition.files.map((file) => ({ file: `tests/integration/${file}`, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "tests/integration", file))).digest("hex") }));
  const report = { scope: suite, candidateSha, evidenceLevel: "integration", qualificationEnvironment: { ...environment, measurement: "native" }, artifactQualification: "workflow-checkout-source", fixtureSources: sources, tests: definition.requiredTests.map((test) => ({ ...test, status: "pass" })) };
  const specification = { schemaVersion: 1, slots: [{ id: "database-fixture", kind: "database", suite, source: sources[0].file, requiredGroup: "adcs", environment }] };
  const artifact = { kind: "database", suite, environment: report.qualificationEnvironment, report };
  assert.deepEqual(verifyMatrix([artifact], { candidateSha, specification }), []);
  for (const mutate of [
    (value) => { value.tests[0].status = "pending"; },
    (value) => { value.tests.pop(); },
    (value) => { value.fixtureSources[0].sha256 = "0".repeat(64); },
    (value) => { value.fixtureSources.push(value.fixtureSources[0]); },
    (value) => { value.evidenceLevel = "real-host"; },
  ]) { const copy = JSON.parse(JSON.stringify(report)); mutate(copy); assert.ok(verifyMatrix([{ ...artifact, report: copy }], { candidateSha, specification }).length); }
});

test("Windows host release proof requires complete CNG custody and same-port SNI isolation",()=>{
 const suite="windows-host",slot=require("../docs/certops/release-qualification-matrix.json").slots.find(item=>item.suite===suite),{CASES}=require("../packages/agent/scripts/host/cng-export-fixture");
 const facts={privateExportBytesWritten:false,privateExportBytesReported:false,workDirectoryUnchanged:true,cases:CASES.map(caseId=>({caseId,exportableControlSucceeded:true,controlBytesZeroed:true,protectedBytesZeroed:true,protectedExportDenied:true,publicNonceSignatureVerified:true,originalCustodyUnchanged:true,controlKeyRemoved:true,privateExportHResult:-2146893813}))};
 const sni={siteCount:2,hostnameCount:2,certificateStore:"My",twoSitesSamePort:true,distinctHostnameSelectors:true,primaryCutoverPeerUnchanged:true,primaryRollbackPeerUnchanged:true,peerCutoverPrimaryUnchanged:true,peerRollbackPrimaryUnchanged:true,sameCertificateReplayVerified:true,independentAuthenticatedTls:true,ownedCleanupVerified:true};
 const contention={winnerGeneratedRealCsr:true,loserLockedBeforeNativeExecution:true,retryAcquiredEnrollmentLock:true,retryExistingContainerRefused:true,sameCsrAndSpki:true,sameNonExportableKey:true,winnerSignatureVerified:true,ownedChildrenStopped:true,ownedKeyRemoved:true,loserNativeCalls:0,loserCertreqCalls:0,retryCertreqCalls:0,winnerCertreqCalls:1,retryNativeCalls:1};
 const value=suiteArtifact(suite,slot.source,{nativeRetentionReferences:retentionReferenceProof(),nativeKeyUsage:keyUsageProof(),cngCustody:facts,nativeSamePortSni:sni,nativeEnrollmentContention:contention,nativeElapsedRetention:elapsedRetentionProof(),nativeKeySurvivors:Object.fromEntries(require("./certops-native-key-survivor-proof").FIELDS.map(field=>[field,true])),nativeRetentionAtomicReplace:Object.fromEntries(require("../packages/agent/scripts/host/retention-ledger-atomic-fixture").FIELDS.map(field=>[field,true]))});value.environment=value.report.qualificationEnvironment={...slot.environment,measurement:"native"};
 value.report.fixtureSources=slot.requiredSources.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));
 const options={candidateSha,specification:{schemaVersion:1,slots:[slot]}};assert.deepEqual(verifyMatrix([value],options),[]);
 const usageSource="packages/agent/scripts/host/cng-key-usage-proof.js",usageOptions=structuredClone(options),sourcedUsage=structuredClone(value);usageOptions.specification.slots[0].requiredSources=[...new Set([...slot.requiredSources,usageSource])];sourcedUsage.report.fixtureSources=sourcedUsage.report.fixtureSources.filter(row=>row.file!==usageSource);sourcedUsage.report.fixtureSources.push({file:usageSource,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,usageSource))).digest("hex")});assert.deepEqual(verifyMatrix([sourcedUsage],usageOptions),[]);
 const staleUsage=structuredClone(sourcedUsage);staleUsage.report.fixtureSources.find(row=>row.file===usageSource).sha256="0".repeat(64);assert.ok(verifyMatrix([staleUsage],usageOptions).length);const missingUsageSource=structuredClone(sourcedUsage);missingUsageSource.report.fixtureSources=missingUsageSource.report.fixtureSources.filter(row=>row.file!==usageSource);assert.ok(verifyMatrix([missingUsageSource],usageOptions).length);
 for(const field of Object.keys(value.report.nativeKeyUsage)){const bad=structuredClone(value);delete bad.report.nativeKeyUsage[field];assert.ok(verifyMatrix([bad],options).length,field);}
 for(const mask of [2,3,6,7,0x00ffffff]){const good=structuredClone(value);for(const item of good.report.nativeKeyUsage.cases)item.cngAllowedOperations=mask;assert.deepEqual(verifyMatrix([good],options),[]);}
 for(let index=0;index<10;index++)for(const mutate of [item=>{delete item.certificateUsageFlags;},item=>{delete item.cngAllowedOperations;},item=>{item.certificateUsageFlags=0;},item=>{item.certificateUsageFlags|=4;},item=>{item.cngAllowedOperations=2|8;},item=>{item.cngAllowedOperations=0;},item=>{item.cngAllowedOperations=true;},item=>{item.cngAllowedOperations="Signing";},item=>{item.cngAllowedOperations=0x100000000;}]){const bad=structuredClone(value);mutate(bad.report.nativeKeyUsage.cases[index]);assert.ok(verifyMatrix([bad],options).length,`case${index}`);}
 for(const mutate of [p=>{p.scope="exact-default-ncrypt-policy-qualified";},p=>{p.copiedActualCsrExtensions=false;},p=>{p.privateKeyUsageClaim="ecdsa-decryption-qualified";},p=>{p.cases.pop();},p=>{p.cases[9]=p.cases[0];},p=>{p.cases[0].caseId="rsa-1024/My";},p=>{p.cases[0].privateKey="unexpected";},p=>{p.privateKey="unexpected";}]){const bad=structuredClone(value);mutate(bad.report.nativeKeyUsage);assert.ok(verifyMatrix([bad],options).length);}
 for(const field of require("../packages/agent/scripts/host/retention-ledger-atomic-fixture").FIELDS){const bad=structuredClone(value);bad.report.nativeRetentionAtomicReplace[field]=false;assert.ok(verifyMatrix([bad],options).length,field);}
 for(const change of [{successfulCutovers:1},{predecessorKeysRemoved:1},{lineageRowsFinalized:1},{immutableHistoryPreserved:false},{waitedMonotonicMs:299999},{waitedMonotonicMs:600000},{fullRetentionWindowQualified:true},{configuredRetentionHours:1}]){const bad=structuredClone(value);Object.assign(bad.report.nativeElapsedRetention,change);assert.ok(verifyMatrix([bad],options).length);}
 for(const field of require("./certops-native-key-survivor-proof").FIELDS){for(const invalid of [false,null,1,"true"]){const bad=structuredClone(value);bad.report.nativeKeySurvivors[field]=invalid;assert.ok(verifyMatrix([bad],options).length,field);}}
 const missingSurvivor=structuredClone(value);delete missingSurvivor.report.nativeKeySurvivors;assert.ok(verifyMatrix([missingSurvivor],options).length);
 const unboundedSurvivor=structuredClone(value);unboundedSurvivor.report.nativeKeySurvivors.rawInventory="sentinel";assert.ok(verifyMatrix([unboundedSurvivor],options).length);
 for(const file of require("./certops-native-key-survivor-proof").REQUIRED_SOURCES){const bad=structuredClone(value);bad.report.fixtureSources.find(source=>source.file===file).sha256="0".repeat(64);assert.ok(verifyMatrix([bad],options).length,file);}
 const missingElapsed=structuredClone(value);delete missingElapsed.report.nativeElapsedRetention;assert.ok(verifyMatrix([missingElapsed],options).length);
 for(const file of ["packages/agent/scripts/host/retention-elapsed-fixture.js","packages/agent/scripts/host/retention-interrupted-child.js","packages/agent/src/index.js","packages/agent/src/windows-retention/index.js","packages/agent/src/windows-discovery/index.js"]){
  const staleElapsed=structuredClone(value);staleElapsed.report.fixtureSources.find(row=>row.file===file).sha256="0".repeat(64);assert.ok(verifyMatrix([staleElapsed],options).length,file);
 }
 for(const field of require("../packages/agent/scripts/host/retention-reference-fixture").fields){for(const invalid of [false,null,1,"true"]){const bad=structuredClone(value);bad.report.nativeRetentionReferences[field]=invalid;assert.ok(verifyMatrix([bad],options).length,field);}}
 for(const mutate of [v=>{delete v.report.nativeRetentionReferences;},v=>{v.report.nativeRetentionReferences.scope="actual-adcs-enrollment";},v=>{v.report.nativeRetentionReferences.elapsed24HourQualified=true;},v=>{v.report.nativeRetentionReferences.rawInventory="sentinel";}]){const bad=structuredClone(value);mutate(bad);assert.ok(verifyMatrix([bad],options).length);}
 for(const source of require("../packages/agent/scripts/host/retention-reference-fixture").requiredSources){const bad=structuredClone(value);bad.report.fixtureSources.find(row=>row.file===source).sha256="0".repeat(64);assert.ok(verifyMatrix([bad],options).length,source);}
 const missingAtomic=structuredClone(value);delete missingAtomic.report.nativeRetentionAtomicReplace;assert.ok(verifyMatrix([missingAtomic],options).length);
 const staleAtomic=structuredClone(value);staleAtomic.report.fixtureSources.find(source=>source.file.endsWith("retention-ledger-atomic-fixture.js")).sha256="0".repeat(64);assert.ok(verifyMatrix([staleAtomic],options).length);
 for(const mutate of [v=>{delete v.report.nativeEnrollmentContention;},v=>{v.report.nativeEnrollmentContention.loserNativeCalls=1;},v=>{v.report.nativeEnrollmentContention.retryCertreqCalls=1;},v=>{v.report.nativeEnrollmentContention.sameNonExportableKey=false;},v=>{v.report.nativeEnrollmentContention.ownedChildrenStopped=false;},v=>{delete v.report.nativeSamePortSni;},v=>{v.report.nativeSamePortSni.hostnameCount=1;},v=>{v.report.nativeSamePortSni.peerRollbackPrimaryUnchanged=false;},v=>{v.report.nativeSamePortSni.ownedCleanupVerified=false;},v=>{delete v.report.cngCustody;},v=>{v.report.cngCustody.cases.pop();},v=>{v.report.cngCustody.cases[0].controlBytesZeroed=false;},v=>{v.report.cngCustody.privateExportBytesReported=true;},v=>{v.report.cngCustody.cases[0].privateExportHResult=0;}]){const bad=structuredClone(value);mutate(bad);assert.ok(verifyMatrix([bad],options).length);}
});


test("first-rename refusal requires actual held fault and preserved running predecessor", () => {
  const suite = "windows-installer-first-rename-refusal", helper = require("../tests/e2e/helpers/certops-windows-rename-refusal");
  const slot = require("../docs/certops/release-qualification-matrix.json").slots.find(row => row.suite === suite);
  const fields = ["nativeDirectoryHandleHeld", "nativeHandleIdentityMatched", "actualFirstRenameRefused", "stagingRemoved", "previousDirectoryAbsent", "installedFilesUnchanged", "configurationAndCredentialUnchanged", "sameRunningServicePid", "freshAuthenticatedHeartbeat", "trustedTlsUnchanged", "nativeHandleReleased", "ownedChildDrained"];
  const facts = Object.fromEntries(fields.map(field => [field, true]));
  assert.equal(helper.verifyProof(facts), true);
  const value = suiteArtifact(suite, slot.source, { nativeRenameRefusal: facts });
  value.environment = value.report.qualificationEnvironment = { ...slot.environment, measurement: "native" };
  value.report.fixtureSources = slot.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
  assert.deepEqual(verifyMatrix([value], options), []);
  for (const field of fields) {
    const bad = structuredClone(value); bad.report.nativeRenameRefusal[field] = false;
    assert.ok(verifyMatrix([bad], options).length, field);
  }
  const missing = structuredClone(value); delete missing.report.nativeRenameRefusal;
  assert.ok(verifyMatrix([missing], options).length);
  const stale = structuredClone(value); stale.report.fixtureSources[0].sha256 = "0".repeat(64);
  assert.ok(verifyMatrix([stale], options).length);
});

test("second-rename evidence cannot claim full CLI rollback or omit native ownership and cleanup", () => {
  const suite = "windows-activation-second-rename", helper = require("../tests/e2e/helpers/certops-windows-second-rename");
  const slot = require("../docs/certops/release-qualification-matrix.json").slots.find(item => item.suite === suite);
  const proof = { ...Object.fromEntries(helper.factFields.map(field => [field, true])), scope: "production-activation-functions-not-installer-cli" };
  const value = suiteArtifact(suite, slot.source, { nativeSecondRename: proof });
  value.environment = value.report.qualificationEnvironment = { ...slot.environment, measurement: "native" };
  value.report.fixtureSources = slot.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
  assert.deepEqual(verifyMatrix([value], options), []);
  for (const field of helper.factFields) { const invalid = structuredClone(value); invalid.report.nativeSecondRename[field] = false; assert.ok(verifyMatrix([invalid], options).length, field); }
  const missing = structuredClone(value); delete missing.report.nativeSecondRename; assert.ok(verifyMatrix([missing], options).length);
  const falseScope = structuredClone(value); falseScope.report.nativeSecondRename.scope = "complete-cli-rollback"; assert.ok(verifyMatrix([falseScope], options).length);
  const stale = structuredClone(value); stale.report.fixtureSources[0].sha256 = "0".repeat(64); assert.ok(verifyMatrix([stale], options).length);
});

function acmeReuseProof(client) {
  const helper=require("../tests/e2e/helpers/certops-acme-key-reuse");
  return {scope:helper.scope,client,...Object.fromEntries(helper.fields.map(field=>[field,true])),fingerprints:["a","b","c"].map(value=>value.repeat(64)),serials:["A1","B2","C3"],spkiFingerprint:"d".repeat(64),jobIds:[crypto.randomUUID(),crypto.randomUUID()],sourceProfileId:crypto.randomUUID(),sourceProfileFingerprint:"e".repeat(64)};
}

test("Linux ACME key reuse requires exact client-bound native proof and current sources", () => {
  const helper=require("../tests/e2e/helpers/certops-acme-key-reuse");
  const scopes=["real-agent-acme-filesystem","real-agent-acme-eab-filesystem","real-agent-acmesh-filesystem","real-agent-acmesh-eab-filesystem","real-agent-alpine-acmesh"];
  const slots=require("../docs/certops/release-qualification-matrix.json").slots.filter(slot=>scopes.includes(slot.suite));
  assert.equal(slots.length,5);
  for(const slot of slots){
    const client=slot.suite.includes("acmesh")?"acme.sh":"certbot";
    const names=[...(slot.requiredInventory?require(path.join(root,slot.requiredInventory)).requiredTests:[]),...(slot.requiredTests||[])];
    const digest=file=>crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex");
    const events=names.map(name=>({type:"test:pass",name,file:slot.source,scope:slot.suite,candidateSha,qualificationEnvironment:{...slot.environment,measurement:"native"},artifactQualification:"workflow-checkout-source",fixtureSource:{file:slot.source,sha256:digest(slot.source)},fixtureSources:slot.requiredSources.map(file=>({file,sha256:digest(file)})),skip:false,todo:false}));
    const main=events.find(event=>event.name==="real ACME: agent discovers public files registers claims issues renews deploys and persists independently verified certificate evidence");assert.ok(main);
    main.nativeAcmeKeyReuse=acmeReuseProof(client);
    const value={kind:"stack",suite:slot.suite,environment:{...slot.environment,measurement:"native"},events};
    const options={candidateSha,specification:{schemaVersion:1,slots:[slot]}};
    assert.deepEqual(verifyMatrix([value],options),[]);
    const reject=mutate=>{const bad=structuredClone(value);mutate(bad.events.find(event=>event.name===main.name),bad);assert.ok(verifyMatrix([bad],options).length,slot.suite);};
    for(const field of helper.fields){for(const invalid of [false,1,null,"true"])reject(event=>{event.nativeAcmeKeyReuse[field]=invalid;});reject(event=>{delete event.nativeAcmeKeyReuse[field];});}
    for(const change of [{scope:"windows-native-reuse"},{scope:"background-worker-loop"},{client:client==="certbot"?"acme.sh":"certbot"},{fingerprints:["a".repeat(64),"a".repeat(64),"b".repeat(64)]},{serials:["AA","AA","BB"]},{jobIds:[main.nativeAcmeKeyReuse.jobIds[0],main.nativeAcmeKeyReuse.jobIds[0].toUpperCase()]},{sourceProfileId:"foreign"},{sourceProfileFingerprint:"bad"},{spkiFingerprint:"bad"},{windowsQualified:true},{workerLoopQualified:true}])reject(event=>Object.assign(event.nativeAcmeKeyReuse,change));
    reject(event=>{delete event.nativeAcmeKeyReuse;});
    reject((event,bad)=>{bad.events[0].fixtureSources[0].sha256="0".repeat(64);});
    reject((event,bad)=>{bad.events=bad.events.filter(row=>row.name!==helper.scenarioName);});
  }
});

function elapsedRetentionProof() {
 return {mode:"real-clock-two-cutover-expiry-grace",successfulCutovers:2,predecessorCertificatesRemoved:2,predecessorKeysRemoved:2,lineageRowsFinalized:2,immediateDeferralPreservedCustody:true,immutableHistoryPreserved:true,replacementTrustedBoundCustodyUnchanged:true,interruptedNativeDeleteRecovered:true,configuredRetentionHours:24,fullRetentionWindowQualified:false,waitedMonotonicMs:420000};
}


test("canonical Windows CLI and completed-console facts are mandatory and source-bound", () => {
  const canonical = require("../tests/e2e/helpers/certops-windows-fixed-root");
  const cases = [
    [canonical.suite, "nativeCanonicalRoot", canonical.fields, { scope: "unmodified-candidate-cli-canonical-root-same-version-reapplication" }],
    ["browser-agent-console", "completedConsolePrivacy", require("./certops-completed-console-proof").FIELDS, {}],
  ];
  for (const [suite, key, fields, extra] of cases) {
    const slots = require("../docs/certops/release-qualification-matrix.json").slots.filter(slot => slot.suite === suite);
    assert.equal(slots.length, suite === canonical.suite ? 2 : 1);
    for (const slot of slots) {
      const proof = { ...Object.fromEntries(fields.map(field => [field, true])), ...extra };
      const value = suiteArtifact(suite, slot.source, { [key]: proof });
      value.environment = value.report.qualificationEnvironment = { ...slot.environment, measurement: "native" };
      value.report.fixtureSources = slot.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
      const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
      assert.deepEqual(verifyMatrix([value], options), []);
      for (const field of fields) for (const invalid of [false, 1, null, "true"]) {
        const bad = structuredClone(value); bad.report[key][field] = invalid; assert.ok(verifyMatrix([bad], options).length, field);
      }
      const missing = structuredClone(value); delete missing.report[key]; assert.ok(verifyMatrix([missing], options).length);
      const unbounded = structuredClone(value); unbounded.report[key].rawSecret = "sentinel"; assert.ok(verifyMatrix([unbounded], options).length);
      for (const file of slot.requiredSources) { const stale = structuredClone(value); stale.report.fixtureSources.find(row => row.file === file).sha256 = "0".repeat(64); assert.ok(verifyMatrix([stale], options).length, file); }
      if (suite === canonical.suite) { const overclaim = structuredClone(value); overclaim.report[key].scope = "published-upgrade"; assert.ok(verifyMatrix([overclaim], options).length); }
    }
  }
});

test("full installer CLI second-rename evidence requires exact scope and all native facts", () => {
  const helper=require("../tests/e2e/helpers/certops-windows-cli-second-rename"), suite=helper.suite;
  assert.equal(helper.fields.length,19);
  const slots=require("../docs/certops/release-qualification-matrix.json").slots.filter(slot=>slot.suite===suite);
  assert.equal(slots.length,2);
  for(const slot of slots){
    const proof={scope:"unmodified-installer-cli-canonical-root-operator-cng-binding",...Object.fromEntries(helper.fields.map(field=>[field,true]))};
    const value=suiteArtifact(suite,slot.source,{nativeCliSecondRename:proof});
    value.environment=value.report.qualificationEnvironment={...slot.environment,measurement:"native"};
    value.report.fixtureSources=slot.requiredSources.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));
    const options={candidateSha,specification:{schemaVersion:1,slots:[slot]}};
    assert.deepEqual(verifyMatrix([value],options),[]);
    for(const field of helper.fields){
      for(const invalid of [false,1,null,"true"]){const bad=structuredClone(value);bad.report.nativeCliSecondRename[field]=invalid;assert.ok(verifyMatrix([bad],options).length,field);}
      const missing=structuredClone(value);delete missing.report.nativeCliSecondRename[field];assert.ok(verifyMatrix([missing],options).length,field);
    }
    for(const invalid of [undefined,null,[],{...proof,scope:"production-activation-functions-not-installer-cli"},{...proof,scope:"temporaryfile-mechanics-only"},{...proof,agentIssuanceQualified:true}]){
      const bad=structuredClone(value);bad.report.nativeCliSecondRename=invalid;assert.ok(verifyMatrix([bad],options).length);
    }
    const stale=structuredClone(value);stale.report.fixtureSources[0].sha256="0".repeat(64);assert.ok(verifyMatrix([stale],options).length);
  }
});
