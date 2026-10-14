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
const candidateSha = "a".repeat(40);
const source = "tests/e2e/certops-job-decisions-e2e.test.js";
const environment = { osFamily: "linux" };
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
  assert.deepEqual(verifyMatrix([value], options), []);
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
    nativeValidationExpiry: { configuredTimeoutSeconds: 300, defaultTimeoutSeconds: 86400, storedWindowSeconds: 299, monotonicObservedWaitSeconds: 301, actualDeadline: new Date().toISOString(), requestId: "17", snapshotSha256: "a".repeat(64), actualNativeRevocationUnknown: true, actualSignedContinuationExpired: true, persistedDeadlineSurvivedRestartAndPolicyRestoration: true, exactUnacceptedKeyFreed: true, noCertificateAccepted: true, noCaResubmission: true, outgoingTrustedTlsPreserved: true, chainCacheValueRestored: true, nativeAndCaClocks: "actual", qualificationScope: "configured-five-minute-window-not-default-24-hour-elapsed" },
    primaryNativePreflightDispatchCount: 18,
    nativePreflightCohorts: [{ workspaceId: "a".repeat(36), agentId: "b".repeat(36), dispatchCount: 18, dispatchLimit: 18, nativeIdentity: "LocalSystem", runtime: "candidate-cli" }],
    nativeTemplateMutations: contract.suites[suite].filter(id => id.startsWith("adcs-real-mutated-template-")).map(id => ({ caseId: id.slice("adcs-real-mutated-template-".length, -"-native-refused".length), template: "TTQualificationRSAShort", preflightVerdict: "unsafe", originalConfirmedIssuerReused: true, actualSignedJobRefused: true, noCaRequestAllocated: true, noKeyGenerated: true, outgoingTrustedTlsPreserved: true })),
  });
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [{ id: "cohort", kind: "host", suite, source: file, environment }] } };
  assert.deepEqual(verifyMatrix([value], options), []);
  for (const mutate of [item => { item.report.nativeIssuedCancellation.unusedIssuedLeafRevoked = false; }, item => { item.report.nativeIssuedCancellation.certificateNeverAccepted = false; }, item => { delete item.report.nativePreflightCohorts; }, item => { item.report.primaryNativePreflightDispatchCount = 19; }, item => { item.report.nativePreflightCohorts[0].dispatchCount = 19; }, item => { item.report.nativePreflightCohorts.push(item.report.nativePreflightCohorts[0]); }, item => { item.report.nativePreflightCohorts[0].runtime = "mock"; }]) {
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
 const value=suiteArtifact(suite,slot.source,{cngCustody:facts,nativeSamePortSni:sni,nativeEnrollmentContention:contention});value.environment=value.report.qualificationEnvironment={...slot.environment,measurement:"native"};
 value.report.fixtureSources=slot.requiredSources.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));
 const options={candidateSha,specification:{schemaVersion:1,slots:[slot]}};assert.deepEqual(verifyMatrix([value],options),[]);
 for(const mutate of [v=>{delete v.report.nativeEnrollmentContention;},v=>{v.report.nativeEnrollmentContention.loserNativeCalls=1;},v=>{v.report.nativeEnrollmentContention.retryCertreqCalls=1;},v=>{v.report.nativeEnrollmentContention.sameNonExportableKey=false;},v=>{v.report.nativeEnrollmentContention.ownedChildrenStopped=false;},v=>{delete v.report.nativeSamePortSni;},v=>{v.report.nativeSamePortSni.hostnameCount=1;},v=>{v.report.nativeSamePortSni.peerRollbackPrimaryUnchanged=false;},v=>{v.report.nativeSamePortSni.ownedCleanupVerified=false;},v=>{delete v.report.cngCustody;},v=>{v.report.cngCustody.cases.pop();},v=>{v.report.cngCustody.cases[0].controlBytesZeroed=false;},v=>{v.report.cngCustody.privateExportBytesReported=true;},v=>{v.report.cngCustody.cases[0].privateExportHResult=0;}]){const bad=structuredClone(value);mutate(bad);assert.ok(verifyMatrix([bad],options).length);}
});
