
/**
 * Regression coverage: a complete mandatory matrix cannot promote incomplete feature specifications.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
function cngJournalAclProof(){return {"scope":"native-prepared-cng-preserved-through-unreadable-adcs-journal","caEnrollmentQualified":false,"installedServiceQualified":false,"actualPreparedNativeKeyPrerequisite":true,"actualFreshOsReadAndListDenied":true,"productionJournalNotAbsent":true,"actualOrphanReconciliationDeferred":true,"sameNativePrivateKeyPossession":true,"sameJournalBytesAndFileIdentities":true,"exactRetainedHandleAclsRestored":true,"ownedNativeChildrenDrained":true,"productionJournalReadersRecovered":true};}
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { verifyMatrix, validateMatrix } = require("./certops-release-qualification");
const { catalogCoverage, validateQualificationSummary } = require("./certops-release-qualification");
const contract = require("../docs/certops/qualification-suites.json");
const root = path.resolve(__dirname, "..");
function adcsCapacityProof(){const helper=require("../tests/e2e/helpers/certops-adcs-capacity");return{scope:helper.SCOPE,cap:5,initialAccepted:5,initialRefused:1,nativeCompleted:2,...Object.fromEntries(helper.FLAGS.map(flag=>[flag,true])),requestIds:["17","18"],fingerprints:["a".repeat(64),"b".repeat(64)],enrollmentIds:["11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222"],jobIds:["33333333-3333-3333-3333-333333333333","44444444-4444-4444-4444-444444444444"]};}
function policyExpiryProof() {
 const helper = require("../packages/agent/scripts/host/retention-policy-expiry-proof");
 return Object.fromEntries(helper.POLICIES.map(hours => [String(hours), {
  ownedInterruption:{scope:'owned-short-retention-native-interruption-drain',assignedBeforeResume:true,rootExit86:true,nativeActiveZero:true,nativeHandlesClosed:true,wrapperClosed:true},scope:helper.SCOPE,configuredRetentionHours:hours,verifiedCutoverAt:"2026-10-15T10:00:00.000Z",oldNotAfter:"2026-10-15T10:02:00.000Z",cleanupDeadline:"2026-10-15T10:07:00.000Z",preDeadlineObservedAt:"2026-10-15T10:01:00.000Z",cleanupObservedAt:"2026-10-15T10:07:01.000Z",waitStartedAt:"2026-10-15T10:01:00.000Z",waitFinishedAt:"2026-10-15T10:07:01.000Z",waitedMonotonicMs:361000,installedServiceTimerQualified:false,fullRetentionWindowQualified:false,...Object.fromEntries(helper.FLAGS.map(field=>[field,true])),...Object.fromEntries(helper.COUNTS.map(field=>[field,2]))
 }]));
}
function sameCertificateLateApprovalProof(){return {...cancelledLateApprovalProof(),scope:"real-cancelled-request-late-issued-after-same-certificate-renewal",sameCertificateRenewalQualified:true,backgroundTimerQualified:false,certificateId:"33333333-3333-4333-8333-333333333333"};}
function cancelledLateApprovalProof(){return {"scope":"real-cancelled-request-late-issued-after-distinct-same-endpoint-successor","cancelledEnrollmentId":"11111111-1111-1111-1111-111111111111","successorEnrollmentId":"22222222-2222-2222-2222-222222222222","requestIds":["17","18"],"fingerprints":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"sameCertificateRenewalQualified":false,"publicCancellationAuditVerified":true,"terminalCleanupAlreadyCompleted":true,"distinctActualSuccessorInstalled":true,"nativePendingCsrRequesterTemplateOwned":true,"actualOfficerLateApproval":true,"actualCaLeafMatchesOriginalCsr":true,"defaultClockDoesNotRevive":true,"overdueSchedulerDoesNotRevive":true,"publicInstallationRetryRefused":true,"originalJournalAndJobsUnchanged":true,"cancelledKeyRemainsAbsent":true,"lateLeafNeverAccepted":true,"successorClaimEvidenceUnchanged":true,"successorNativeCustodyBindingTlsUnchanged":true,"noCaResubmission":true,"ownedUnusedLateLeafRevoked":true};}
function retentionReferenceProof(){const helper=require("../packages/agent/scripts/host/retention-reference-fixture");return {scope:"native-collector-supporting-ledger-reference-lifecycle",elapsed24HourQualified:false,...Object.fromEntries(helper.fields.map(field=>[field,true]))};}
function browserJobApprovalProof(){return {"scope":"browser-control-plane-job-approval-for-two-real-adcs-capacity-installations","approvePosts":2,"rejectPosts":1,"cancelPosts":0,"caOfficerApprovalQualified":false,"jobIds":["33333333-3333-3333-3333-333333333333","44444444-4444-4444-4444-444444444444"],"enrollmentIds":["11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222"],"payloadHashes":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"requestIds":["17","18"],"fingerprints":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"rejectedJobId":"77777777-7777-7777-7777-777777777777","rejectedEnrollmentId":"88888888-8888-8888-8888-888888888888","rejectedPayloadHash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","rejectedCanonicalIntentHash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","twoDistinctOwnedPendingJobs":true,"distinctManagerApprover":true,"exactJobVisibleInActualDashboard":true,"cancelDidNotMutate":true,"twoExactPublicApprovalPosts":true,"appendOnlyDecisionsBoundToActor":true,"payloadAndCanonicalIntentHashesVerified":true,"browserAndTrustDrained":true,"sameApprovedJobsInstalledNatively":true,"capacityGenerationsCrossBound":true,"oneExactPublicRejectionPost":true,"rejectedJobNeverClaimedOrSubmitted":true,"rejectedIntentAndNativeAbsencePreserved":true}}
function ipv4WildcardProof(){return {"scope":"native-ipv4-wildcard-sni-shadow-rollback-with-ipv4-sibling","installedAgentQualified":false,"caQualified":false,"actualIpv4LoopbackAvailable":true,"borrowedCertificatesVerified":true,"actualIpv4ShadowObserved":true,"productionPrecedenceWarning":true,"actualProductionVerifyFailed":true,"actualProductionRollback":true,"nativeHostnameEndpointRestored":true,"trustedIpv4ShadowObserved":true,"trustedIpv4BaselineRecovered":true,"ipv4SiblingUnchanged":true,"ownedSitesAndEndpointsRemoved":true}}
function ipv6WildcardProof(){return {"scope":"native-ipv6-wildcard-sni-shadow-rollback-with-ipv4-sibling","installedAgentQualified":false,"caQualified":false,"actualIpv6LoopbackAvailable":true,"borrowedCertificatesVerified":true,"actualIpv6ShadowObserved":true,"productionPrecedenceWarning":true,"actualProductionVerifyFailed":true,"actualProductionRollback":true,"nativeHostnameEndpointRestored":true,"trustedIpv6ShadowObserved":true,"trustedIpv6BaselineRecovered":true,"ipv4SiblingUnchanged":true,"ownedSitesAndEndpointsRemoved":true}}
function ipv6ShadowProof(){return {"scope":"native-ipv6-sni-shadow-rollback-with-ipv4-sibling","installedAgentQualified":false,"caQualified":false,"actualIpv6LoopbackAvailable":true,"borrowedCertificatesVerified":true,"actualIpv6ShadowObserved":true,"productionPrecedenceWarning":true,"actualProductionVerifyFailed":true,"actualProductionRollback":true,"nativeHostnameEndpointRestored":true,"trustedIpv6ShadowObserved":true,"trustedIpv6BaselineRecovered":true,"ipv4SiblingUnchanged":true,"ownedSitesAndEndpointsRemoved":true}}
function orphanJournalProof(){return {"scope":"native-cng-supporting-prepared-journal-orphan-protection","installedServiceQualified":false,"caEnrollmentQualified":false,"orphanAgePolicyQualified":false,"actualPreparedCngCsr":true,"actualUnresolvedJobPrerequisites":true,"unprotectedNativeOrphanRemoved":true,"openJournalKeyPreserved":true,"corruptJournalFailsClosed":true,"exactJournalBytesRestored":true,"untrackedNativeKeyPreserved":true,"independentPrivateKeyPossession":true,"actualGlobalStoreInventory":true,"terminalFixtureClosureAllowsCleanup":true,"ownedNativeKeysAndStateRemoved":true}}
function ledgerReadProof(){const h=require("../packages/agent/scripts/host/retention-ledger-read-refusal-fixture");return {scope:h.scope,...Object.fromEntries(h.fields.map(field=>[field,true])),installedServiceQualified:false,nativeCertificateCleanupQualified:false,elapsedRetentionQualified:false};}
function journalReadProof(){return {"scope":"native-temporary-adcs-journal-acl-refusals-not-installed-enrollment","installedServiceQualified":false,"nativeCngQualified":false,"genuinePreparedPublicCsr":true,"twoActualNativeAccessDenials":true,"journalUnreadableNotAbsent":true,"globalProtectionScanDeferred":true,"exactFileIdentitiesAndBytesPreserved":true,"exactNativeAclsRestored":true,"productionReadersRecovered":true,"ownedTemporaryStateRemoved":true}}
function stateReadProof(){const helper=require("../packages/agent/scripts/host/state-read-refusal-fixture");return {scope:"native-temporary-state-read-denials-production-readers",installedServiceStartupQualified:false,...Object.fromEntries(helper.fields.map(field=>[field,true]))};}
const candidateSha = "a".repeat(40);
const source = "tests/e2e/certops-job-decisions-e2e.test.js";
const environment = { osFamily: "linux" };
function packagedChainRuntimeProof(){const h=require("../packages/agent/scripts/host/packaged-helper-runtime-fixture");return {scope:h.SCOPE,metadataOnly:true,serviceInstalled:false,cmcPackagedQualified:false,nativeGoVerifierPackagedQualified:false,architecture:"amd64",chainHelperSha256:"a".repeat(64),wrongProtocolHostSha256:"b".repeat(64),...Object.fromEntries(h.FLAGS.map(flag=>[flag,true]))};}
function httpClientSettingsProof(){const helper=require("../packages/agent/scripts/host/iis-client-settings-fixture");return {scope:helper.SCOPE,clientAuthHandshakeQualified:false,cases:helper.CASES.map(item=>({id:item.id,checkMode:item.checkMode,freshness:item.freshness,retrievalTimeout:item.retrievalTimeout,...Object.fromEntries(helper.FLAGS.map(flag=>[flag,true]))}))};}
function keyUsageProof() {
  const { CASES, CERTIFICATE_USAGE, SCOPE } = require("../packages/agent/scripts/host/cng-key-usage-proof");
  return { scope: SCOPE, copiedActualCsrExtensions: true, privateKeyUsageClaim: "signing-permitted-not-exact-default-ncrypt-mask", cases: CASES.map(caseId => ({ caseId, certificateUsageFlags: CERTIFICATE_USAGE[caseId.split("/")[0]], cngAllowedOperations: 0x00ffffff })) };
}
function foreignSpkiProof(){const helper=require("../tests/e2e/helpers/certops-adcs-native-reconcile");return {scope:helper.foreignScope,...Object.fromEntries(helper.foreignFlags.map(flag=>[flag,true])),requestIds:["17","18"],spkiFingerprints:["a".repeat(64),"b".repeat(64)]};}
function localPairsProof(){const helper=require("../tests/e2e/helpers/certops-adcs-local-rules");return helper.pairCases.map(caseId=>({caseId,...Object.fromEntries(helper.pairFlags.map(flag=>[flag,true]))}));}
function algorithmProof(){const helper=require("../tests/e2e/helpers/certops-adcs-algorithm-boundaries");return helper.CASES.map((item,index)=>({caseId:item.id,positiveScenario:`adcs-real-${item.positiveId}-issued-cng-iis`,positiveFingerprintSha256:(index+10).toString(16).repeat(64),positiveRequestId:String(17+index),...Object.fromEntries(helper.FLAGS.map(flag=>[flag,true]))}));}
function cmcProof(){const helper=require("../tests/e2e/helpers/certops-adcs-cmc-signature-copy");return {scope:helper.scope,...Object.fromEntries(helper.flags.map(flag=>[flag,true])),syntheticCaResponse:false,caRequestId:"17",responseSha256:"a".repeat(64),nativeHelperSha256:"b".repeat(64),originalResponseDerSha256:"c".repeat(64),tamperedResponseDerSha256:"d".repeat(64),refusedVariants:[...helper.refusedVariants]};}
function browserCancelProof(){const h=require("../tests/e2e/helpers/certops-adcs-browser-cancel"),c=adcsCapacityProof();return {scope:h.SCOPE,enrollmentId:"55555555-5555-5555-5555-555555555555",jobId:"66666666-6666-6666-6666-666666666666",priorEnrollmentId:c.enrollmentIds[1],priorJobId:c.jobIds[1],priorRequestId:c.requestIds[1],fingerprint:c.fingerprints[1],cancelPosts:1,otherMutations:0,capacityBeforeCancel:5,capacityAfterCancel:4,initialSixConcurrencyQualified:false,caSubmissionCancellationQualified:false,...Object.fromEntries(h.FLAGS.map(flag=>[flag,true]))};}
function pendingCaProof(){return{scope:"real-pending-enrollment-across-same-key-ca-certificate-renewal",schedulerClock:"supported-scheduler-now-input",backgroundWorkerIntervalQualified:false,enrollmentId:"11111111-1111-1111-1111-111111111111",originalJobId:"22222222-2222-2222-2222-222222222222",continuationJobId:"33333333-3333-3333-3333-333333333333",requestId:"17",caKeySha256:"a".repeat(64),caCertificateCountBefore:1,caCertificateCountAfter:2,csrSha256:"b".repeat(64),spkiSha256:"c".repeat(64),leafFingerprint:"d".repeat(64),predecessorFingerprint:adcsCapacityProof().fingerprints[1],...Object.fromEntries(["matchingActualInstalledPredecessor", "ownedMyCleanupRegistered", "actualPendingBeforeCaRenewal", "pendingCngSignatureVerified", "actualCaSameKeyRenewal", "confirmedIssuerUnchanged", "noReconfirmation", "pendingCsrKeyRequestPreserved", "predecessorPreservedAcrossCaRenewal", "actualSameRequestApproved", "actualSignedContinuationInstalled", "claimBoundNativeEvidence", "nativeSamePendingKeyAndLeaf", "trustedTlsCutover", "predecessorKeyAndReceiptPreserved", "noCaResubmission"].map(flag=>[flag,true]))};}
function issuedRevocationProof(){const h=require("../tests/e2e/helpers/certops-adcs-issued-revocation");return{scope:h.SCOPE,requestId:"17",enrollmentId:"11111111-1111-1111-1111-111111111111",continuationJobId:"22222222-2222-2222-2222-222222222222",errorCode:"ADCS_CERTIFICATE_INVALID",schedulerDefaultClockQualified:false,...Object.fromEntries(h.FLAGS.map(flag=>[flag,true]))};}
function issuedSanProof(){const h=require("../tests/e2e/helpers/certops-adcs-issued-san-boundary");return{scope:h.SCOPE,requestId:"17",enrollmentId:"11111111-1111-1111-1111-111111111111",continuationJobId:"22222222-2222-2222-2222-222222222222",errorCode:"ADCS_CERTIFICATE_INVALID",...Object.fromEntries(h.FLAGS.map(flag=>[flag,true]))};}
function browserReconcileProof(){const h=require("../tests/e2e/helpers/certops-adcs-browser-reconcile"),n=operatorAmbiguityProof();return {scope:h.SCOPE,fixtureOrigin:h.ORIGIN,...Object.fromEntries(h.FLAGS.map(flag=>[flag,true])),enrollmentId:n.enrollmentId,selectedRequestId:n.selectedRequestId,unusedRequestId:n.unusedRequestId,selectedFingerprint:n.fingerprints[0],continuationJobId:n.jobIds[2],reconcilePosts:1,invalidRequestPosts:0};}
function operatorAmbiguityProof() {
  const helper = require("../tests/e2e/helpers/certops-adcs-uncertain-operator-ambiguity");
  const enrollmentId = "11111111-1111-1111-1111-111111111111";
  return { scope: helper.SCOPE, fixtureOrigin: "operator-created-two-real-system-submissions-of-the-same-public-csr", resolvedIssuingCaAddress: "10.64.0.4",
    leaseRemainingAtFaultMs: 60000, recoveryWaitBudgetMs: 150000, actualLeaseWaitMs: 120000,
    caRequestsAtFault: 0, caRequestsAfterOperatorSubmissions: 2, caRequestsAfterAmbiguousRecovery: 2, caRequestsAfterExplicitRecovery: 2,
    requestIds: ["101", "102"], fingerprints: ["1".repeat(64), "2".repeat(64)], serialNumbers: ["aa", "bb"], csrSpkiSha256: "3".repeat(64), csrSha256: "4".repeat(64),
    selectedRequestId: "101", unusedRequestId: "102", enrollmentId, containerName: `tokentimer-enr-${enrollmentId}`,
    jobIds: ["22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333", "44444444-4444-4444-4444-444444444444"],
    reconcileSearchFrom: 100, scanWindowSize: 16, ...Object.fromEntries(helper.FLAGS.map(flag => [flag, true])) };
}
function browserAdcsProof() {
  const { FLAGS, SCOPE } = require("../tests/e2e/helpers/certops-adcs-browser-journey");
  const uuid = value => `${value.repeat(8)}-${value.repeat(4)}-4${value.repeat(3)}-8${value.repeat(3)}-${value.repeat(12)}`;
  return { ...Object.fromEntries(FLAGS.map(key => [key, true])), scope: SCOPE, lifecycle: "renew-existing-inventory-not-first-issue-or-manual-job", scheduler: "production-default-sweep-not-background-worker-loop", browserEngine: "chromium", browserMutationCount: 6, successfulEnrollments: 1,
    fingerprints: ["a", "b"].map(value => value.repeat(64)), spkiFingerprints: ["c", "d"].map(value => value.repeat(64)), requestId: "17", enrollmentId: uuid("a"), jobId: uuid("b"), profileId: uuid("c"), issuerId: uuid("d") };
}
function backgroundAdcsProof() {
 return {...twoAdcsRenewalsProof(),scope:"two-real-default-interval-worker-native-adcs-renewals",schedulerInvocation:"actual-production-runner-default-interval",workerIntervalQualified:true,workerLifecycle:{failed:false,starts:1,ticks:2,finishes:2,summaries:2,created:2,stops:1,forwarded:true,firstTickElapsedMs:60010,exitCode:0,nativeDrained:true,bridgeReady:true}};
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
    nativeAdcsBackgroundRenewals: backgroundAdcsProof(),
    nativeBrowserAbandon: {"scope":"browser-confirmed-real-uncertain-abandon-and-native-unaccepted-key-cleanup","enrollmentId":"11111111-1111-1111-1111-111111111111","cleanupJobId":"22222222-2222-2222-2222-222222222222","abandonPosts":1,"keepPosts":0,"actualUncertainEnrollmentVisible":true,"keepDidNotMutate":true,"explicitConfirmationRequired":true,"exactPublicAbandonAcknowledged":true,"browserAndTrustDrained":true,"actualProductionContinuation":true,"journalAndDatabaseAbandoned":true,"exactUnacceptedKeyAbsent":true,"noAcceptedLeaf":true,"zeroNativeCaRequests":true,"onePublicAudit":true,"originalUnknownEffectPreserved":true},
    nativeWebHostingRenewal: {"scope":"real-adcs-webhosting-issue-and-fresh-key-manual-renewal","store":"WebHosting","expiryCleanupQualified":false,"requestIds":["17","18"],"fingerprints":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"publicIssueAndRenewInstalled":true,"twoIndependentCaRequests":true,"freshSerialSpkiAndKey":true,"webHostingProtectedCustody":true,"myCopiesAbsent":true,"exactNativeIisAndHttpSysStore":true,"trustedSniTls":true,"installedDiscoveryInventory":true,"immutableAcceptedStore":true,"predecessorRetentionStorePreserved":true,"storeQualifiedCleanupRegistered":true},
    nativeLocalRulePairs: localPairsProof(),
    nativeAdcsCapacity: adcsCapacityProof(), nativeAlgorithmBoundaries: algorithmProof(), nativeCmcBoundaries: cmcProof(),
    nativeForeignSpkiCandidate: foreignSpkiProof(),
    nativeUncertainOperatorAmbiguity: operatorAmbiguityProof(),
    nativePublicForeignSpki: require("./fixtures/certops-adcs-public-foreign-spki.cjs").proof(),
    nativeRequiredTemplateAttributes: require("./fixtures/certops-adcs-template-required-attributes.cjs").proof(),
    nativeLiveEnrollAcl: require("./fixtures/certops-adcs-live-enroll-acl.cjs").proof(),
    nativeHttpOnlyLeafCrl: require("./fixtures/certops-adcs-http-leaf-crl.cjs").proof(),
    nativeAdcsResultOutbox: require("./fixtures/certops-adcs-result-outbox.cjs").proof(),
    nativeOcspResponder: require("./fixtures/certops-adcs-ocsp.cjs").proof(),
    nativeOcspRevoked: require("./fixtures/certops-adcs-ocsp-revoked.cjs").proof(),
    nativeBrowserAdminBoundary: {"scope":"public-manager-viewer-adcs-admin-boundary-not-mounted-admin-withdrawal","enrollmentId":"11111111-1111-1111-1111-111111111111","forbiddenMutations":4,"roleChanges":2,"adminDemotions":0,"mountedAdminWithdrawalQualified":false,"distinctOwnedNonownerActors":true,"noGlobalAdminBypassAssumed":true,"publicManagerViewerManagerTransitions":true,"managerAndViewerUiDenied":true,"bothRolesReconcileAndAbandonForbidden":true,"publicOwnerAdminPatchDemotionRefused":true,"exactOwnerAdminUnchanged":true,"actualUncertainEnrollmentAndJobsUnchanged":true,"nativeCaAndUnacceptedKeyUnchanged":true,"servingNativeCustodyAndTrustedTlsUnchanged":true,"targetCertOpsAuditUnchanged":true,"exactMembershipAudits":true,"managerMembershipRestored":true,"browserAndTrustDrained":true},
    nativeBrowserReconcile: browserReconcileProof(),
    nativeIssuedSanBoundary: issuedSanProof(),
    nativeIssuedRevocation: issuedRevocationProof(),
    nativeCancelledLateApproval: cancelledLateApprovalProof(),
    nativeSameCertificateLateApproval:sameCertificateLateApprovalProof(),
    nativePendingCaRenewal: pendingCaProof(),
    nativePendingCaKeyChange: require("./fixtures/certops-adcs-pending-ca-key-change.cjs").proof(),
    nativeBrowserJobApproval:browserJobApprovalProof(),
    nativeBrowserCancel: browserCancelProof(),
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
  for(const key of Object.keys(pendingCaProof())){
    const missing=structuredClone(value);delete missing.report.nativePendingCaRenewal[key];assert.ok(verifyMatrix([missing],options).length,`pending CA missing ${key}`);
    const wrong=structuredClone(value);wrong.report.nativePendingCaRenewal[key]=typeof wrong.report.nativePendingCaRenewal[key]==="boolean"?!wrong.report.nativePendingCaRenewal[key]:"invalid";assert.ok(verifyMatrix([wrong],options).length,`pending CA invalid ${key}`);
  }
  for(const patch of [{requestId:"4294967296"},{caCertificateCountAfter:17},{caCertificateCountAfter:1},{caCertificateCountBefore:true},{continuationJobId:pendingCaProof().originalJobId},{leafFingerprint:pendingCaProof().predecessorFingerprint},{schedulerClock:"default-real-now"},{backgroundWorkerIntervalQualified:true},{rawJournal:"private"},{predecessorFingerprint:"f".repeat(64)}]){const invalid=structuredClone(value);Object.assign(invalid.report.nativePendingCaRenewal,patch);assert.ok(verifyMatrix([invalid],options).length);}
  const pendingNewKey = require("./fixtures/certops-adcs-pending-ca-key-change.cjs").proof();
  for (const key of Object.keys(pendingNewKey)) { const missing=structuredClone(value);delete missing.report.nativePendingCaKeyChange[key];assert.ok(verifyMatrix([missing],options).length); }
  for (const patch of [{freshRequestId:pendingNewKey.oldRequestId},{freshEnrollmentId:pendingNewKey.oldEnrollmentId},{newCaKeySha256:pendingNewKey.oldCaKeySha256},{freshSnapshotSha256:pendingNewKey.oldSnapshotSha256},{subjectCountAfter:9},{predecessorFingerprint:"f".repeat(64)},{oldCaKeySha256:"f".repeat(64)},{privateExtra:"sentinel"}]) {const wrong=structuredClone(value);Object.assign(wrong.report.nativePendingCaKeyChange,patch);assert.ok(verifyMatrix([wrong],options).length);}
  const absentNewKey=structuredClone(value);delete absentNewKey.report.nativePendingCaKeyChange;assert.ok(verifyMatrix([absentNewKey],options).length);
  const publicForeign = require("./fixtures/certops-adcs-public-foreign-spki.cjs").proof();
  for (const key of Object.keys(publicForeign)) { const missing=structuredClone(value);delete missing.report.nativePublicForeignSpki[key];assert.ok(verifyMatrix([missing],options).length); }
  for (const patch of [{foreignRequestId:"101"},{failedJobId:operatorAmbiguityProof().jobIds[1]},{selectedFingerprint:"f".repeat(64)},{originalSpkiSha256:"f".repeat(64)},{reconcileSearchFrom:99},{foreignSubjectRequestCount:2},{privateExtra:"sentinel"}]) { const wrong=structuredClone(value);Object.assign(wrong.report.nativePublicForeignSpki,patch);assert.ok(verifyMatrix([wrong],options).length); }
  const httpLeaf=require("./fixtures/certops-adcs-http-leaf-crl.cjs").proof();
  const ocsp=require("./fixtures/certops-adcs-ocsp.cjs").proof();
  for(const key of Object.keys(ocsp)){const missing=structuredClone(value);delete missing.report.nativeOcspResponder[key];assert.ok(verifyMatrix([missing],options).length);}
  for(const patch of [{nativeValidUnknownValid:false},{caRequestCounts:[39,40,42,43]},{installedAgentFaultRecoveryQualified:false},{authoritativeRevokedStatusQualified:true},{privateReceipt:"sentinel"}]){const wrong=structuredClone(value);Object.assign(wrong.report.nativeOcspResponder,patch);assert.ok(verifyMatrix([wrong],options).length);}
  for(const patch of [{requestId:42},{continuationJobId:"44444444-4444-4444-8444-444444444444"},{originalJobId:"33333333-3333-4333-8333-333333333333"},{originalClaimId:"77777777-7777-4777-8777-777777777777"},{rawContainer:"private"}]){const wrong=structuredClone(value);Object.assign(wrong.report.nativeOcspResponder.deferredRecovery,patch);assert.ok(verifyMatrix([wrong],options).length);}
  const absentOcsp=structuredClone(value);delete absentOcsp.report.nativeOcspResponder;assert.ok(verifyMatrix([absentOcsp],options).length);
  const revoked=require("./fixtures/certops-adcs-ocsp-revoked.cjs").proof();
  for(const key of Object.keys(revoked)){const missing=structuredClone(value);delete missing.report.nativeOcspRevoked[key];assert.ok(verifyMatrix([missing],options).length,`revoked OCSP missing ${key}`);}
  const absentRevoked=structuredClone(value);delete absentRevoked.report.nativeOcspRevoked;assert.ok(verifyMatrix([absentRevoked],options).length);
  const outbox=require("./fixtures/certops-adcs-result-outbox.cjs").proof();
  const absentOutbox=structuredClone(value);delete absentOutbox.report.nativeAdcsResultOutbox;assert.ok(verifyMatrix([absentOutbox],options).length);
  for(const key of Object.keys(outbox)){const missing=structuredClone(value);delete missing.report.nativeAdcsResultOutbox[key];assert.ok(verifyMatrix([missing],options).length);}
  for(const patch of [{sameLeafKeyAndCaRequestAfterRestart:false},{caRequestCounts:[10,11,12]},{retryDelayMs:1},{backgroundTimerQualified:true},{atomicTreeContainmentQualified:true},{privateCredential:"sentinel"}]){const wrong=structuredClone(value);Object.assign(wrong.report.nativeAdcsResultOutbox,patch);assert.ok(verifyMatrix([wrong],options).length);}
  const absentHttpLeaf=structuredClone(value);delete absentHttpLeaf.report.nativeHttpOnlyLeafCrl;assert.ok(verifyMatrix([absentHttpLeaf],options).length);
  for(const key of Object.keys(httpLeaf)){const missing=structuredClone(value);delete missing.report.nativeHttpOnlyLeafCrl[key];assert.ok(verifyMatrix([missing],options).length);}
  for(const patch of [{actualOwnedHttp503:false},{caRequestCounts:[10,11,13]},{installedAgentFaultRecoveryQualified:false},{restoredRequestId:42},{privateReceipt:"sentinel"}]){const wrong=structuredClone(value);Object.assign(wrong.report.nativeHttpOnlyLeafCrl,patch);assert.ok(verifyMatrix([wrong],options).length);}
  const liveAcl=require("./fixtures/certops-adcs-live-enroll-acl.cjs").proof();
  for(const key of Object.keys(liveAcl)){const wrong=structuredClone(value);delete wrong.report.nativeLiveEnrollAcl[key];assert.ok(verifyMatrix([wrong],options).length);}
  for(const patch of [{exactDaclRestored:false},{restoredDaclSha256:"e".repeat(64)},{caRequestCounts:[10,11,13]},{deniedCaRequestDelta:2},{signedCmcRenewalQualified:true},{rawDacl:"private"}]){const wrong=structuredClone(value);Object.assign(wrong.report.nativeLiveEnrollAcl,patch);assert.ok(verifyMatrix([wrong],options).length);}
  const requiredAttrs=require("./fixtures/certops-adcs-template-required-attributes.cjs").proof();
  for(const key of Object.keys(requiredAttrs)){const wrong=structuredClone(value);delete wrong.report.nativeRequiredTemplateAttributes[key];assert.ok(verifyMatrix([wrong],options).length);}
  for(const mutate of [v=>v.cases.pop(),v=>v.cases.reverse(),v=>v.cases[0].observedValue=false,v=>v.cases[1].observedValue=0,v=>v.cases[0].exactOriginalAttributesRestored=false,v=>v.cases[0].preflightVerdict="unsafe",v=>v.cases[1].jobId=v.cases[0].jobId,v=>v.privateReceipt="sentinel"]){const wrong=structuredClone(value);mutate(wrong.report.nativeRequiredTemplateAttributes);assert.ok(verifyMatrix([wrong],options).length);}
  const absentPending=structuredClone(value);delete absentPending.report.nativePendingCaRenewal;assert.ok(verifyMatrix([absentPending],options).length);
  const hierarchy = structuredClone(value), hierarchyOptions = structuredClone(options), hierarchySuite = "enterprise-adcs-hierarchy-real";
  delete hierarchy.report.nativePendingCaRenewal; // Root CA mutation is explicitly outside subordinate hierarchy scope.
  hierarchy.suite = hierarchy.report.suite = hierarchyOptions.specification.slots[0].suite = hierarchySuite;
  hierarchy.report.nativeHttpIntermediateCrl=require("./fixtures/certops-adcs-http-crl.cjs").proof();
  for(const key of Object.keys(hierarchy.report.nativeHttpIntermediateCrl)){const missing=structuredClone(hierarchy);delete missing.report.nativeHttpIntermediateCrl[key];assert.ok(verifyMatrix([missing],hierarchyOptions).length);}
  hierarchy.report.requiredScenarios = contract.suites[hierarchySuite]; hierarchy.report.scenarios = contract.suites[hierarchySuite].map(id => ({ ...value.report.scenarios[0], id }));
  assert.deepEqual(verifyMatrix([hierarchy], hierarchyOptions), []);
  for(const key of Object.keys(hierarchy.report.nativeHttpIntermediateCrl)){const missing=structuredClone(hierarchy);delete missing.report.nativeHttpIntermediateCrl[key];assert.ok(verifyMatrix([missing],hierarchyOptions).length);}
  for (const [base, settings] of [[value, options], [hierarchy, hierarchyOptions]]) {
    const missing = structuredClone(base); delete missing.report.nativeUncertainOperatorAmbiguity;
    assert.ok(verifyMatrix([missing], settings).length);
    for (const id of require("../tests/e2e/helpers/certops-adcs-uncertain-operator-ambiguity").REQUIRED_SCENARIOS) {
      const absent = structuredClone(base); absent.report.scenarios = absent.report.scenarios.filter(item => item.id !== id);
      assert.ok(verifyMatrix([absent], settings).length, id);
    }
  }
  for (const [key, prior] of Object.entries(operatorAmbiguityProof())) {
    const missing = structuredClone(value); delete missing.report.nativeUncertainOperatorAmbiguity[key]; assert.ok(verifyMatrix([missing], options).length, key);
    const invalids = prior === true ? [false, null, 1, "true"] : [Array.isArray(prior) ? prior.map(() => prior[0]) : typeof prior === "number" ? false : "invalid"];
    for (const invalid of invalids) { const bad = structuredClone(value); bad.report.nativeUncertainOperatorAmbiguity[key] = invalid; assert.ok(verifyMatrix([bad], options).length, key); }
  }
  for (const patch of [{ fixtureOrigin: "lost-submit-response" }, { scope: "deterministic-response-loss-qualified" }, { caRequestsAtFault: 1 }, { caRequestsAfterExplicitRecovery: 3 }, { actualLeaseWaitMs: 60000 }, { actualLeaseWaitMs: 152000 }, { reconcileSearchFrom: 86 }, { scanWindowSize: 64 }, { selectedRequestId: "103" }, { unusedRequestId: "101" }, { containerName: "tokentimer-enr-55555555-5555-5555-5555-555555555555" }, { jobIds: ["AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "44444444-4444-4444-4444-444444444444"] }, { deterministicResponseLossQualified: true }]) {
    const bad = structuredClone(value); Object.assign(bad.report.nativeUncertainOperatorAmbiguity, patch); assert.ok(verifyMatrix([bad], options).length);
  }
  {
    const supporting = "tests/e2e/helpers/certops-adcs-uncertain-operator-ambiguity.js", bound = structuredClone(value), settings = structuredClone(options);
    settings.specification.slots[0].requiredSources = [supporting];
    bound.report.fixtureSources = [{ file: supporting, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, supporting))).digest("hex") }];
    assert.deepEqual(verifyMatrix([bound], settings), []);
    bound.report.fixtureSources[0].sha256 = "0".repeat(64); assert.ok(verifyMatrix([bound], settings).length);
  }
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
  for(const flag of require("../tests/e2e/helpers/certops-adcs-native-reconcile").foreignFlags){for(const invalid of [false,1,null,"true"]){const bad=structuredClone(value);bad.report.nativeForeignSpkiCandidate[flag]=invalid;assert.ok(verifyMatrix([bad],options).length,flag);}const missing=structuredClone(value);delete missing.report.nativeForeignSpkiCandidate[flag];assert.ok(verifyMatrix([missing],options).length,flag);}
  for(const change of [{scope:"public-uncertain-recovery"},{requestIds:["17","17"]},{requestIds:["17","4294967296"]},{spkiFingerprints:["a".repeat(64),"a".repeat(64)]},{installedCertificate:true}]){const bad=structuredClone(value);Object.assign(bad.report.nativeForeignSpkiCandidate,change);assert.ok(verifyMatrix([bad],options).length);}
  {const bad=structuredClone(value);delete bad.report.nativeForeignSpkiCandidate;assert.ok(verifyMatrix([bad],options).length);}
  for(const flag of require("../tests/e2e/helpers/certops-adcs-local-rules").pairFlags){
    for(const wrong of [false,1,null,"true"]){const bad=structuredClone(value);bad.report.nativeLocalRulePairs[0][flag]=wrong;assert.ok(verifyMatrix([bad],options).length,flag);}
    const missing=structuredClone(value);delete missing.report.nativeLocalRulePairs[0][flag];assert.ok(verifyMatrix([missing],options).length,flag);
  }
  for(const rows of [undefined,[],[localPairsProof()[0],localPairsProof()[0],localPairsProof()[2]],localPairsProof().map(row=>({...row,rawKey:"private"}))]){const bad=structuredClone(value);bad.report.nativeLocalRulePairs=rows;assert.ok(verifyMatrix([bad],options).length);}
  for(const key of Object.keys(value.report.nativeAdcsBackgroundRenewals)) {
    const missing=structuredClone(value);delete missing.report.nativeAdcsBackgroundRenewals[key];assert.ok(verifyMatrix([missing],options).length,key);
  }
  for(const [key,bad] of Object.entries({failed:true,ticks:1,finishes:1,created:3,stops:0,forwarded:false,firstTickElapsedMs:59999,exitCode:1,nativeDrained:false,bridgeReady:false})) {
    const invalid=structuredClone(value);invalid.report.nativeAdcsBackgroundRenewals.workerLifecycle[key]=bad;assert.ok(verifyMatrix([invalid],options).length,key);
  }
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
  const requiredSources = [...new Set([...require("../tests/e2e/helpers/certops-adcs-pending-ca-renewal").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-adcs-browser-job-approval").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-adcs-issued-revocation").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-adcs-issued-san-boundary").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-adcs-browser-admin-boundary").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-adcs-browser-cancel").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-adcs-browser-reconcile").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-adcs-browser-abandon").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-adcs-capacity").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-adcs-webhosting-renewal").REQUIRED_SOURCES,...require("../tests/e2e/helpers/certops-adcs-uncertain-abandon").REQUIRED_SOURCES, ...require("../tests/e2e/helpers/certops-adcs-two-renewals").REQUIRED_SOURCES, ...require("../tests/e2e/helpers/certops-adcs-browser-journey").REQUIRED_SOURCES])];
  for(const key of ["nativeAlgorithmBoundaries","nativeCmcBoundaries","nativeWebHostingRenewal","nativeAdcsCapacity","nativeBrowserAbandon","nativeBrowserAdminBoundary","nativeBrowserReconcile","nativeBrowserCancel","nativeIssuedSanBoundary","nativeIssuedRevocation"]){const missing=structuredClone(value);delete missing.report[key];assert.ok(verifyMatrix([missing],options).length,key);}
  for(const key of Object.keys(value.report.nativeBrowserCancel)){const missing=structuredClone(value);delete missing.report.nativeBrowserCancel[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeBrowserCancel[key]=typeof bad.report.nativeBrowserCancel[key]==="boolean"?!bad.report.nativeBrowserCancel[key]:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
  for(const patch of [{cancelPosts:true},{otherMutations:false},{priorRequestId:"4294967296"},{priorRequestId:"17"},{fingerprint:"a".repeat(64)},{priorEnrollmentId:"55555555-5555-5555-5555-555555555555"},{initialSixConcurrencyQualified:true},{caSubmissionCancellationQualified:true},{rawTrace:"sentinel"}]){const bad=structuredClone(value);Object.assign(bad.report.nativeBrowserCancel,patch);assert.ok(verifyMatrix([bad],options).length);}
  for(const key of Object.keys(value.report.nativeSameCertificateLateApproval)){const missing=structuredClone(value);delete missing.report.nativeSameCertificateLateApproval[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeSameCertificateLateApproval[key]=typeof bad.report.nativeSameCertificateLateApproval[key]==="boolean"?!bad.report.nativeSameCertificateLateApproval[key]:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
  {const bad=structuredClone(value);delete bad.report.nativeSameCertificateLateApproval;assert.ok(verifyMatrix([bad],options).length);}
  for(const patch of [{requestIds:["17","4294967296"]},{scope:"real-cancelled-request-late-issued-after-distinct-same-endpoint-successor"},{backgroundTimerQualified:true},{rawCsr:"private"}]){const bad=structuredClone(value);Object.assign(bad.report.nativeSameCertificateLateApproval,patch);assert.ok(verifyMatrix([bad],options).length);}
  {const helper=require("../tests/e2e/helpers/certops-adcs-same-certificate-late-approval"),sourced=structuredClone(value),sourceOptions=structuredClone(options);sourceOptions.specification.slots[0].requiredSources=[...helper.REQUIRED_SOURCES];sourced.report.fixtureSources=helper.REQUIRED_SOURCES.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));assert.deepEqual(verifyMatrix([sourced],sourceOptions),[]);for(const file of helper.REQUIRED_SOURCES){for(const mutate of [v=>{v.report.fixtureSources=v.report.fixtureSources.filter(row=>row.file!==file)},v=>{v.report.fixtureSources.find(row=>row.file===file).sha256="0".repeat(64)}]){const bad=structuredClone(sourced);mutate(bad);assert.ok(verifyMatrix([bad],sourceOptions).length,file);}}}
  for(const key of Object.keys(value.report.nativeCancelledLateApproval)){const missing=structuredClone(value);delete missing.report.nativeCancelledLateApproval[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeCancelledLateApproval[key]=typeof bad.report.nativeCancelledLateApproval[key]==="boolean"?!bad.report.nativeCancelledLateApproval[key]:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
  for(const patch of [{requestIds:["17","4294967296"]},{requestIds:["17","17"]},{fingerprints:["a".repeat(64),"a".repeat(64)]},{cancelledEnrollmentId:value.report.nativeCancelledLateApproval.successorEnrollmentId},{sameCertificateRenewalQualified:true},{rawCsr:"private"}]){const bad=structuredClone(value);Object.assign(bad.report.nativeCancelledLateApproval,patch);assert.ok(verifyMatrix([bad],options).length);}
  {const bad=structuredClone(value);delete bad.report.nativeCancelledLateApproval;assert.ok(verifyMatrix([bad],options).length);}
  for(const id of require("../tests/e2e/helpers/certops-adcs-cancelled-late-approval").REQUIRED_SCENARIOS){const bad=structuredClone(value);bad.report.scenarios=bad.report.scenarios.filter(row=>row.id!==id);assert.ok(verifyMatrix([bad],options).length,id);}
  {const helper=require("../tests/e2e/helpers/certops-adcs-cancelled-late-approval"),sourced=structuredClone(value),sourceOptions=structuredClone(options);sourceOptions.specification.slots[0].requiredSources=[...helper.REQUIRED_SOURCES];sourced.report.fixtureSources=helper.REQUIRED_SOURCES.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));assert.deepEqual(verifyMatrix([sourced],sourceOptions),[]);for(const file of helper.REQUIRED_SOURCES){for(const mutate of [v=>{v.report.fixtureSources=v.report.fixtureSources.filter(row=>row.file!==file)},v=>{v.report.fixtureSources.find(row=>row.file===file).sha256="0".repeat(64)}]){const bad=structuredClone(sourced);mutate(bad);assert.ok(verifyMatrix([bad],sourceOptions).length,file);}}}
  for(const key of Object.keys(value.report.nativeIssuedRevocation)){const missing=structuredClone(value);delete missing.report.nativeIssuedRevocation[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeIssuedRevocation[key]=typeof bad.report.nativeIssuedRevocation[key]==="boolean"?!bad.report.nativeIssuedRevocation[key]:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
  for(const patch of [{requestId:"4294967296"},{requestId:17},{schedulerDefaultClockQualified:0},{privateKey:"sentinel"}]){const bad=structuredClone(value);Object.assign(bad.report.nativeIssuedRevocation,patch);assert.ok(verifyMatrix([bad],options).length);}
  for(const key of Object.keys(value.report.nativeIssuedSanBoundary)){const missing=structuredClone(value);delete missing.report.nativeIssuedSanBoundary[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeIssuedSanBoundary[key]=typeof bad.report.nativeIssuedSanBoundary[key]==="boolean"?false:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
  for(const patch of [{requestId:"4294967296"},{requestId:17},{errorCode:"ADCS_CA_KEY_CHANGED"},{privateKey:"sentinel"}]){const bad=structuredClone(value);Object.assign(bad.report.nativeIssuedSanBoundary,patch);assert.ok(verifyMatrix([bad],options).length);}
  for(const key of Object.keys(value.report.nativeBrowserReconcile)){const missing=structuredClone(value);delete missing.report.nativeBrowserReconcile[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeBrowserReconcile[key]=typeof bad.report.nativeBrowserReconcile[key]==="boolean"?false:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
  for(const patch of [{reconcilePosts:true},{invalidRequestPosts:false},{selectedRequestId:"4294967296"},{unusedRequestId:"101"},{selectedFingerprint:"a".repeat(64)},{continuationJobId:"55555555-5555-5555-5555-555555555555"},{enrollmentId:"55555555-5555-5555-5555-555555555555"},{rawTrace:"sentinel"}]){const bad=structuredClone(value);Object.assign(bad.report.nativeBrowserReconcile,patch);assert.ok(verifyMatrix([bad],options).length);}
  for(const key of Object.keys(value.report.nativeBrowserJobApproval)){const missing=structuredClone(value);delete missing.report.nativeBrowserJobApproval[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeBrowserJobApproval[key]=typeof bad.report.nativeBrowserJobApproval[key]==="boolean"?!bad.report.nativeBrowserJobApproval[key]:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
  for(const patch of [{approvePosts:true},{rejectPosts:true},{cancelPosts:false},{requestIds:["17","4294967296"]},{jobIds:["44444444-4444-4444-4444-444444444444","33333333-3333-3333-3333-333333333333"]},{rejectedJobId:"33333333-3333-3333-3333-333333333333"},{rawApprovalPayload:"sentinel"}]){const bad=structuredClone(value);Object.assign(bad.report.nativeBrowserJobApproval,patch);assert.ok(verifyMatrix([bad],options).length);}
  for(const key of Object.keys(value.report.nativeBrowserAdminBoundary)){const missing=structuredClone(value);delete missing.report.nativeBrowserAdminBoundary[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeBrowserAdminBoundary[key]=typeof bad.report.nativeBrowserAdminBoundary[key]==="boolean"?!bad.report.nativeBrowserAdminBoundary[key]:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
  for(const key of Object.keys(value.report.nativeBrowserAbandon)){const missing=structuredClone(value);delete missing.report.nativeBrowserAbandon[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeBrowserAbandon[key]=typeof bad.report.nativeBrowserAbandon[key]==="boolean"?false:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
  for(const key of Object.keys(value.report.nativeAdcsCapacity)){const missing=structuredClone(value);delete missing.report.nativeAdcsCapacity[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeAdcsCapacity[key]=typeof bad.report.nativeAdcsCapacity[key]==="boolean"?false:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
  for(const field of ["requestIds","fingerprints","enrollmentIds","jobIds"]){const bad=structuredClone(value);bad.report.nativeAdcsCapacity[field][1]=bad.report.nativeAdcsCapacity[field][0];assert.ok(verifyMatrix([bad],options).length,field);}
  for(const key of Object.keys(value.report.nativeWebHostingRenewal)){const missing=structuredClone(value);delete missing.report.nativeWebHostingRenewal[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeWebHostingRenewal[key]=typeof bad.report.nativeWebHostingRenewal[key]==="boolean"?!bad.report.nativeWebHostingRenewal[key]:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
  for(const flag of require("../tests/e2e/helpers/certops-adcs-algorithm-boundaries").FLAGS)for(const wrong of [false,1,null,"true"]){const bad=structuredClone(value);bad.report.nativeAlgorithmBoundaries[0][flag]=wrong;assert.ok(verifyMatrix([bad],options).length,flag);}
  for(const flag of require("../tests/e2e/helpers/certops-adcs-cmc-signature-copy").flags)for(const wrong of [false,1,null,"true"]){const bad=structuredClone(value);bad.report.nativeCmcBoundaries[flag]=wrong;assert.ok(verifyMatrix([bad],options).length,flag);}
  for(const mutate of [item=>item.nativeAlgorithmBoundaries.pop(),item=>item.nativeAlgorithmBoundaries[1].positiveRequestId=item.nativeAlgorithmBoundaries[0].positiveRequestId,item=>item.nativeAlgorithmBoundaries[1].positiveFingerprintSha256=item.nativeAlgorithmBoundaries[0].positiveFingerprintSha256,item=>item.nativeAlgorithmBoundaries[0].positiveScenario="unexecuted",item=>item.nativeCmcBoundaries.refusedVariants.pop(),item=>item.nativeCmcBoundaries.syntheticCaResponse=true,item=>item.nativeCmcBoundaries.tamperedResponseDerSha256=item.nativeCmcBoundaries.originalResponseDerSha256,item=>item.nativeCmcBoundaries.rawPrivate="unexpected"]){const bad=structuredClone(value);mutate(bad.report);assert.ok(verifyMatrix([bad],options).length);}
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
test("release supporting sources enforce reviewed 256-item cap, unique identities and repository bounds",()=>{
 const declared=[...new Set(require("../docs/certops/release-qualification-matrix.json").slots.flatMap(slot=>[slot.source,...(slot.requiredSources||[])]))];assert.ok(declared.length>=257);
 const records=declared.slice(0,257).map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));
 const value=artifact(),spec=structuredClone(specification),options={candidateSha,specification:spec};value.report.fixtureSources=records.slice(0,256);spec.slots[0].requiredSources=records.slice(0,96).map(row=>row.file);assert.deepEqual(verifyMatrix([value],options),[]);
 for(const count of [97,128,129,192,256]){const good=structuredClone(value),specification=structuredClone(spec);good.report.fixtureSources=records.slice(0,count);specification.slots[0].requiredSources=records.slice(0,count).map(row=>row.file);assert.deepEqual(verifyMatrix([good],{candidateSha,specification}),[]);}
 for(const rows of [records,[records[0],records[0]],[{file:"../outside.js",sha256:"a".repeat(64)}],[{file:"C:\\outside.js",sha256:"a".repeat(64)}]]){const bad=structuredClone(value);bad.report.fixtureSources=rows;assert.ok(verifyMatrix([bad],options).length);}
 const oversized=structuredClone(spec);oversized.slots[0].requiredSources=records.map(row=>row.file);assert.ok(validateMatrix(oversized).some(error=>error.includes("invalid supporting source")));
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
  const reuse=require("../tests/e2e/helpers/certops-windows-key-reuse-refusal");events.at(-1).nativeWindowsKeyReuseRefusal={scope:"public-windows-acme-profile-reuse-refusal",...Object.fromEntries(reuse.fields.map(field=>[field,true]))};
  events.at(-1).nativeInstalledCrash={"scope": "installed-system-native-handle-crash-fixture-lease-recovery", "retainedNativeHandles": true, "freshIdentityReverified": true, "capturedHandlesExited": true, "capturedLineageAbsent": true, "fixtureCommandPathsAbsent": true, "fixtureAdjustedLeaseRecovery": true, "unresolvedAttemptNotReplayed": true, "startupOrphanKeyRemoved": true, "priorTrustedTlsPreserved": true, "atomicTreeContainmentQualified": false, "productionLeaseGraceQualified": false};
  events.at(-1).nativeInstalledIisRefusal={"scope":"installed-agent-public-standalone-iis-deploy-refusal","jobId":"11111111-1111-1111-1111-111111111111","claimId":"22222222-2222-2222-2222-222222222222","genuinePriorIssuance":true,"publicDeployAdmitted":true,"sameInstalledAgentClaimedOnce":true,"specificUnsupportedTargetFailure":true,"claimBoundFailureAudit":true,"nativeInventoryAndCustodyUnchanged":true,"bothBindingsAndTrustedTlsUnchanged":true,"actualAcmeClientNotInvoked":true,"dnsTrafficUnchanged":true,"credentialAndPinUnchanged":true,"exactOwnedShadowRemoved":true};
  const installedPaths=require("../tests/e2e/helpers/certops-windows-installed-paths");events.at(-1).nativeInstalledPaths={scope:installedPaths.SCOPE,...Object.fromEntries(installedPaths.FLAGS.map(flag=>[flag,true]))};
  const multiAdmission=require("../tests/e2e/helpers/certops-windows-multi-target-admission-refusal");events.at(-1).nativeWindowsMultiTargetAdmission={scope:multiAdmission.SCOPE,profilePatchStatus:422,renewOverrideStatus:400,signedJobExecutionQualified:false,multiTargetDeploymentQualified:false,...Object.fromEntries(multiAdmission.FLAGS.map(flag=>[flag,true]))};
  events.at(-1).nativeInstalledVerifyRollback=require("./fixtures/certops-windows-installed-verify-rollback.cjs").fixture();
  events.at(-1).nativeInstalledSigningPinRefusal=require("./fixtures/certops-windows-signing-pin-refusal.cjs").fixture();
  const activeScm=require("../tests/e2e/helpers/certops-windows-active-service-controls");events.at(-1).nativeInstalledActiveServiceControls={scope:activeScm.SCOPE,controlCount:3,certificateOperationInterruptionQualified:false,defaultLeaseGraceQualified:false,...Object.fromEntries(activeScm.FLAGS.map(flag=>[flag,true]))};
  const scm=require("../tests/e2e/helpers/certops-windows-service-controls");events.at(-1).nativeInstalledServiceControls={scope:scm.SCOPE,controlCount:3,certificateOperationInterruptionQualified:false,...Object.fromEntries(scm.FLAGS.map(flag=>[flag,true]))};
  events.at(-1).nativeInstalledPublicRetirement={"scope":"public-idle-installed-windows-agent-retirement","inFlightRetirementQualified":false,"anonymousStatus":401,"viewerStatus":403,"managerStatus":200,"replayStatus":200,"retirementAuditCount":1,"noRespawnObservedMs":5000,"sameOwnedSystemRuntimeBeforeRetirement":true,"anonymousAndViewerRefused":true,"authorizedManagerPublicRetirement":true,"sameActorAppendOnlyAudit":true,"idempotentWithoutDuplicateAudit":true,"actualAuthenticatedRetirementExit86":true,"nativeScmCleanExitZero":true,"measuredNoRespawnWindow":true,"capturedHostAndChildAbsent":true,"nativeCustodyAndTrustedTlsPreserved":true,"credentialConfigurationAndPinPreserved":true,"noJobClaimMutation":true,"ownedRetirementGuardCleared":true};
  events.at(-1).nativeInstalledRetentionConfig={"scope":"installed-system-invalid-retention-policy-startup-refusal","policies":["below-minimum-hours","above-maximum-hours","zero-sweep-interval"],"startupFailureCount":3,"retentionTimerQualified":false,"threeActualSystemValidationFailures":true,"freshStoppedServiceForEach":true,"credentialAndPinPreserved":true,"nativeCngAndBindingPreserved":true,"trustedTlsPreserved":true,"noNewAgentOrJob":true,"exactOriginalConfigurationRestored":true,"actualRepairedSystemChild":true,"freshAuthenticatedHeartbeat":true,"ownedPolicyGuardCleared":true};
  events.at(-1).nativeInstalledCredentialRefusal={"scope":"installed-system-invalid-credential-startup-refusal","credentials":["empty-credential","malformed-credential"],"startupFailureCount":2,"inFlightMutationQualified":false,"twoActualSystemCredentialFailures":true,"freshStoppedServiceForEach":true,"configurationAndPinPreserved":true,"nativeCngAndBindingPreserved":true,"trustedTlsPreserved":true,"noNewAgentOrJob":true,"exactOriginalCredentialRestored":true,"actualRepairedSystemChild":true,"freshAuthenticatedHeartbeat":true,"ownedCredentialGuardCleared":true};
  const encoding=require("../tests/e2e/helpers/certops-windows-config-encoding");events.at(-1).nativeInstalledConfigEncoding={scope:encoding.SCOPE,encodings:[...encoding.CASES],startupFailureCount:3,...Object.fromEntries(encoding.FLAGS.map(flag=>[flag,true]))};
  const handoff=require("../tests/e2e/helpers/certops-windows-installed-handoff");events.at(-1).nativeInstalledStateHandoff={scope:handoff.SCOPE,...Object.fromEntries(handoff.FLAGS.map(flag=>[flag,true]))};
  assert.deepEqual(verifyMatrix([value], options), []);
  for(const nativeSlot of require("../docs/certops/release-qualification-matrix.json").slots.filter(row=>row.suite.startsWith("real-agent-windows-acme-iis/"))){
    const sample=structuredClone(value);sample.suite=nativeSlot.suite;sample.environment={...nativeSlot.environment,measurement:"native"};
    // Each environment fixture binds its own declared inventory; do not reuse a
    // different profile slot's source set when their prerequisites diverge.
    const nativeSources=nativeSlot.requiredSources.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));
    for(const event of sample.events){event.scope=nativeSlot.suite;event.qualificationEnvironment=sample.environment;event.fixtureSources=structuredClone(nativeSources);}
    assert.deepEqual(verifyMatrix([sample],{candidateSha,specification:{schemaVersion:1,slots:[nativeSlot]}}),[],nativeSlot.id);
  }
  {const bad=structuredClone(value);bad.events[0].fixtureSources.find(row=>row.file===reuse.requiredSources[0]).sha256="0".repeat(64);assert.ok(verifyMatrix([bad],options).length);}
  // The helper's pure tests and Python parity cover every field. These cases
  // exercise release delegation without repeatedly hashing the whole archive.
  for(const mutate of [v=>delete v.nativeInstalledSigningPinRefusal,v=>v.nativeInstalledSigningPinRefusal.twoActualSystemPinFailures=false,v=>v.nativeInstalledSigningPinRefusal.missingPinQualified=true,v=>v.nativeInstalledSigningPinRefusal.pins=[],v=>v.nativeInstalledSigningPinRefusal.rawPin="private"]){const bad=structuredClone(value);mutate(bad.events.at(-1));assert.ok(verifyMatrix([bad],options).length);}
  const missingPinCase=structuredClone(value);missingPinCase.events=missingPinCase.events.filter(row=>row.name!==require("../tests/e2e/helpers/certops-windows-signing-pin-refusal").SCENARIO);assert.ok(verifyMatrix([missingPinCase],options).length);
  for(const mutate of [v=>delete v.nativeInstalledVerifyRollback,v=>v.nativeInstalledVerifyRollback.originalNativeSniAndTrustedTls=false,v=>v.nativeInstalledVerifyRollback.transientNewBindingObservationQualified=true,v=>v.nativeInstalledVerifyRollback.jobIds.reverse().fill(v.nativeInstalledVerifyRollback.jobIds[0]),v=>v.nativeInstalledVerifyRollback.privateNative="secret"]){const bad=structuredClone(value);mutate(bad.events.at(-1));assert.ok(verifyMatrix([bad],options).length);}
  const missingRollbackCase=structuredClone(value);missingRollbackCase.events=missingRollbackCase.events.filter(row=>row.name!==require("../tests/e2e/helpers/certops-windows-installed-verify-rollback").SCENARIO);assert.ok(verifyMatrix([missingRollbackCase],options).length);
  for(const mutate of [v=>delete v.nativeWindowsMultiTargetAdmission,v=>v.nativeWindowsMultiTargetAdmission.noJobAllocated=false,v=>v.nativeWindowsMultiTargetAdmission.signedJobExecutionQualified=true,v=>v.nativeWindowsMultiTargetAdmission.multiTargetDeploymentQualified=true,v=>v.nativeWindowsMultiTargetAdmission.privateNative="secret"]){const bad=structuredClone(value);mutate(bad.events.at(-1));assert.ok(verifyMatrix([bad],options).length);}
  for(const mutate of [v=>delete v.nativeInstalledActiveServiceControls,v=>v.nativeInstalledActiveServiceControls.actualDnsPostBarrier=false,v=>v.nativeInstalledActiveServiceControls.defaultLeaseGraceQualified=true,v=>v.nativeInstalledActiveServiceControls.certificateOperationInterruptionQualified=true,v=>v.nativeInstalledActiveServiceControls.privateNative="secret"]){const bad=structuredClone(value);mutate(bad.events.at(-1));assert.ok(verifyMatrix([bad],options).length);}
  for(const mutate of [v=>delete v.nativeInstalledServiceControls,v=>v.nativeInstalledServiceControls.interrogateSucceeded=false,v=>v.nativeInstalledServiceControls.scope="supporting-only"]){const bad=structuredClone(value);mutate(bad.events.at(-1));assert.ok(verifyMatrix([bad],options).length);}
  for(const patch of [{controlCount:2},{certificateOperationInterruptionQualified:true},{rawCommandLine:"private"}]){const bad=structuredClone(value);Object.assign(bad.events.at(-1).nativeInstalledServiceControls,patch);assert.ok(verifyMatrix([bad],options).length);}
  for(const mutate of [v=>delete v.nativeInstalledPublicRetirement,v=>v.nativeInstalledPublicRetirement.authorizedManagerPublicRetirement=false,v=>v.nativeInstalledPublicRetirement.inFlightRetirementQualified=true,v=>v.nativeInstalledPublicRetirement.noRespawnObservedMs=4999,v=>v.nativeInstalledPublicRetirement.privatePath="secret"]){const bad=structuredClone(value);mutate(bad.events.at(-1));assert.ok(verifyMatrix([bad],options).length);}
  for(const mutate of [v=>delete v.nativeInstalledRetentionConfig,v=>v.nativeInstalledRetentionConfig.threeActualSystemValidationFailures=false,v=>v.nativeInstalledRetentionConfig.retentionTimerQualified=true,v=>v.nativeInstalledRetentionConfig.policies=[],v=>v.nativeInstalledRetentionConfig.rawConfig="secret"]){const bad=structuredClone(value);mutate(bad.events.at(-1));assert.ok(verifyMatrix([bad],options).length);}
  for(const mutate of [v=>delete v.nativeInstalledCredentialRefusal,v=>v.nativeInstalledCredentialRefusal.twoActualSystemCredentialFailures=false,v=>v.nativeInstalledCredentialRefusal.inFlightMutationQualified=true,v=>v.nativeInstalledCredentialRefusal.credentials=[],v=>v.nativeInstalledCredentialRefusal.rawCredential="secret"]){const bad=structuredClone(value);mutate(bad.events.at(-1));assert.ok(verifyMatrix([bad],options).length);}
  for(const mutate of [v=>delete v.nativeInstalledConfigEncoding,v=>v.nativeInstalledConfigEncoding.freshStoppedServiceForEach=false,v=>v.nativeInstalledConfigEncoding.encodings=["utf8-bom"],v=>v.nativeInstalledConfigEncoding.rawConfig="private"]){const bad=structuredClone(value);mutate(bad.events.at(-1));assert.ok(verifyMatrix([bad],options).length);}
  const missingEncodingCase=structuredClone(value);missingEncodingCase.events=missingEncodingCase.events.filter(row=>row.name!==encoding.SCENARIO);assert.ok(verifyMatrix([missingEncodingCase],options).length);
  const missingScmCase=structuredClone(value);missingScmCase.events=missingScmCase.events.filter(row=>row.name!==scm.SCENARIO);assert.ok(verifyMatrix([missingScmCase],options).length);
  for(const field of ["scope",...installedPaths.FLAGS]){const bad=structuredClone(value);delete bad.events.at(-1).nativeInstalledPaths[field];assert.ok(verifyMatrix([bad],options).length);for(const wrong of [false,1,"true",null]){const invalid=structuredClone(value);invalid.events.at(-1).nativeInstalledPaths[field]=wrong;assert.ok(verifyMatrix([invalid],options).length);}}
  for(const change of [v=>delete v.nativeInstalledPaths,v=>v.nativeInstalledPaths.scope="historical-ascii-supporting",v=>v.nativeInstalledPaths.privateNativePath="private"]){const bad=structuredClone(value);change(bad.events.at(-1));assert.ok(verifyMatrix([bad],options).length);}
  for(const file of installedPaths.REQUIRED_SOURCES){const bad=structuredClone(value);bad.events[0].fixtureSources=bad.events[0].fixtureSources.filter(row=>row.file!==file);assert.ok(verifyMatrix([bad],options).length);const stale=structuredClone(value);stale.events[0].fixtureSources.find(row=>row.file===file).sha256="0".repeat(64);assert.ok(verifyMatrix([stale],options).length);}
  {const bad=structuredClone(value);bad.events=bad.events.filter(event=>event.name!==installedPaths.scenarioName);assert.ok(verifyMatrix([bad],options).length);}
  const crash=require("../tests/e2e/helpers/certops-windows-owned-process");
  for(const field of ['scope',...crash.PUBLIC_FLAGS,'atomicTreeContainmentQualified','productionLeaseGraceQualified']){const bad=structuredClone(value);delete bad.events.at(-1).nativeInstalledCrash[field];assert.ok(verifyMatrix([bad],options).length,field);const wrong=structuredClone(value);wrong.events.at(-1).nativeInstalledCrash[field]=field.endsWith('Qualified')?true:false;assert.ok(verifyMatrix([wrong],options).length,field);}
  for(const file of crash.REQUIRED_SOURCES){const missing=structuredClone(value);missing.events[0].fixtureSources=missing.events[0].fixtureSources.filter(row=>row.file!==file);assert.ok(verifyMatrix([missing],options).length);const stale=structuredClone(value);stale.events[0].fixtureSources.find(row=>row.file===file).sha256='0'.repeat(64);assert.ok(verifyMatrix([stale],options).length);}
  for(const field of ['rootPid','rootNativeCreatedTicks','commandPaths']){const bad=structuredClone(value);bad.events.at(-1).nativeInstalledCrash[field]='private';assert.ok(verifyMatrix([bad],options).length);}
  {const bad=structuredClone(value);bad.events=bad.events.filter(event=>event.name!==crash.scenarioName);assert.ok(verifyMatrix([bad],options).length);}
  const iisRefusal=require("../tests/e2e/helpers/certops-windows-installed-iis-refusal");
  for(const field of ["scope","jobId","claimId",...iisRefusal.FLAGS]){const missing=structuredClone(value);delete missing.events.at(-1).nativeInstalledIisRefusal[field];assert.ok(verifyMatrix([missing],options).length,field);const wrong=structuredClone(value);wrong.events.at(-1).nativeInstalledIisRefusal[field]=false;assert.ok(verifyMatrix([wrong],options).length,field);}
  for(const change of [r=>delete r.nativeInstalledIisRefusal,r=>r.nativeInstalledIisRefusal.scope="direct-executor-only",r=>r.nativeInstalledIisRefusal.privateCngContainer="private"]){const bad=structuredClone(value);change(bad.events.at(-1));assert.ok(verifyMatrix([bad],options).length);}
  for(const file of iisRefusal.REQUIRED_SOURCES){const bad=structuredClone(value);bad.events[0].fixtureSources=bad.events[0].fixtureSources.filter(row=>row.file!==file);assert.ok(verifyMatrix([bad],options).length,file);}
  {const bad=structuredClone(value);bad.events=bad.events.filter(event=>event.name!==iisRefusal.scenarioName);assert.ok(verifyMatrix([bad],options).length);}
  for(const field of reuse.fields){for(const wrong of [false,1,null,"true"]){const bad=structuredClone(value);bad.events.at(-1).nativeWindowsKeyReuseRefusal[field]=wrong;assert.ok(verifyMatrix([bad],options).length);}const missing=structuredClone(value);delete missing.events.at(-1).nativeWindowsKeyReuseRefusal[field];assert.ok(verifyMatrix([missing],options).length);}
  for(const change of [{scope:"installed-agent-invalid-signed-job"},{privateKey:"forbidden"}]){const bad=structuredClone(value);Object.assign(bad.events.at(-1).nativeWindowsKeyReuseRefusal,change);assert.ok(verifyMatrix([bad],options).length);}
  {const bad=structuredClone(value);delete bad.events.at(-1).nativeWindowsKeyReuseRefusal;assert.ok(verifyMatrix([bad],options).length);}
  {const bad=structuredClone(value);bad.events=bad.events.filter(event=>event.name!==reuse.scenarioName);assert.ok(verifyMatrix([bad],options).length);}
  for(const file of reuse.requiredSources){const bad=structuredClone(value);bad.events[0].fixtureSources=bad.events[0].fixtureSources.filter(row=>row.file!==file);assert.ok(verifyMatrix([bad],options).length,file);}
  for(const flag of handoff.FLAGS){for(const wrong of [false,1,null,"true"]){const bad=structuredClone(value);bad.events.at(-1).nativeInstalledStateHandoff[flag]=wrong;assert.ok(verifyMatrix([bad],options).length,flag);}const missing=structuredClone(value);delete missing.events.at(-1).nativeInstalledStateHandoff[flag];assert.ok(verifyMatrix([missing],options).length,flag);}
  for(const change of [{scope:"automatic-in-place-reregistration"},{oldAdcsJobsTransferred:true},{rawCredential:"private"}]){const bad=structuredClone(value);Object.assign(bad.events.at(-1).nativeInstalledStateHandoff,change);assert.ok(verifyMatrix([bad],options).length);}
  {const bad=structuredClone(value);delete bad.events.at(-1).nativeInstalledStateHandoff;assert.ok(verifyMatrix([bad],options).length);}
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
 const value=suiteArtifact(suite,slot.source,{nativeIisPublicOnly:require("./fixtures/certops-windows-iis-public-only.cjs").fixture(),nativeIpv4WildcardShadow:ipv4WildcardProof(),nativeIpv6WildcardShadow:ipv6WildcardProof(),nativeIpv6SniShadow:ipv6ShadowProof(),supportingConfiguredRetentionTimer:{"scope":"production-configured-real-timer-empty-ledger-supporting","configuredIntervalMs":100,"defaultIntervalMs":21600000,"defaultRetentionHours":168,"actualCallbacks":3,"actualDelayedCallbacks":2,"waitedMonotonicMs":200,"defaultSixHourElapsedQualified":false,"installedServiceQualified":false,"nativeDeletionQualified":false,"productionCollectorReturnedEmpty":true,"actualAbortDrained":true,"ownedEmptyStatePreserved":true},nativeCngJournalAcl: cngJournalAclProof(), nativeOrphanJournalProtection:orphanJournalProof(),nativeLedgerReadRefusals:ledgerReadProof(),nativeJournalReadRefusals:journalReadProof(),nativeCredentialWeakAcl:require("./fixtures/certops-windows-credential-weak-acl.cjs").fixture(),nativeStateReadRefusals:stateReadProof(),nativeRetentionReferences:retentionReferenceProof(),nativeKeyUsage:keyUsageProof(),nativeHttpSysClientSettings:httpClientSettingsProof(),nativePackagedChainRuntime:packagedChainRuntimeProof(),cngCustody:facts,nativeSamePortSni:sni,nativeEnrollmentContention:contention,nativeRetentionPolicyExpiry:policyExpiryProof(),nativeElapsedRetention:elapsedRetentionProof(),nativeKeySurvivors:Object.fromEntries(require("./certops-native-key-survivor-proof").FIELDS.map(field=>[field,true])),nativeRetentionAtomicReplace:Object.fromEntries(require("../packages/agent/scripts/host/retention-ledger-atomic-fixture").FIELDS.map(field=>[field,true]))});value.environment=value.report.qualificationEnvironment={...slot.environment,measurement:"native"};
 value.report.fixtureSources=slot.requiredSources.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));
 const options={candidateSha,specification:{schemaVersion:1,slots:[slot]}};assert.deepEqual(verifyMatrix([value],options),[]);
 const usageSource="packages/agent/scripts/host/cng-key-usage-proof.js",usageOptions=structuredClone(options),sourcedUsage=structuredClone(value);usageOptions.specification.slots[0].requiredSources=[...new Set([...slot.requiredSources,usageSource])];sourcedUsage.report.fixtureSources=sourcedUsage.report.fixtureSources.filter(row=>row.file!==usageSource);sourcedUsage.report.fixtureSources.push({file:usageSource,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,usageSource))).digest("hex")});assert.deepEqual(verifyMatrix([sourcedUsage],usageOptions),[]);
 const staleUsage=structuredClone(sourcedUsage);staleUsage.report.fixtureSources.find(row=>row.file===usageSource).sha256="0".repeat(64);assert.ok(verifyMatrix([staleUsage],usageOptions).length);const missingUsageSource=structuredClone(sourcedUsage);missingUsageSource.report.fixtureSources=missingUsageSource.report.fixtureSources.filter(row=>row.file!==usageSource);assert.ok(verifyMatrix([missingUsageSource],usageOptions).length);
 for(const nativeSlot of require("../docs/certops/release-qualification-matrix.json").slots.filter(row=>row.suite==="windows-host")){const good=structuredClone(value);good.environment=good.report.qualificationEnvironment={...nativeSlot.environment,measurement:"native"};assert.deepEqual(verifyMatrix([good],{candidateSha,specification:{schemaVersion:1,slots:[nativeSlot]}}),[],nativeSlot.id);}
 for(const field of Object.keys(packagedChainRuntimeProof())){const missing=structuredClone(value);delete missing.report.nativePackagedChainRuntime[field];assert.ok(verifyMatrix([missing],options).length,field);}
 for(const flag of require("../packages/agent/scripts/host/packaged-helper-runtime-fixture").FLAGS)for(const wrong of [false,1,null,"true"]){const bad=structuredClone(value);bad.report.nativePackagedChainRuntime[flag]=wrong;assert.ok(verifyMatrix([bad],options).length,flag);}
 for(const change of [{scope:"packaged-cmc-qualified"},{metadataOnly:false},{serviceInstalled:true},{cmcPackagedQualified:true},{nativeGoVerifierPackagedQualified:true},{architecture:"arm64"},{chainHelperSha256:"bad"},{wrongProtocolHostSha256:"a".repeat(64)},{rawProcessLog:"forbidden"}]){const bad=structuredClone(value);Object.assign(bad.report.nativePackagedChainRuntime,change);assert.ok(verifyMatrix([bad],options).length);}
 {const bad=structuredClone(value);delete bad.report.nativePackagedChainRuntime;assert.ok(verifyMatrix([bad],options).length);}
 {const bad=structuredClone(value);bad.report.scenarios=bad.report.scenarios.filter(row=>row.id!=="windows-packaged-chain-runtime-protocol-refusal");assert.ok(verifyMatrix([bad],options).length);}
 for(const file of require("../packages/agent/scripts/host/packaged-helper-runtime-fixture").REQUIRED_SOURCES){const bad=structuredClone(value);bad.report.fixtureSources=bad.report.fixtureSources.filter(row=>row.file!==file);assert.ok(verifyMatrix([bad],options).length,file);}
 for(let index=0;index<2;index++)for(const field of require("../packages/agent/scripts/host/iis-client-settings-fixture").FLAGS){for(const wrong of [false,1,null,"true"]){const bad=structuredClone(value);bad.report.nativeHttpSysClientSettings.cases[index][field]=wrong;assert.ok(verifyMatrix([bad],options).length);}const bad=structuredClone(value);delete bad.report.nativeHttpSysClientSettings.cases[index][field];assert.ok(verifyMatrix([bad],options).length);}
 for(const mutate of [p=>{p.scope="client-auth-handshake";},p=>{p.clientAuthHandshakeQualified=true;},p=>{p.cases.pop();},p=>{p.cases[1]=p.cases[0];},p=>{p.cases[0].checkMode=0;},p=>{p.cases[0].freshness=0;},p=>{p.cases[0].retrievalTimeout=0x100000000;},p=>{p.rawRegistry="forbidden";}]){const bad=structuredClone(value);mutate(bad.report.nativeHttpSysClientSettings);assert.ok(verifyMatrix([bad],options).length);}
 {const bad=structuredClone(value);delete bad.report.nativeHttpSysClientSettings;assert.ok(verifyMatrix([bad],options).length);}
 {const bad=structuredClone(value);bad.report.scenarios=bad.report.scenarios.filter(row=>row.id!=="windows-iis-client-revocation-policy-preservation");assert.ok(verifyMatrix([bad],options).length);}
 for(const file of require("../packages/agent/scripts/host/iis-client-settings-fixture").REQUIRED_SOURCES){const bad=structuredClone(value);bad.report.fixtureSources=bad.report.fixtureSources.filter(row=>row.file!==file);assert.ok(verifyMatrix([bad],options).length,file);}
 for(const mutate of [v=>delete v.report.supportingConfiguredRetentionTimer,v=>v.report.supportingConfiguredRetentionTimer.defaultSixHourElapsedQualified=true,v=>v.report.supportingConfiguredRetentionTimer.actualCallbacks=1,v=>v.report.supportingConfiguredRetentionTimer.waitedMonotonicMs=0,v=>v.report.supportingConfiguredRetentionTimer.nativeDeletionQualified=true,v=>v.report.supportingConfiguredRetentionTimer.privatePath="secret"]){const bad=structuredClone(value);mutate(bad);assert.ok(verifyMatrix([bad],options).length);}
 for(const field of Object.keys(value.report.nativeCngJournalAcl)){const bad=structuredClone(value);delete bad.report.nativeCngJournalAcl[field];assert.ok(verifyMatrix([bad],options).length,field);}
 for(const field of require("../packages/agent/scripts/host/orphan-journal-acl-fixture").FLAGS){const bad=structuredClone(value);bad.report.nativeCngJournalAcl[field]=false;assert.ok(verifyMatrix([bad],options).length,field);}
 for(const patch of [{scope:"software-only"},{caEnrollmentQualified:true},{installedServiceQualified:true},{rawContainerName:"private"}]){const bad=structuredClone(value);Object.assign(bad.report.nativeCngJournalAcl,patch);assert.ok(verifyMatrix([bad],options).length);}
 {const bad=structuredClone(value);delete bad.report.nativeCngJournalAcl;assert.ok(verifyMatrix([bad],options).length);}
 for(const file of require("../packages/agent/scripts/host/orphan-journal-acl-fixture").REQUIRED_SOURCES){const bad=structuredClone(value);bad.report.fixtureSources=bad.report.fixtureSources.filter(row=>row.file!==file);assert.ok(verifyMatrix([bad],options).length,file);}
 for(const field of Object.keys(value.report.nativeKeyUsage)){const bad=structuredClone(value);delete bad.report.nativeKeyUsage[field];assert.ok(verifyMatrix([bad],options).length,field);}
 for(const mask of [2,3,6,7,0x00ffffff]){const good=structuredClone(value);for(const item of good.report.nativeKeyUsage.cases)item.cngAllowedOperations=mask;assert.deepEqual(verifyMatrix([good],options),[]);}
 for(let index=0;index<10;index++)for(const mutate of [item=>{delete item.certificateUsageFlags;},item=>{delete item.cngAllowedOperations;},item=>{item.certificateUsageFlags=0;},item=>{item.certificateUsageFlags|=4;},item=>{item.cngAllowedOperations=2|8;},item=>{item.cngAllowedOperations=0;},item=>{item.cngAllowedOperations=true;},item=>{item.cngAllowedOperations="Signing";},item=>{item.cngAllowedOperations=0x100000000;}]){const bad=structuredClone(value);mutate(bad.report.nativeKeyUsage.cases[index]);assert.ok(verifyMatrix([bad],options).length,`case${index}`);}
 for(const mutate of [p=>{p.scope="exact-default-ncrypt-policy-qualified";},p=>{p.copiedActualCsrExtensions=false;},p=>{p.privateKeyUsageClaim="ecdsa-decryption-qualified";},p=>{p.cases.pop();},p=>{p.cases[9]=p.cases[0];},p=>{p.cases[0].caseId="rsa-1024/My";},p=>{p.cases[0].privateKey="unexpected";},p=>{p.privateKey="unexpected";}]){const bad=structuredClone(value);mutate(bad.report.nativeKeyUsage);assert.ok(verifyMatrix([bad],options).length);}
 for(const field of require("../packages/agent/scripts/host/retention-ledger-atomic-fixture").FIELDS){const bad=structuredClone(value);bad.report.nativeRetentionAtomicReplace[field]=false;assert.ok(verifyMatrix([bad],options).length,field);}
 for(const target of ['nativeElapsedRetention', 'nativeRetentionPolicyExpiry']){const nested=target==='nativeElapsedRetention'?value.report[target]:value.report[target]['168'];for(const key of Object.keys(nested.ownedInterruption)){const bad=structuredClone(value);const actual=target==='nativeElapsedRetention'?bad.report[target]:bad.report[target]['168'];delete actual.ownedInterruption[key];assert.ok(verifyMatrix([bad],options).length);}}
 for(const change of [{successfulCutovers:1},{predecessorKeysRemoved:1},{lineageRowsFinalized:1},{immutableHistoryPreserved:false},{waitedMonotonicMs:299999},{waitedMonotonicMs:600000},{fullRetentionWindowQualified:true},{configuredRetentionHours:1}]){const bad=structuredClone(value);Object.assign(bad.report.nativeElapsedRetention,change);assert.ok(verifyMatrix([bad],options).length);}
 for(const field of require("./certops-native-key-survivor-proof").FIELDS){for(const invalid of [false,null,1,"true"]){const bad=structuredClone(value);bad.report.nativeKeySurvivors[field]=invalid;assert.ok(verifyMatrix([bad],options).length,field);}}
 const missingSurvivor=structuredClone(value);delete missingSurvivor.report.nativeKeySurvivors;assert.ok(verifyMatrix([missingSurvivor],options).length);
 const unboundedSurvivor=structuredClone(value);unboundedSurvivor.report.nativeKeySurvivors.rawInventory="sentinel";assert.ok(verifyMatrix([unboundedSurvivor],options).length);
 for(const file of require("./certops-native-key-survivor-proof").REQUIRED_SOURCES){const bad=structuredClone(value);bad.report.fixtureSources.find(source=>source.file===file).sha256="0".repeat(64);assert.ok(verifyMatrix([bad],options).length,file);}
 for (const policy of ["168", "720"]) {
  const helper = require("../packages/agent/scripts/host/retention-policy-expiry-proof");
  for (const field of helper.FIELDS) { const bad=structuredClone(value); delete bad.report.nativeRetentionPolicyExpiry[policy][field]; assert.ok(verifyMatrix([bad],options).length,field); }
  for (const field of helper.FLAGS) { const bad=structuredClone(value); bad.report.nativeRetentionPolicyExpiry[policy][field]=false; assert.ok(verifyMatrix([bad],options).length,field); }
  for (const change of [{configuredRetentionHours:24},{successfulCutovers:1},{scope:"installed-service-timer"},{waitedMonotonicMs:299999},{waitedMonotonicMs:600000},{installedServiceTimerQualified:true},{fullRetentionWindowQualified:true},{rawNativeInventory:"private"}]) {const bad=structuredClone(value);Object.assign(bad.report.nativeRetentionPolicyExpiry[policy],change);assert.ok(verifyMatrix([bad],options).length);}
 }
 for (const mutate of [v=>{delete v.report.nativeRetentionPolicyExpiry;},v=>{delete v.report.nativeRetentionPolicyExpiry["720"];},v=>{v.report.nativeRetentionPolicyExpiry["720"]=v.report.nativeRetentionPolicyExpiry["168"];},v=>{v.report.nativeRetentionPolicyExpiry["24"]=v.report.nativeRetentionPolicyExpiry["168"]; }]){const bad=structuredClone(value);mutate(bad);assert.ok(verifyMatrix([bad],options).length);}
 for(const id of [168,720].flatMap(hours=>[`windows-retention-policy-${hours}-expiry-wins`,`windows-retention-policy-${hours}-interrupted-delete`])){const bad=structuredClone(value);bad.report.scenarios=bad.report.scenarios.filter(row=>row.id!==id);assert.ok(verifyMatrix([bad],options).length,id);}
 for(const file of [...require("../packages/agent/scripts/host/retention-policy-expiry-fixture").REQUIRED_SOURCES,"scripts/certops_retention_policy_expiry.py"]){for(const mutate of [v=>{v.report.fixtureSources=v.report.fixtureSources.filter(row=>row.file!==file)},v=>{v.report.fixtureSources.find(row=>row.file===file).sha256="0".repeat(64)}]){const bad=structuredClone(value);mutate(bad);assert.ok(verifyMatrix([bad],options).length,file);}}
 const missingElapsed=structuredClone(value);delete missingElapsed.report.nativeElapsedRetention;assert.ok(verifyMatrix([missingElapsed],options).length);
 for(const file of ["packages/agent/scripts/host/retention-elapsed-fixture.js","packages/agent/scripts/host/retention-interrupted-child.js","packages/agent/src/index.js","packages/agent/src/windows-retention/index.js","packages/agent/src/windows-discovery/index.js"]){
  const staleElapsed=structuredClone(value);staleElapsed.report.fixtureSources.find(row=>row.file===file).sha256="0".repeat(64);assert.ok(verifyMatrix([staleElapsed],options).length,file);
 }
 for(const field of require("../packages/agent/scripts/host/retention-reference-fixture").fields){for(const invalid of [false,null,1,"true"]){const bad=structuredClone(value);bad.report.nativeRetentionReferences[field]=invalid;assert.ok(verifyMatrix([bad],options).length,field);}}
 for(const mutate of [v=>{delete v.report.nativeRetentionReferences;},v=>{v.report.nativeRetentionReferences.scope="actual-adcs-enrollment";},v=>{v.report.nativeRetentionReferences.elapsed24HourQualified=true;},v=>{v.report.nativeRetentionReferences.rawInventory="sentinel";}]){const bad=structuredClone(value);mutate(bad);assert.ok(verifyMatrix([bad],options).length);}
 for(const source of require("../packages/agent/scripts/host/retention-reference-fixture").requiredSources){const bad=structuredClone(value);bad.report.fixtureSources.find(row=>row.file===source).sha256="0".repeat(64);assert.ok(verifyMatrix([bad],options).length,source);}
 for(const key of Object.keys(require("./fixtures/certops-windows-iis-public-only.cjs").fixture())){const missing=structuredClone(value);delete missing.report.nativeIisPublicOnly[key];assert.ok(verifyMatrix([missing],options).length,key);}for(const patch of [{installedSignedJobQualified:true},{refusalCode:"success"},{exactOwnedPublicCopyRemoved:false},{privateContainer:"sentinel"}]){const bad=structuredClone(value);Object.assign(bad.report.nativeIisPublicOnly,patch);assert.ok(verifyMatrix([bad],options).length);}
 for(const key of Object.keys(ipv4WildcardProof())){const missing=structuredClone(value);delete missing.report.nativeIpv4WildcardShadow[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeIpv4WildcardShadow[key]=typeof bad.report.nativeIpv4WildcardShadow[key]==="boolean"?!bad.report.nativeIpv4WildcardShadow[key]:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
 for(const key of Object.keys(ipv6WildcardProof())){const missing=structuredClone(value);delete missing.report.nativeIpv6WildcardShadow[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeIpv6WildcardShadow[key]=typeof bad.report.nativeIpv6WildcardShadow[key]==="boolean"?!bad.report.nativeIpv6WildcardShadow[key]:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
 const ipv4Substitute=structuredClone(value);ipv4Substitute.report.nativeIpv4WildcardShadow=ipv6WildcardProof();assert.ok(verifyMatrix([ipv4Substitute],options).length);
 const ipv4MissingCase=structuredClone(value);ipv4MissingCase.report.scenarios=ipv4MissingCase.report.scenarios.filter(row=>row.id!=="windows-iis-ipv4-wildcard-shadow-rollback");assert.ok(verifyMatrix([ipv4MissingCase],options).length);
 for(const file of require("../packages/agent/scripts/host/ipv4-wildcard-fixture").REQUIRED_SOURCES){const bad=structuredClone(value);bad.report.fixtureSources.find(row=>row.file===file).sha256="0".repeat(64);assert.ok(verifyMatrix([bad],options).length,file);}
 const concreteSubstitute=structuredClone(value);concreteSubstitute.report.nativeIpv6WildcardShadow=ipv6ShadowProof();assert.ok(verifyMatrix([concreteSubstitute],options).length);
 for(const file of require("../packages/agent/scripts/host/ipv6-wildcard-fixture").REQUIRED_SOURCES){const bad=structuredClone(value);bad.report.fixtureSources.find(row=>row.file===file).sha256="0".repeat(64);assert.ok(verifyMatrix([bad],options).length,file);}
 for(const key of Object.keys(ipv6ShadowProof())){const missing=structuredClone(value);delete missing.report.nativeIpv6SniShadow[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeIpv6SniShadow[key]=typeof bad.report.nativeIpv6SniShadow[key]==="boolean"?!bad.report.nativeIpv6SniShadow[key]:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
 for(const file of require("../packages/agent/scripts/host/ipv6-shadow-fixture").REQUIRED_SOURCES){const bad=structuredClone(value);bad.report.fixtureSources.find(row=>row.file===file).sha256="0".repeat(64);assert.ok(verifyMatrix([bad],options).length,file);}
 for(const key of Object.keys(orphanJournalProof())){const missing=structuredClone(value);delete missing.report.nativeOrphanJournalProtection[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeOrphanJournalProtection[key]=typeof bad.report.nativeOrphanJournalProtection[key]==="boolean"?!bad.report.nativeOrphanJournalProtection[key]:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
 for(const file of require("../packages/agent/scripts/host/orphan-journal-fixture").requiredSources){const bad=structuredClone(value);bad.report.fixtureSources.find(row=>row.file===file).sha256="0".repeat(64);assert.ok(verifyMatrix([bad],options).length,file);}
 for(const key of Object.keys(ledgerReadProof())){const missing=structuredClone(value);delete missing.report.nativeLedgerReadRefusals[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeLedgerReadRefusals[key]=typeof bad.report.nativeLedgerReadRefusals[key]==="boolean"?!bad.report.nativeLedgerReadRefusals[key]:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
 for(const change of [v=>{delete v.report.nativeLedgerReadRefusals},v=>{v.report.nativeLedgerReadRefusals.rawPrivateSddl="sentinel"}]){const bad=structuredClone(value);change(bad);assert.ok(verifyMatrix([bad],options).length);}
 for(const source of require("../packages/agent/scripts/host/retention-ledger-read-refusal-fixture").requiredSources){const bad=structuredClone(value);bad.report.fixtureSources.find(row=>row.file===source).sha256="0".repeat(64);assert.ok(verifyMatrix([bad],options).length,source);}
 for(const key of Object.keys(journalReadProof())){const missing=structuredClone(value);delete missing.report.nativeJournalReadRefusals[key];assert.ok(verifyMatrix([missing],options).length,key);const bad=structuredClone(value);bad.report.nativeJournalReadRefusals[key]=typeof bad.report.nativeJournalReadRefusals[key]==="boolean"?!bad.report.nativeJournalReadRefusals[key]:"invalid";assert.ok(verifyMatrix([bad],options).length,key);}
 for(const change of [v=>{delete v.report.nativeJournalReadRefusals},v=>{v.report.nativeJournalReadRefusals.rawPrivateJournal="sentinel"}]){const bad=structuredClone(value);change(bad);assert.ok(verifyMatrix([bad],options).length);}
 for(const file of require("../packages/agent/scripts/host/journal-read-refusal-fixture").requiredSources){const bad=structuredClone(value);bad.report.fixtureSources.find(row=>row.file===file).sha256="0".repeat(64);assert.ok(verifyMatrix([bad],options).length,file);}
 for(const mutate of [v=>delete v.report.nativeCredentialWeakAcl,v=>v.report.nativeCredentialWeakAcl.actualProductionAclRefusal=false,v=>v.report.nativeCredentialWeakAcl.installedServiceStartupQualified=true,v=>v.report.nativeCredentialWeakAcl.untrustedProcessReadQualified=true,v=>v.report.nativeCredentialWeakAcl.rawCredential="sentinel"]){const bad=structuredClone(value);mutate(bad);assert.ok(verifyMatrix([bad],options).length);}
 const missingWeakAclCase=structuredClone(value);missingWeakAclCase.report.scenarios=missingWeakAclCase.report.scenarios.filter(row=>row.id!==require("../packages/agent/scripts/host/credential-weak-acl-fixture").SCENARIO);assert.ok(verifyMatrix([missingWeakAclCase],options).length);
 for(const f of require("../packages/agent/scripts/host/credential-weak-acl-fixture").REQUIRED_SOURCES){const bad=structuredClone(value);bad.report.fixtureSources.find(row=>row.file===f).sha256="0".repeat(64);assert.ok(verifyMatrix([bad],options).length);}
 for(const field of require("../packages/agent/scripts/host/state-read-refusal-fixture").fields){for(const invalid of [false,null,1,"true"]){const bad=structuredClone(value);bad.report.nativeStateReadRefusals[field]=invalid;assert.ok(verifyMatrix([bad],options).length,field);}}
 for(const mutate of [v=>{delete v.report.nativeStateReadRefusals;},v=>{v.report.nativeStateReadRefusals.scope="installed-agent-startup";},v=>{v.report.nativeStateReadRefusals.installedServiceStartupQualified=true;},v=>{v.report.nativeStateReadRefusals.rawCredential="sentinel";}]){const bad=structuredClone(value);mutate(bad);assert.ok(verifyMatrix([bad],options).length);}
 for(const source of require("../packages/agent/scripts/host/state-read-refusal-fixture").requiredSources){const bad=structuredClone(value);bad.report.fixtureSources.find(row=>row.file===source).sha256="0".repeat(64);assert.ok(verifyMatrix([bad],options).length,source);}
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
    main.nativeAcmeStageFaults=require("./test-support/acme-stage-proof.cjs").proof(client);
    main.nativeAcmeBackgroundRenewals=require("./test-support/acme-background-proof.cjs").proof(client,main.nativeAcmeKeyReuse);
    if(slot.suite==="real-agent-acme-filesystem"){main.nativeAcmeBulkRenewal=require("./test-support/acme-bulk-proof.cjs").proof(main.nativeAcmeKeyReuse);main.nativeAcmeRenewalSetup=require("./test-support/acme-native-adoption-proof.cjs").proof(main.nativeAcmeBulkRenewal);main.nativeAcmeCertificateOutbox=require("./test-support/acme-certificate-outbox-proof.cjs").proof(main.nativeAcmeBulkRenewal);main.nativeAcmeDisabledProfile=require("./test-support/acme-disabled-profile-proof.cjs").proof(main.nativeAcmeBulkRenewal);main.nativeAcmeRenewalAlert=require("./test-support/acme-renewal-alert-proof.cjs").proof(main.nativeAcmeCertificateOutbox);}
    const value={kind:"stack",suite:slot.suite,environment:{...slot.environment,measurement:"native"},events};
    const options={candidateSha,specification:{schemaVersion:1,slots:[slot]}};
    assert.deepEqual(verifyMatrix([value],options),[]);
    const reject=mutate=>{const bad=structuredClone(value);mutate(bad.events.find(event=>event.name===main.name),bad);assert.ok(verifyMatrix([bad],options).length,slot.suite);};
    if(slot.suite==="real-agent-acme-filesystem") reject(event=>{delete event.nativeAcmeRenewalAlert;});
    for(const field of helper.fields){for(const invalid of [false,1,null,"true"])reject(event=>{event.nativeAcmeKeyReuse[field]=invalid;});reject(event=>{delete event.nativeAcmeKeyReuse[field];});}
    for(const change of [{scope:"windows-native-reuse"},{scope:"background-worker-loop"},{client:client==="certbot"?"acme.sh":"certbot"},{fingerprints:["a".repeat(64),"a".repeat(64),"b".repeat(64)]},{serials:["AA","AA","BB"]},{jobIds:[main.nativeAcmeKeyReuse.jobIds[0],main.nativeAcmeKeyReuse.jobIds[0].toUpperCase()]},{sourceProfileId:"foreign"},{sourceProfileFingerprint:"bad"},{spkiFingerprint:"bad"},{windowsQualified:true},{workerLoopQualified:true}])reject(event=>Object.assign(event.nativeAcmeKeyReuse,change));
    reject(event=>{delete event.nativeAcmeKeyReuse;});
    reject((event,bad)=>{bad.events[0].fixtureSources[0].sha256="0".repeat(64);});
    reject((event,bad)=>{bad.events=bad.events.filter(row=>row.name!==helper.scenarioName);});
  }
});

function elapsedRetentionProof() {
 return {ownedInterruption:{scope:'owned-short-retention-native-interruption-drain',assignedBeforeResume:true,rootExit86:true,nativeActiveZero:true,nativeHandlesClosed:true,wrapperClosed:true},mode:"real-clock-two-cutover-expiry-grace",successfulCutovers:2,predecessorCertificatesRemoved:2,predecessorKeysRemoved:2,lineageRowsFinalized:2,immediateDeferralPreservedCustody:true,immutableHistoryPreserved:true,replacementTrustedBoundCustodyUnchanged:true,interruptedNativeDeleteRecovered:true,configuredRetentionHours:24,fullRetentionWindowQualified:false,waitedMonotonicMs:420000};
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

test("resident domain retention requires genuine day, complete native facts and current candidate sources",()=>{
 const helper=require("./certops-retention24h-proof"),fixture=require("./certops-retention24h-test-fixture.cjs"),slot=require("../docs/certops/release-qualification-matrix.json").slots.find(item=>item.suite===helper.SUITE);assert.ok(slot);
 const composite=fixture();composite.publicPreparation.fixtureSources=helper.REQUIRED_SOURCES.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));
 const report=helper.createQualificationReport(composite),value={kind:"host",suite:helper.SUITE,environment:{...slot.environment},report},options={candidateSha,specification:{schemaVersion:1,slots:[slot]}};
 assert.deepEqual(verifyMatrix([value],options),[]);
 for(const flag of helper.FLAGS){const invalid=structuredClone(value);invalid.report.nativeRetention24h[flag]=false;assert.ok(verifyMatrix([invalid],options).length,flag);}
 for(const patch of [{monotonicElapsedMs:86399999},{maximumSweepGapMs:3900001},{oldNotAfter:report.nativeRetention24h.cleanupDeadline},{keptSweepCount:2},{scope:"resident-timing-only-native-oracles-required"},{requestIds:["11","11"]}]){const invalid=structuredClone(value);Object.assign(invalid.report.nativeRetention24h,patch);assert.ok(verifyMatrix([invalid],options).length);}
 for(const id of helper.REQUIRED_SCENARIOS){const invalid=structuredClone(value);invalid.report.scenarios=invalid.report.scenarios.filter(item=>item.id!==id);assert.ok(verifyMatrix([invalid],options).length,id);}
 const interruption=require('../tests/e2e/helpers/certops-retention24h-interrupted');
 for(const flag of interruption.FLAGS){const invalid=structuredClone(value);invalid.report.nativeRetention24h.interruptedDelete[flag]=false;assert.ok(verifyMatrix([invalid],options).length);}
 for(const patch of [{cleanupDeadline:report.nativeRetention24h.oldNotAfter},{productionSixHourCadenceQualified:true},{full168HourRetentionQualified:true},{interruptedAt:report.nativeRetention24h.cleanupDeadline},{resumedAt:report.nativeRetention24h.cleanupFinishedAt}]){const invalid=structuredClone(value);Object.assign(invalid.report.nativeRetention24h.interruptedDelete,patch);assert.ok(verifyMatrix([invalid],options).length);}
 {const invalid=structuredClone(value);delete invalid.report.nativeRetention24h.interruptedDelete;assert.ok(verifyMatrix([invalid],options).length);}
 for(const file of interruption.REQUIRED_SOURCES){const missing=structuredClone(value);missing.report.fixtureSources=missing.report.fixtureSources.filter(row=>row.file!==file);assert.ok(verifyMatrix([missing],options).length);const stale=structuredClone(value);stale.report.fixtureSources.find(row=>row.file===file).sha256='0'.repeat(64);assert.ok(verifyMatrix([stale],options).length);}
 const missing=structuredClone(value);delete missing.report.nativeRetention24h;assert.ok(verifyMatrix([missing],options).length);
 const stale=structuredClone(value);stale.report.fixtureSources[0].sha256="0".repeat(64);assert.ok(verifyMatrix([stale],options).length);
 const omitted=structuredClone(value);omitted.report.fixtureSources.pop();assert.ok(verifyMatrix([omitted],options).length);
});


test("WebHosting hosted cells require independent store, elapsed and borrowed-key custody proof", () => {
 const runner=require('./certops-windows-webhosting-retention');
 const fixture=require('./fixtures/certops-webhosting-retention.cjs');
 const slots=require('../docs/certops/release-qualification-matrix.json').slots.filter(x=>x.suite===runner.SUITE);
 assert.equal(slots.length,2);
 for(const slot of slots){
  const value=suiteArtifact(slot.suite,slot.source,{nativeWebHostingRetention:fixture.proof(),cleanup:{status:"passed"}});
  value.environment=slot.environment; value.report.qualificationEnvironment={...slot.environment,measurement:"native"};
  value.report.fixtureSources=slot.requiredSources.map(file=>({file,sha256:crypto.createHash('sha256').update(fs.readFileSync(path.join(root,file))).digest('hex')}));
  assert.deepEqual(verifyMatrix([value],{candidateSha,specification:{schemaVersion:1,slots:[slot]}}),[]);
  for(const mutate of [p=>{p.cleanup.status="failed"},p=>{delete p.nativeWebHostingRetention},p=>{p.nativeWebHostingRetention.store='My'},p=>{p.nativeWebHostingRetention.storeReceipt.nativeIisWebHostingStoreObserved=false},p=>{p.nativeWebHostingRetention.borrowedReplacement.sameOriginalMyPrivateKeyPossession=false},p=>{p.nativeWebHostingRetention.elapsed.waitedMonotonicMs=1},p=>{delete p.nativeWebHostingRetention.elapsed.ownedInterruption},p=>{p.nativeWebHostingRetention.privateNative='forbidden'},p=>{p.fixtureSources.pop()}]){
   const bad=structuredClone(value);mutate(bad.report);assert.ok(verifyMatrix([bad],{candidateSha,specification:{schemaVersion:1,slots:[slot]}}).length);
  }
 }
});

test("certificate signing rotation requires the owned non-forced cell", () => {
  const slot = require("../docs/certops/release-qualification-matrix.json").slots.find(item => item.id === "linux-native-certificate-signing-rotation");
  const proof = require("./fixtures/certops-acme-certificate-signing.cjs").fixture();
  const value = suiteArtifact(slot.suite, slot.source, { platform: "linux", architecture: "x64", nativeCertificateSigningRotation: proof });
  value.environment = { ...slot.environment };
  value.report.qualificationEnvironment = { ...slot.environment, distribution: "ubuntu", osVersion: "24.04", measurement: "native" };
  value.report.fixtureSources = slot.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
  assert.deepEqual(verifyMatrix([value], options), []);
  const missing = structuredClone(value); delete missing.report.nativeCertificateSigningRotation;
  assert.ok(verifyMatrix([missing], options).length);
  const forced = structuredClone(value); forced.report.nativeCertificateSigningRotation.forcedCompletionQualified = true;
  assert.ok(verifyMatrix([forced], options).length);
});

test("installed bind-failure and interruption proofs stay local and fail closed", () => {
  const bind = require("../tests/e2e/helpers/certops-windows-installed-bind-failure");
  const recovery = require("../tests/e2e/helpers/certops-windows-installed-interruption");
  const run = "ab".repeat(16);
  const owned = bind.createRunManifest({ runId: run, root: `C:\\qualification\\tt-bindfail-${run}`, predecessorThumbprint: "AB".repeat(20), siblingThumbprint: "CD".repeat(20), appIds: ["{11111111-1111-1111-1111-111111111111}", "{22222222-2222-2222-2222-222222222222}"] });
  const bindProof = bind.simulateScriptContract(owned, { bindings: [{ selector: "ipport=0.0.0.0:443", endpoint: "0.0.0.0:443", thumbprint: "EE".repeat(20), store: "MY" }], sites: [{ name: "Default Web Site" }] }).proof;
  const interruptionRun = "cd".repeat(16);
  const recorded = recovery.recordPoint({ kind: "ledger", runId: interruptionRun, sequence: 7, payload: Buffer.from("ledger-row"), mode: "service-stop", root: `C:\\qualification\\tt-int-${interruptionRun}` });
  const interruptionProof = recovery.recover({ point: recorded.point, bytes: recorded.bytes, commands: recovery.buildInterruptionPlan(recorded.point) }).proof;
  const cases = [
    ["windows-installed-bind-failure", "nativeInstalledBindFailure", bindProof],
    ["windows-installed-interruption-recovery", "nativeInstalledInterruption", interruptionProof],
  ];
  for (const [id, field, proof] of cases) {
    const slot = require("../docs/certops/release-qualification-matrix.json").slots.find(item => item.id === id);
    const value = suiteArtifact(slot.suite, slot.source, { [field]: proof });
    value.environment = { ...slot.environment };
    value.report.qualificationEnvironment = { ...slot.environment, measurement: "native" };
    value.report.fixtureSources = slot.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
    const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
    assert.deepEqual(verifyMatrix([value], options), []);
    const missing = structuredClone(value); delete missing.report[field];
    assert.ok(verifyMatrix([missing], options).length);
  }
  const interruption = require("../docs/certops/release-qualification-matrix.json").slots.find(item => item.id === "windows-installed-interruption-recovery");
  const durable = suiteArtifact(interruption.suite, interruption.source, { nativeInstalledInterruption: { ...interruptionProof, powerLossDurabilityQualified: true } });
  durable.environment = { ...interruption.environment };
  durable.report.qualificationEnvironment = { ...interruption.environment, measurement: "native" };
  durable.report.fixtureSources = interruption.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
  assert.ok(verifyMatrix([durable], { candidateSha, specification: { schemaVersion: 1, slots: [interruption] } }).length);
});

test("native issuer reassignment stays pending without a disposable forest", () => {
  const slot = require("../docs/certops/release-qualification-matrix.json").slots.find(item => item.id === "windows-native-issuer-reassignment");
  const helper = require("../tests/e2e/helpers/certops-native-issuer-reassignment");
  const proof = {
    scope: helper.SCOPE, renewalProtocol: "production-scheduler-sweep-after-public-issuer-switch", schedulerInvocation: "qualification-invoked-production-default-sweep", workerIntervalQualified: false, nativeCell: "pending",
    originIssuerId: "11111111-1111-4111-8111-111111111111", destinationIssuerId: "22222222-2222-4222-8222-222222222222", originCaKeySha256: "a".repeat(64), destinationCaKeySha256: "b".repeat(64),
    profileId: "33333333-3333-4333-8333-333333333333", certificateId: "44444444-4444-4444-8444-444444444444", requestIds: ["17", "18"], fingerprints: ["c".repeat(64), "d".repeat(64)], spkiFingerprints: ["e".repeat(64), "f".repeat(64)],
    enrollmentIds: ["55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666"], jobIds: ["77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888"],
    containerNames: ["tokentimer-enr-55555555-5555-4555-8555-555555555555", "tokentimer-enr-66666666-6666-4666-8666-666666666666"],
    ...Object.fromEntries(helper.FLAGS.map(flag => [flag, true])),
  };
  const value = suiteArtifact(slot.suite, slot.source, { nativeIssuerReassignment: proof, nativeCell: "pending" });
  value.environment = { ...slot.environment };
  value.report.qualificationEnvironment = { ...slot.environment, measurement: "native" };
  value.report.fixtureSources = slot.requiredSources.map(file => ({ file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }));
  const options = { candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
  assert.deepEqual(verifyMatrix([value], options), []);
  const qualified = structuredClone(value); qualified.report.nativeCell = "qualified";
  assert.ok(verifyMatrix([qualified], options).length);
  const missing = structuredClone(value); delete missing.report.nativeIssuerReassignment;
  assert.ok(verifyMatrix([missing], options).length);
});
