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

function adcsCapacityProof(){const helper=require("../tests/e2e/helpers/certops-adcs-capacity");return{scope:helper.SCOPE,cap:5,initialAccepted:5,initialRefused:1,nativeCompleted:2,...Object.fromEntries(helper.FLAGS.map(flag=>[flag,true])),requestIds:["17","18"],fingerprints:["a".repeat(64),"b".repeat(64)],enrollmentIds:["11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222"],jobIds:["33333333-3333-3333-3333-333333333333","44444444-4444-4444-4444-444444444444"]};}

function sameCertificateLateApprovalProof(){return {...cancelledLateApprovalProof(),scope:"real-cancelled-request-late-issued-after-same-certificate-renewal",sameCertificateRenewalQualified:true,backgroundTimerQualified:false,certificateId:"33333333-3333-4333-8333-333333333333"};}

function cancelledLateApprovalProof(){return {"scope":"real-cancelled-request-late-issued-after-distinct-same-endpoint-successor","cancelledEnrollmentId":"11111111-1111-1111-1111-111111111111","successorEnrollmentId":"22222222-2222-2222-2222-222222222222","requestIds":["17","18"],"fingerprints":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"sameCertificateRenewalQualified":false,"publicCancellationAuditVerified":true,"terminalCleanupAlreadyCompleted":true,"distinctActualSuccessorInstalled":true,"nativePendingCsrRequesterTemplateOwned":true,"actualOfficerLateApproval":true,"actualCaLeafMatchesOriginalCsr":true,"defaultClockDoesNotRevive":true,"overdueSchedulerDoesNotRevive":true,"publicInstallationRetryRefused":true,"originalJournalAndJobsUnchanged":true,"cancelledKeyRemainsAbsent":true,"lateLeafNeverAccepted":true,"successorClaimEvidenceUnchanged":true,"successorNativeCustodyBindingTlsUnchanged":true,"noCaResubmission":true,"ownedUnusedLateLeafRevoked":true};}

function browserJobApprovalProof(){return {"scope":"browser-control-plane-job-approval-for-two-real-adcs-capacity-installations","approvePosts":2,"rejectPosts":1,"cancelPosts":0,"caOfficerApprovalQualified":false,"jobIds":["33333333-3333-3333-3333-333333333333","44444444-4444-4444-4444-444444444444"],"enrollmentIds":["11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222"],"payloadHashes":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"requestIds":["17","18"],"fingerprints":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"rejectedJobId":"77777777-7777-7777-7777-777777777777","rejectedEnrollmentId":"88888888-8888-8888-8888-888888888888","rejectedPayloadHash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","rejectedCanonicalIntentHash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","twoDistinctOwnedPendingJobs":true,"distinctManagerApprover":true,"exactJobVisibleInActualDashboard":true,"cancelDidNotMutate":true,"twoExactPublicApprovalPosts":true,"appendOnlyDecisionsBoundToActor":true,"payloadAndCanonicalIntentHashesVerified":true,"browserAndTrustDrained":true,"sameApprovedJobsInstalledNatively":true,"capacityGenerationsCrossBound":true,"oneExactPublicRejectionPost":true,"rejectedJobNeverClaimedOrSubmitted":true,"rejectedIntentAndNativeAbsencePreserved":true}}

const candidateSha = "a".repeat(40);

const source = "tests/e2e/certops-adcs-gates-api-e2e.test.js";

const environment = { osFamily: "linux" };

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

const specification = { schemaVersion: 1, slots: [{ id: "fixture", kind: "host", suite: "adcs-api-release-gates", source, environment }] };

function artifact() {
  const suite = "adcs-api-release-gates";
  const now = new Date().toISOString();
  const report = { schemaVersion: 1, suite, candidateSha, startedAt: now, finishedAt: now, status: "passed", strict: true, evidenceLevel: "integration", requiredCapabilities: contract.requiredCapabilities[suite], capabilities: { api: { available: true }, postgres: { available: true } }, requiredScenarios: contract.suites[suite], missingCapabilities: [], missingScenarios: [], scenarios: contract.suites[suite].map((id) => ({ id, status: "passed", evidenceLevel: "integration", startedAt: now, finishedAt: now })), qualificationEnvironment: { ...environment, measurement: "native" }, artifactQualification: "workflow-checkout-source", fixtureSource: { file: source, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, source))).digest("hex") } };
  return { kind: "host", suite, environment: report.qualificationEnvironment, report };
}

function suiteArtifact(suite, file, fields) {
  const value = artifact(); value.suite = suite;
  Object.assign(value.report, { suite, evidenceLevel: contract.suiteEvidenceLevels[suite], requiredCapabilities: contract.requiredCapabilities[suite], capabilities: Object.fromEntries(contract.requiredCapabilities[suite].map(name => [name, { available: true }])), requiredScenarios: contract.suites[suite], scenarios: contract.suites[suite].map(id => ({ ...value.report.scenarios[0], id, evidenceLevel: contract.scenarioEvidenceLevels[suite][id] })), fixtureSource: { file, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, file))).digest("hex") }, ...fields });
  return value;
}

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
    nativePendingKeySurvivor: {"scope":"native-pending-key-policy-change-retrieval-install-and-survivor-protection","store":"WebHosting","recovery":"signed-retrieval-and-isolated-iis-installation","enrollmentId":"11111111-1111-1111-1111-111111111111","requestId":"17","continuationJobId":"22222222-2222-2222-2222-222222222222","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","csrSpkiSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","caRequestCounts":[7,7,7],"actualOwnedPendingRequest":true,"actualOwnedCaLeafSameCsrSpki":true,"exactWebHostingAssociationAndProtectedKey":true,"nativeSurvivorReferenceObserved":true,"signedRetrievalInstalled":true,"frozenEnrollmentIdentityPreserved":true,"originalKeyUsableAfterReconciliation":true,"installedKeyProtectedFromCleanup":true,"installedReferenceSurvivesSecondaryRemoval":true,"noAdditionalCaRequest":true,"exactPublicAssociationOnlyRemoved":true,"predecessorCustodyIisTlsPreserved":true,"configurationCredentialRestored":true,"ownedCaLeafRevoked":true,"ownershipGuardReleased":true},
    nativeLocalRuleTightening: {"enrollmentId":"11111111-1111-1111-1111-111111111111","continuationJobId":"22222222-2222-2222-2222-222222222222","requestId":"17","snapshotSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","caRequestCounts":[7,7],"actualSignedRetrievalPending":true,"originalCngKeyUsable":true,"frozenContextPreserved":true,"noAdditionalCaRequest":true,"outgoingTrustedTlsPreserved":true,"explicitTerminalCleanupAfterDenial":true},
    nativeAdcsCapacity: adcsCapacityProof(), nativeAlgorithmBoundaries: algorithmProof(), nativeCmcBoundaries: cmcProof(),
    nativeForeignSpkiCandidate: foreignSpkiProof(),
    nativeUncertainOperatorAmbiguity: operatorAmbiguityProof(),
    nativeUncertainOperatorUnique: require("./fixtures/certops-adcs-unique-candidate.cjs").proof(),
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
  {
    const helper = require("../tests/e2e/helpers/certops-adcs-uncertain-operator-unique");
    assert.ok(value.report.nativeUncertainOperatorUnique);
    {
      const absent = structuredClone(value); delete absent.report.nativeUncertainOperatorUnique;
      assert.ok(verifyMatrix([absent], options).length);
      for (const id of helper.REQUIRED_SCENARIOS) {
        const missing = structuredClone(value);
        missing.report.scenarios = missing.report.scenarios.filter(row => row.id !== id);
        assert.ok(verifyMatrix([missing], options).length, id);
      }
    }
  }
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
  for(const key of Object.keys(value.report.nativePendingKeySurvivor)){const bad=structuredClone(value);delete bad.report.nativePendingKeySurvivor[key];assert.ok(verifyMatrix([bad],options).length,key);}
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
  const files = ["tests/e2e/helpers/certops-adcs-browser-abandon.js", "tests/e2e/helpers/certops-adcs-browser-admin-boundary.js"];
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
 const declared=require("node:child_process").execFileSync("git",["ls-files"],{cwd:root,encoding:"utf8"}).trim().split(/\r?\n/).filter(file=>fs.existsSync(path.join(root,file)));assert.ok(declared.length>=257);
 const records=declared.slice(0,257).map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));
 const value=artifact(),spec=structuredClone(specification),options={candidateSha,specification:spec};value.report.fixtureSources=records.slice(0,256);spec.slots[0].requiredSources=records.slice(0,96).map(row=>row.file);assert.deepEqual(verifyMatrix([value],options),[]);
 for(const count of [97,128,129,192,256]){const good=structuredClone(value),specification=structuredClone(spec);good.report.fixtureSources=records.slice(0,count);specification.slots[0].requiredSources=records.slice(0,count).map(row=>row.file);assert.deepEqual(verifyMatrix([good],{candidateSha,specification}),[]);}
 for(const rows of [records,[records[0],records[0]],[{file:"../outside.js",sha256:"a".repeat(64)}],[{file:"C:\\outside.js",sha256:"a".repeat(64)}]]){const bad=structuredClone(value);bad.report.fixtureSources=rows;assert.ok(verifyMatrix([bad],options).length);}
 const oversized=structuredClone(spec);oversized.slots[0].requiredSources=records.map(row=>row.file);assert.ok(validateMatrix(oversized).some(error=>error.includes("invalid supporting source")));
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
