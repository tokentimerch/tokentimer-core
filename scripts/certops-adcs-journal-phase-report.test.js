"use strict";
/* Portable adversarial report checks for journal-phase experiments. Run with node --test;
 * synthetic report fixtures do not execute or qualify native Windows faults.
 */
const {test}=require("node:test");const assert=require("node:assert/strict");const {verify}=require("./certops-adcs-journal-phase-report");
function fixture(phase="installing"){return {schemaVersion:1,scope:"enterprise-adcs-journal-phase-experimental",qualificationStatus:"not-qualified",status:"passed",candidateSha:"a".repeat(40),fixtureSource:{file:"tests/e2e/helpers/certops-adcs-journal-phase-experiment.js",sha256:"b".repeat(64)},phase,fault:{phase,observedDurablePhase:true,unchangedAfterTermination:true,ownedServiceTree:true,nativeIdentity:"LocalSystem"},actualRenewedLeaseObserved:true,actualOrphanedJobObserved:true,ownedScmRecoveryTemporarilyDisabled:true,ownedScmRecoveryRestored:true,operatorRecoveryAuditObserved:true,originalUnknownEffectEvidencePreserved:true,sameKeyAndCsrIdentityPreserved:true,leaseSeconds:60,hardGraceMs:60000,clocks:"actual-host-and-database",databasePhaseRewritten:false,journalRewritten:false,outcome:"same-key-installation-recovered",caRequestsAtFault:1,caRequestsAfterRecovery:1,trustedNativeTls:true};}
test("observed native phase evidence remains explicitly experimental",()=>{assert.equal(verify(fixture()),true);assert.equal(verify({...fixture("prepared"),caRequestsAtFault:0}),true);});
test("submitting requires a reconciled real request and rejects zero-row abandonment",()=>{
  const report={...fixture("submitting"),outcome:"uncertain-no-resubmit-operator-reconciled",uncertainNoResubmitVerified:true,uncertainFrozenIdentityAndKeyPreserved:true};
  assert.equal(verify(report),true);
  for(const change of [{outcome:"uncertain-no-resubmit-abandoned-with-absent-key",caRequestsAtFault:0,caRequestsAfterRecovery:0,abandonedKeyAbsent:true},
    {outcome:"uncertain-no-resubmit-operator-action-required",status:"failed",cleanupPendingOperatorReconciliation:true},
    {caRequestsAfterRecovery:2},{uncertainFrozenIdentityAndKeyPreserved:false}])assert.throws(()=>verify({...report,...change}));
});
test("unresolved zero-row submission guard preserves the native fixture",()=>{
  const fs=require("node:fs"),os=require("node:os"),path=require("node:path");
  const guard=require("../tests/e2e/helpers/certops-adcs-journal-phase-experiment").assertCleanupSafe;
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),"journal-cleanup-guard-"));
  try{assert.doesNotThrow(()=>guard(directory));fs.writeFileSync(path.join(directory,".preserve-adcs-journal-uncertainty.json"),"{}");assert.throws(()=>guard(directory),/Preserve key and durable journal/);}finally{fs.rmSync(directory,{recursive:true});}
});

test("missing native fault, lease acknowledgement, TLS or integrity never passes",()=>{for(const change of [{status:"failed"},{qualificationStatus:"qualified"},{actualRenewedLeaseObserved:false},{actualOrphanedJobObserved:false},{journalRewritten:true},{databasePhaseRewritten:true},{trustedNativeTls:false},{cleanupFailed:true},{ownedScmRecoveryRestored:false},{clocks:"injected"}])assert.throws(()=>verify({...fixture(),...change}));assert.throws(()=>verify({...fixture(),fault:{...fixture().fault,ownedServiceTree:false}}));});

test("certreq-new interruption requires real protected key and absent CSR then physical cancellation cleanup",()=>{const report={...fixture("keygen_intent"),fault:{...fixture("keygen_intent").fault,actualCertreqNewObserved:true,nonExportableOwnedKeyObserved:true},outcome:"pre-csr-recovery-refused-owned-key-cancelled",caRequestsAtFault:0,caRequestsAfterRecovery:0,preCsrRecoveryRefused:true,ownedProtectedKeyPreserved:true,durableCsrAbsent:true,cancelledKeyAbsent:true};assert.equal(verify(report),true);for(const field of ["preCsrRecoveryRefused","ownedProtectedKeyPreserved","durableCsrAbsent","cancelledKeyAbsent"])assert.throws(()=>verify({...report,[field]:false}));assert.throws(()=>verify({...report,caRequestsAfterRecovery:1}));assert.throws(()=>verify({...report,fault:{...report.fault,actualCertreqNewObserved:false}}));});

test("issued crash recovery requires one pre-existing CA request and preserves its RequestId",()=>{
  const report={...fixture("issued"),issuedRequestIdentityPreserved:true,nativeRequestIdAtFault:17,nativeRequestIdAfterRecovery:17};
  assert.equal(verify(report),true);
  for(const change of [{caRequestsAtFault:0},{caRequestsAtFault:2},{caRequestsAfterRecovery:2},{issuedRequestIdentityPreserved:false},{nativeRequestIdAtFault:undefined},{nativeRequestIdAtFault:0},{nativeRequestIdAtFault:4294967296},{nativeRequestIdAfterRecovery:18}])assert.throws(()=>verify({...report,...change}));
});

test("scoped zero-row recovery proves actionable uncertainty without installation or cleanup claims",()=>{
 const report={...fixture("submitting"),outcome:"uncertain-no-resubmit-operator-action-required",uncertainNoResubmitVerified:true,uncertainFrozenIdentityAndKeyPreserved:true,caRequestsAtFault:0,caRequestsAfterRecovery:0,trustedNativeTls:false,scopedOperatorReconciliationOutcome:true,recoveryContinuationRefused:true,publicOperatorUncertaintyObserved:true,ordinaryPollAbsent:true,supportedSchedulerDidNotResubmit:true,ownedProtectedKeyPreserved:true,cleanupPendingOperatorReconciliation:true};
 assert.equal(verify(report),true);
 for(const field of ["scopedOperatorReconciliationOutcome","recoveryContinuationRefused","publicOperatorUncertaintyObserved","ordinaryPollAbsent","supportedSchedulerDidNotResubmit","ownedProtectedKeyPreserved","cleanupPendingOperatorReconciliation","sameKeyAndCsrIdentityPreserved","operatorRecoveryAuditObserved","originalUnknownEffectEvidencePreserved"]){assert.throws(()=>verify({...report,[field]:false}));}
 for(const patch of [{trustedNativeTls:true},{caRequestsAtFault:1},{caRequestsAfterRecovery:1},{status:"failed"},{qualificationStatus:"qualified"}])assert.throws(()=>verify({...report,...patch}));
});
