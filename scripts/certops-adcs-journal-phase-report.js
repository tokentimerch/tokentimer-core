#!/usr/bin/env node
"use strict";
/* Independent verifier for observed native journal-phase crash experiments. Rejects missing
 * lease/process/key/recovery evidence and keeps these fault experiments separate from release
 * qualification; reads only the supplied sanitized report.
 */
const assert=require("node:assert/strict");
const fs=require("node:fs");
function verify(report){
  if(report?.phase==="bound-before-complete")return require("../tests/e2e/helpers/certops-adcs-bound-install-recovery").verifyReport(report);
  if(report?.phase==="accepted-before-bind")return require("../tests/e2e/helpers/certops-adcs-accepted-install-recovery").verifyReport(report);
  assert.equal(report.schemaVersion,1);assert.equal(report.scope,"enterprise-adcs-journal-phase-experimental");
  assert.equal(report.qualificationStatus,"not-qualified");assert.equal(report.status,"passed");
  assert.match(report.candidateSha,/^[a-f0-9]{40}$/i);assert.match(report.fixtureSource?.sha256,/^[a-f0-9]{64}$/i);
  assert.equal(report.fixtureSource.file,"tests/e2e/helpers/certops-adcs-journal-phase-experiment.js");
  assert.ok(["keygen_intent","prepared","submitting","installing"].includes(report.phase));assert.equal(report.fault?.phase,report.phase);
  for(const field of ["observedDurablePhase","unchangedAfterTermination","ownedServiceTree"])assert.equal(report.fault[field],true);
  assert.equal(report.fault.nativeIdentity,"LocalSystem");assert.equal(report.actualRenewedLeaseObserved,true);assert.equal(report.actualOrphanedJobObserved,true);assert.equal(report.ownedScmRecoveryTemporarilyDisabled,true);assert.equal(report.ownedScmRecoveryRestored,true);
  assert.equal(report.operatorRecoveryAuditObserved,true);assert.equal(report.originalUnknownEffectEvidencePreserved,true);
  assert.equal(report.leaseSeconds,60);assert.equal(report.hardGraceMs,60000);assert.equal(report.clocks,"actual-host-and-database");
  assert.equal(report.databasePhaseRewritten,false);assert.equal(report.journalRewritten,false);assert.notEqual(report.cleanupFailed,true);
  if(report.phase==="keygen_intent"){
    assert.equal(report.outcome,"pre-csr-recovery-refused-owned-key-cancelled");
    for(const field of ["preCsrRecoveryRefused","ownedProtectedKeyPreserved","durableCsrAbsent","cancelledKeyAbsent"])assert.equal(report[field],true);
    assert.equal(report.fault.actualCertreqNewObserved,true);assert.equal(report.fault.nonExportableOwnedKeyObserved,true);
    assert.equal(report.caRequestsAtFault,0);assert.equal(report.caRequestsAfterRecovery,0);
  }else if(report.phase==="submitting"){
    assert.equal(report.uncertainNoResubmitVerified,true);
    assert.ok(["uncertain-no-resubmit-abandoned-with-absent-key","uncertain-no-resubmit-operator-reconciled"].includes(report.outcome));
    assert.equal(report.caRequestsAfterRecovery,report.caRequestsAtFault);
    if(report.outcome==="uncertain-no-resubmit-abandoned-with-absent-key"){assert.equal(report.caRequestsAfterRecovery,0);assert.equal(report.abandonedKeyAbsent,true);}
    else {assert.equal(report.caRequestsAfterRecovery,1);assert.equal(report.trustedNativeTls,true);assert.equal(report.sameKeyAndCsrIdentityPreserved,true);}
  }else{assert.equal(report.outcome,"same-key-installation-recovered");assert.equal(report.caRequestsAfterRecovery,1);assert.equal(report.trustedNativeTls,true);assert.equal(report.sameKeyAndCsrIdentityPreserved,true);}
  return true;
}
if(require.main===module){try{assert.equal(process.argv.length,3);verify(JSON.parse(fs.readFileSync(process.argv[2],"utf8")));process.stdout.write("Experimental native phase evidence passed; release qualification remains unchanged\n");}catch{process.stderr.write("Experimental native phase evidence incomplete or invalid\n");process.exitCode=1;}}
module.exports={verify};
