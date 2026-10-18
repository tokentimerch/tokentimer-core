"use strict";
/** Synthetic report verification only; no installed service is run or stopped. */
const {test}=require("node:test"), assert=require("node:assert/strict");
const native=require("../tests/e2e/helpers/certops-windows-interruption-native");
const fixture=require("./test-support/windows-stop-offline.cjs");
test("native interruption derives only an actual completed narrow parent scope",()=>{
  for(const version of ["2022","2025"]){
    const parent=fixture.artifact(version).report;
    const report=native.createReport(parent,{candidateSha:fixture.candidateSha});
    assert.equal(report.suite,native.SUITE);
    assert.equal(report.nativeInstalledInterruption.originalOperationAutomaticallyRecovered,false);
    assert.equal(report.nativeInstalledInterruption.realRebootQualified,false);
    assert.equal(native.verifyProof(report.nativeInstalledInterruption),true);
    const slot=require("./certops-qualification-manifest").slots.find(s=>s.suite===native.SUITE&&s.environment.osVersion===version);
    assert.deepEqual(require("./certops-release-qualification").verifyMatrix([{kind:"host",suite:report.suite,environment:slot.environment,report}],{candidateSha:fixture.candidateSha,specification:{schemaVersion:1,slots:[slot]}}),[]);
    const invalid=structuredClone(report);
    invalid.nativeInstalledInterruption={scope:"installed-deterministic-interruption-recovery",evidenceLevel:"host-integration",pointKind:"cng",interruptionMode:"service-stop",recordedSequence:1,startupRecovery:true,inUseKeyDeleted:false,powerLossDurabilityQualified:false,realRebootQualified:false,nativeExecutionQualified:false,hostCapabilityAbsentIsPass:false};
    require("../tests/e2e/helpers/certops-windows-installed-interruption").verifyProof(invalid.nativeInstalledInterruption);
    assert.ok(require("./certops-release-qualification").verifyMatrix([{kind:"host",suite:invalid.suite,environment:slot.environment,report:invalid}],{candidateSha:fixture.candidateSha,specification:{schemaVersion:1,slots:[slot]}}).length);
  }
});
test("absent stage, drainage, cleanup, custody and provenance cannot produce interruption success",()=>{
  const changes=[p=>{p.cleanup.status="failed";},p=>{p.status="failed";},p=>{p.scenarios=[];},p=>{p.platform="linux";},p=>{p.experimental=true;},p=>{p.fixtureSources.pop();},p=>{p.fixtureSource.sha256="0".repeat(64);},
    ...["realHeldDnsPostAfterNativeCngJournal","allCapturedDescendantsExited","nativeHandlesAndObserverClosed","sameServingCngBindingAndTrustedTlsWhileStopped","exactOwnedCleanupCompleted"].map(key=>p=>{p.nativeWindowsStoppedOffline[key]=false;})];
  for(const change of changes){const p=fixture.artifact().report;change(p);assert.throws(()=>native.createReport(p,{candidateSha:fixture.candidateSha}));}
  const proof=native.createReport(fixture.artifact().report,{candidateSha:fixture.candidateSha}).nativeInstalledInterruption;
  for(const change of [p=>{p.originalOperationAutomaticallyRecovered=true;},p=>{p.observedStage="bind";},p=>{p.interruptionMode="process-kill";}]){const p=structuredClone(proof);change(p);assert.throws(()=>native.verifyProof(p));}
});
