"use strict";
/** Strict composite native evidence contract. A four-hour prepare receipt or a
 * keeper timer alone never qualifies. Named phases derive only from the actual
 * independently verified operation receipts, including owned Azure absence. */
const assert=require("node:assert/strict"),contract=require("./certops-retention24h-contract");
const SCOPE="actual-domain-adcs-same-process-native-retention24h",SUITE="windows-domain-adcs-retention24h";
const REQUIRED_SCENARIOS=["retention24h-real-adcs-production-cutover","retention24h-real-resident-production-collector","retention24h-real-day-native-delete-interruption-and-default-clock-resume","retention24h-independent-native-final-and-owned-cleanup"];
const FLAGS=["genuinePublicAdcsCutover","distinctNativeRequestsAndLeaves","productionLedger24HourDeadline","oldExpiryBeyondDeadline","immutableOriginalPrepareVerified","sameVmTaskBootAndProcess","soleInstalledAgentStoppedDrained","predecessorProtectedCustodyPreserved","actualPreDeadlinePreserved","productionDefaultClockCollector","actualResidentDayElapsed","oldCertificateActuallyAbsent","oldKeyActuallyAbsent","replacementCngIisAndTrustedTlsUnchanged","immutableLedgerIdentityPreserved","currentExecutableAndSourceDigestsBound","independentFinalNativeRecheck","ownedAzureCleanupVerified"];
const UUID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const REQUIRED_SOURCES=require("./certops-retention24h-sources").REQUIRED_SOURCES;
function exactKeys(value,keys){assert.ok(value&&typeof value==="object"&&!Array.isArray(value));assert.deepEqual(Object.keys(value).sort(),keys.slice().sort());}
function time(value){assert.equal(typeof value,"string");assert.match(value,/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$/);assert.ok(value.length<=40&&Number.isFinite(Date.parse(value)));return Date.parse(value);}
function verifyProof(p){
 exactKeys(p,["scope",...FLAGS,"interruptedDelete","candidateSha","prepareRunId","prepareRunAttempt","nonce","vmId","processId","bootTime","processCreatedAt","taskXmlSha256","configSha256","nodeSha256","keeperSha256","collectorHelperSha256","ledgerIdentitySha256","retentionHours","monotonicElapsedMs","keptSweepCount","maximumSweepGapMs","originalCreatedAt","verifiedCutoverAt","oldNotAfter","cleanupDeadline","startedAt","finishedAt","preDeadlineObservedAt","cleanupFinishedAt","requestIds","enrollmentIds","jobIds","thumbprints","containerNames","fingerprints","spkiSha256","serialNumbers"]);
 require("../tests/e2e/helpers/certops-retention24h-interrupted").verifyProof(p.interruptedDelete);
 assert.equal(p.interruptedDelete.cleanupDeadline,p.cleanupDeadline);assert.ok(p.interruptedDelete.monotonicElapsedBeforeCrashMs<=p.monotonicElapsedMs);
 assert.ok(time(p.interruptedDelete.interruptedAt)>=time(p.startedAt)+p.interruptedDelete.monotonicElapsedBeforeCrashMs-5000);assert.ok(time(p.interruptedDelete.resumedAt)<=time(p.finishedAt));
 assert.equal(p.scope,SCOPE);for(const flag of FLAGS)assert.equal(p[flag],true,flag);
 assert.match(p.candidateSha,/^[a-f0-9]{40}$/);for(const k of ["prepareRunId","prepareRunAttempt"])assert.match(p[k],/^[1-9][0-9]{0,19}$/);
 assert.match(p.vmId,UUID);assert.ok(Number.isInteger(p.processId)&&p.processId>0&&p.processId<=0xffffffff);time(p.bootTime);time(p.processCreatedAt);
 for(const k of ["nonce","taskXmlSha256","configSha256","nodeSha256","keeperSha256","collectorHelperSha256","ledgerIdentitySha256"])assert.match(p[k],/^[a-f0-9]{64}$/);
 assert.equal(p.retentionHours,24);assert.ok(Number.isInteger(p.monotonicElapsedMs)&&p.monotonicElapsedMs>=contract.DAY&&p.monotonicElapsedMs<=contract.DAY+contract.HOUR);
 assert.ok(Number.isInteger(p.keptSweepCount)&&p.keptSweepCount>=24&&p.keptSweepCount<=26);assert.ok(Number.isInteger(p.maximumSweepGapMs)&&p.maximumSweepGapMs>0&&p.maximumSweepGapMs<=3900000);
 const created=time(p.originalCreatedAt),cut=time(p.verifiedCutoverAt),deadline=time(p.cleanupDeadline),start=time(p.startedAt),end=time(p.finishedAt),pre=time(p.preDeadlineObservedAt),clean=time(p.cleanupFinishedAt);
 assert.ok(created<=cut&&cut<=start&&start-cut<=600000);assert.ok(created<=time(p.bootTime)&&time(p.bootTime)<=time(p.processCreatedAt)&&time(p.processCreatedAt)<=start);assert.equal(deadline,cut+contract.DAY);assert.ok(time(p.oldNotAfter)>deadline+contract.HOUR);
 assert.ok(start<=pre&&pre<deadline&&deadline<end&&end<=clean&&clean<=created+contract.MAX);assert.ok(Math.abs(end-start-p.monotonicElapsedMs)<=5000);
 for(const[field,pattern]of [["requestIds",/^[1-9][0-9]{0,9}$/],["enrollmentIds",UUID],["jobIds",UUID],["thumbprints",/^[A-F0-9]{40}$/],["containerNames",/^tokentimer-enr-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/],["fingerprints",/^[a-f0-9]{64}$/],["spkiSha256",/^[a-f0-9]{64}$/],["serialNumbers",/^[a-f0-9]{1,128}$/]]){
  assert.ok(Array.isArray(p[field]));assert.equal(p[field].length,2);assert.equal(new Set(p[field].map(v=>typeof v==="string"?v.toLowerCase():v)).size,2);for(const value of p[field])assert.match(value,pattern);
 }
 for(let i=0;i<2;i++){assert.ok(Number(p.requestIds[i])<=0xffffffff);assert.equal(p.containerNames[i],`tokentimer-enr-${p.enrollmentIds[i]}`);}return true;
}
function verifyCompositeProof(c,{requireCleanup=true}={}){
 assert.ok(c&&typeof c==="object");assert.equal(c.schemaVersion,1);assert.equal(c.scope,SCOPE);assert.equal(c.immutablePrepareArtifactVerified,true);
 contract.verifyOriginalLease(c.lease,c.preparedLease);assert.equal(c.lease.phase,"keeper-owned");assert.equal(c.candidateSha,c.lease.candidateSha);assert.equal(c.prepareRunId,c.lease.runId);assert.equal(c.prepareRunAttempt,c.lease.runAttempt);
 const prep=c.publicPreparation,hand=c.handoffObserved,final=c.finalObserved,result=c.residentResult;
 assert.equal(prep.scope,"prepared-real-domain-adcs-retention24h-not-elapsed-qualified");assert.deepEqual(prep.lease,c.preparedLease);assert.ok(time(hand.nativeVerificationStartedAt)>=time(prep.finishedAt));assert.ok(time(hand.nativeVerificationFinishedAt)>=time(hand.nativeVerificationStartedAt));contract.attestHandoff(c.preparedLease,hand,new Date(time(hand.nativeVerificationFinishedAt)).toISOString());
 for(const observation of [hand,final])for(const key of contract.IDENTITY)assert.equal(observation[key],c.lease[key]);
 assert.equal(hand.taskState,"Running");assert.equal(final.taskState,"Ready");assert.equal(final.principalSid,"S-1-5-18");assert.equal(final.currentNativeDeletionVerified,true);
 for(const field of ["nativeCustodyVerified","trustedTlsVerified","soleAgentStoppedAndDrained","productionCutoverVerified","ledgerUnmodified","taskXmlVerified","vmIdentityVerified","nodeHashVerified","keeperHashVerified","residentProcessVerified","replacementCngCustodyVerified","replacementIisSniBindingVerified"])for(const observation of [hand,final])assert.equal(observation[field],true,field);
 for(const field of ["configSha256","processId","processCreatedAt","bootTime","taskXmlSha256"])assert.equal(final[field],hand[field]);
 for(const key of [...contract.IDENTITY,"configSha256","processId","processCreatedAt","bootTime","taskXmlSha256"])assert.equal(prep.task[key],hand[key]);
 assert.ok(time(prep.task.nativeVerificationFinishedAt)<=time(prep.finishedAt));
 assert.equal(final.actualPredecessorCertificateAbsent,true);assert.equal(final.actualPredecessorKeyAbsent,true);assert.equal(hand.actualPredecessorCertificateAbsent,false);assert.equal(hand.actualPredecessorKeyAbsent,false);
 assert.equal(prep.configSha256,hand.configSha256);assert.equal(prep.soleAgentStoppedAndDrained,true);assert.deepEqual(final.residentResult,result);
 require("../tests/e2e/helpers/certops-retention24h-interrupted").verifyProof(result.interruptedDelete);assert.equal(result.interruptedDelete.cleanupDeadline,prep.cleanupDeadline);
 assert.equal(result.scope,"resident-timing-only-native-oracles-required");assert.equal(result.collector,"production-default-clock");for(const flag of ["nativeCustodyVerified","trustedTlsVerified","actualProductionLedgerVerified"])assert.equal(result[flag],true);
 for(const[field,key]of [["pid","processId"],["processCreatedAt","processCreatedAt"],["bootTime","bootTime"],["configSha256","configSha256"]])assert.equal(result[field],hand[key]);assert.equal(result.candidateSha,c.candidateSha);assert.equal(result.nonce,c.lease.nonce);assert.equal(result.retentionHours,24);
 assert.ok(Array.isArray(prep.fixtureSources)&&prep.fixtureSources.length<=64);const seen=new Set();for(const item of prep.fixtureSources){exactKeys(item,["file","sha256"]);assert.ok(REQUIRED_SOURCES.includes(item.file));assert.equal(seen.has(item.file),false);seen.add(item.file);assert.match(item.sha256,/^[a-f0-9]{64}$/);}assert.equal(seen.size,REQUIRED_SOURCES.length);assert.equal(prep.sourceCount,seen.size);
 assert.match(prep.collectorHelper.file,/^packages\/agent\/(?:bin\/tokentimer-adcs-chain-amd64.exe|reference\/adcs-chain\/dist\/tokentimer-adcs-chain-windows-amd64.exe)$/);assert.match(prep.collectorHelper.sha256,/^[a-f0-9]{64}$/);assert.match(prep.ledgerIdentitySha256,/^[a-f0-9]{64}$/);
 assert.ok(Array.isArray(prep.generations)&&prep.generations.length===2);assert.deepEqual(c.actualRequestIds,prep.actualRequestIds);assert.deepEqual(c.fingerprints,prep.fingerprints);
 assert.ok(time(prep.startedAt)<=time(prep.verifiedCutoverAt)&&time(prep.finishedAt)>=time(prep.verifiedCutoverAt));
 for(const key of ["verifiedCutoverAt","oldNotAfter","cleanupDeadline"])for(const observation of [hand,final])assert.equal(observation[key],prep[key]);
 assert.ok(time(final.nativeVerificationStartedAt)>=time(result.finishedAt));assert.ok(time(final.nativeVerificationFinishedAt)>=time(final.nativeVerificationStartedAt));assert.ok(time(c.collectedAt)>=time(final.nativeVerificationFinishedAt));
 if(requireCleanup)assert.equal(c.cleanup,"completed");else assert.ok(["pending","completed"].includes(c.cleanup));
 const proof={scope:SCOPE,interruptedDelete:result.interruptedDelete,...Object.fromEntries(FLAGS.map(flag=>[flag,true])),candidateSha:c.candidateSha,prepareRunId:c.prepareRunId,prepareRunAttempt:c.prepareRunAttempt,nonce:c.lease.nonce,vmId:c.lease.vmId,processId:hand.processId,bootTime:hand.bootTime,processCreatedAt:hand.processCreatedAt,taskXmlSha256:hand.taskXmlSha256,configSha256:prep.configSha256,nodeSha256:c.lease.nodeSha256,keeperSha256:c.lease.keeperSha256,collectorHelperSha256:prep.collectorHelper.sha256,ledgerIdentitySha256:prep.ledgerIdentitySha256,retentionHours:24,monotonicElapsedMs:result.monotonicElapsedMs,keptSweepCount:result.keptSweepCount,maximumSweepGapMs:result.maximumSweepGapMs,originalCreatedAt:c.preparedLease.createdAt,verifiedCutoverAt:prep.verifiedCutoverAt,oldNotAfter:prep.oldNotAfter,cleanupDeadline:prep.cleanupDeadline,startedAt:result.startedAt,finishedAt:result.finishedAt,preDeadlineObservedAt:result.preDeadlineObservedAt,cleanupFinishedAt:requireCleanup?c.cleanupFinishedAt:c.collectedAt,
 requestIds:prep.generations.map(g=>g.requestId),enrollmentIds:prep.generations.map(g=>g.enrollmentId),jobIds:prep.generations.map(g=>g.jobId),thumbprints:prep.generations.map(g=>g.thumbprint),containerNames:prep.generations.map(g=>g.containerName),fingerprints:prep.fingerprints,spkiSha256:prep.generations.map(g=>g.spkiSha256),serialNumbers:prep.generations.map(g=>g.serial.toLowerCase())};
 assert.deepEqual(proof.requestIds,prep.actualRequestIds);verifyProof(proof);if(!requireCleanup)proof.ownedAzureCleanupVerified=false;return proof;
}
function createQualificationReport(c){
 const proof=verifyCompositeProof(c);const intervals=[[c.publicPreparation.startedAt,c.publicPreparation.finishedAt],[proof.startedAt,proof.finishedAt],[proof.interruptedDelete.interruptedAt,proof.interruptedDelete.resumedAt],[c.finalObserved.nativeVerificationStartedAt,c.cleanupFinishedAt]];
 const source="scripts/certops-retention24h-runtime.js",digest=c.publicPreparation.fixtureSources.find(item=>item.file===source);assert.ok(digest);
 const capabilities=Object.fromEntries(["windows","elevated","domain","sameVmResidentKeeper"].map(name=>[name,{available:true}]));
 return {schemaVersion:1,suite:SUITE,candidateSha:c.candidateSha,strict:true,status:"passed",evidenceLevel:"real-host",startedAt:c.publicPreparation.startedAt,finishedAt:c.cleanupFinishedAt,requiredCapabilities:Object.keys(capabilities),capabilities,missingCapabilities:[],requiredScenarios:REQUIRED_SCENARIOS,missingScenarios:[],scenarios:REQUIRED_SCENARIOS.map((id,i)=>({id,status:"passed",evidenceLevel:"real-host",startedAt:intervals[i][0],finishedAt:intervals[i][1]})),cleanup:{status:"passed"},qualificationEnvironment:{osFamily:"windows",osVersion:"2022",nativeLanguage:"en-US",identity:"LocalSystem",measurement:"native"},fixtureSource:digest,fixtureSources:c.publicPreparation.fixtureSources,artifactQualification:"workflow-checkout-source",retention24hProvenance:c.retention24hProvenance,nativeRetention24h:proof};
}
module.exports={SCOPE,SUITE,FLAGS,REQUIRED_SCENARIOS,REQUIRED_SOURCES,verifyProof,verifyCompositeProof,createQualificationReport};
