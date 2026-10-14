"use strict";
/* Independent evidence checks for the dedicated real-hour pending-expiry
 * workflow. This supplements mandatory scenario verification; it cannot turn
 * generic scenario success or scheduler time injection into elapsed proof. */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
function verify(report,{checkSource=true,expectedSha=process.env.GITHUB_SHA}={}){
 assert.equal(report.suite,"enterprise-adcs-elapsed-pending-real");assert.equal(report.status,"passed");assert.equal(report.strict,true);assert.notEqual(report.experimental,true);
 assert.match(report.candidateSha,/^[a-f0-9]{40}$/i);assert.equal(report.qualificationEnvironment.osVersion,"2022");assert.equal(report.qualificationEnvironment.nativeLanguage,"en-US");assert.equal(report.qualificationEnvironment.identity,"LocalSystem");assert.equal(report.qualificationEnvironment.measurement,"native");assert.equal(report.artifactQualification,"workflow-checkout-source");
 if(expectedSha)assert.equal(report.candidateSha,expectedSha);
 const required=["adcs-real-installed-native-language","adcs-real-agent-registration-system","adcs-real-rsa2048-issued-cng-iis","adcs-elapsed-pending-one-hour-terminal-cleanup","adcs-real-owned-cleanup"];
 assert.deepEqual([...report.requiredScenarios].sort(),[...required].sort());assert.equal(report.scenarios.length,required.length);
 for(const id of required){const actual=report.scenarios.filter(scenario=>scenario.id===id);assert.equal(actual.length,1);assert.equal(actual[0].status,"passed");}
 assert.ok(Date.parse(report.finishedAt)-Date.parse(report.startedAt)>=3600000);
 const facts=report.nativePendingElapsed;assert.ok(facts);assert.equal(facts.pendingTimeoutSeconds,3600);assert.equal(facts.pollIntervalSeconds,60);
 for(const field of ["monotonicWaitSeconds","databaseElapsedSeconds"])assert.ok(Number.isFinite(facts[field])&&facts[field]>=3600&&facts[field]<=4800);
 assert.equal(facts.clocks,"actual-host-and-database");assert.equal(facts.schedulerClock,"default-real-now");assert.equal(facts.databaseDatesRewritten,false);assert.equal(facts.journalRewritten,false);
 assert.equal(facts.qualificationScope,"configured-one-hour-not-default-fourteen-days");assert.ok(Number.isFinite(Date.parse(facts.pendingSince)));assert.match(facts.requestId,/^[1-9][0-9]{0,9}$/);assert.ok(Number(facts.requestId)<=0xffffffff);assert.match(facts.snapshotSha256,/^[a-f0-9]{64}$/i);
 for(const field of ["snapshotAndCsrStableAcrossRestart","keyProtectedBeforeDeadline","signedTerminalCleanup","exactKeyAbsent","noCertificateAccepted","noCaResubmission","lateApprovalTerminalRefusal","lateIssuedCertificateRevoked","outgoingTrustedTlsUnchanged"])assert.equal(facts[field],true);
 const file="tests/e2e/helpers/certops-adcs-pending-elapsed.js",sources=(report.fixtureSources||[]).filter(source=>source.file===file);assert.equal(sources.length,1);assert.match(sources[0].sha256,/^[a-f0-9]{64}$/i);
 if(checkSource)assert.equal(sources[0].sha256,crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"..",file))).digest("hex"));
 const producer="tests/e2e/certops-adcs-real-e2e.test.js";assert.equal(report.fixtureSource?.file,producer);assert.match(report.fixtureSource.sha256,/^[a-f0-9]{64}$/i);
 if(checkSource)assert.equal(report.fixtureSource.sha256,crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"..",producer))).digest("hex"));
 return true;
}
if(require.main===module){try{assert.equal(process.argv.length,3);verify(JSON.parse(fs.readFileSync(process.argv[2],"utf8")));process.stdout.write("Actual one-hour pending-expiry evidence verified\n");}catch{process.stderr.write("Elapsed pending-expiry evidence incomplete or invalid\n");process.exitCode=1;}}
module.exports={verify};
