"use strict";
/* Portable negative evidence checks only. These fabricated reports cannot prove
 * SCM upgrade; native authenticated version/state/TLS observations must come
 * from the dedicated trusted Windows workflow and matching source fingerprints. */
const {test}=require("node:test"),assert=require("node:assert/strict");
const {verifyUpgradeFacts,verifySourceUpgradeReport,requiredScenarios}=require("../e2e/helpers/certops-windows-source-upgrade");
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {historical}=require("../../scripts/certops-historical-windows-package");
function facts(){return {provenance:"historical-source-build",publishedArchiveUsedForInstallation:false,historicalCommit:historical.commit,historicalVersion:historical.version,historicalArchiveSha256:"a".repeat(64),historicalHelpers:{amd64:"b".repeat(64),arm64:"c".repeat(64)},candidateVersion:require("../../packages/agent/package.json").version,werPolicyPreserved:true,schedulerHistoryPreserved:true,distinctVersionObserved:true,configurationPreserved:true,credentialPreserved:true,signingKeyPinPreserved:true,sameAgentIdentity:true,authenticatedCandidateHeartbeat:true,candidateHelperActivated:true,nonExportableCngKeyPreserved:true,iisBindingPreserved:true,trustedTlsPreserved:true,serviceIdentityPreserved:true,ownedFixtureRemoved:true};}
test("complete distinct-source migration observations pass bounded verifier",()=>assert.equal(verifyUpgradeFacts(facts()),true));
test("same version, substituted source or falsely published provenance cannot qualify",()=>{for(const change of [{candidateVersion:historical.version},{candidateVersion:"99.0.0"},{historicalCommit:"a".repeat(40)},{historicalVersion:"0.17.3"},{publishedArchiveUsedForInstallation:true},{provenance:"published-release-archive"},{historicalArchiveSha256:"invalid"},{historicalHelpers:{amd64:"a".repeat(64)}}])assert.throws(()=>verifyUpgradeFacts({...facts(),...change}));});
test("loss of identity, actual history, CNG, binding, trust or cleanup fails migration proof",()=>{for(const field of Object.keys(facts()).filter(key=>facts()[key]===true))assert.throws(()=>verifyUpgradeFacts({...facts(),[field]:false}),field);});
test("source-upgrade report requires the primary harness fingerprint as well as supporting sources",()=>{
 const sources=["tests/e2e/helpers/certops-windows-source-upgrade.js","tests/e2e/windows-real-journey.js","scripts/certops-historical-windows-package.js"].map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(__dirname,"../..",file))).digest("hex")}));
 const report={suite:"windows-historical-source-upgrade",status:"passed",strict:true,requiredScenarios,scenarios:[{id:requiredScenarios[0],status:"passed"}],cleanup:{status:"passed"},candidateSha:"a".repeat(40),qualificationEnvironment:{osFamily:"windows",osVersion:"2022",measurement:"native",identity:"LocalSystem"},fixtureSource:sources[0],fixtureSources:sources,sourceUpgrade:facts()};
 assert.equal(verifySourceUpgradeReport(report,{expectedSha:report.candidateSha}),true);
 for(const primary of [undefined,{...sources[0],sha256:"0".repeat(64)},sources[1]])assert.throws(()=>verifySourceUpgradeReport({...report,fixtureSource:primary},{expectedSha:report.candidateSha}));
});
