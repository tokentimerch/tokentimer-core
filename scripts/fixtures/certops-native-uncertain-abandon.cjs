"use strict";
// Synthetic verifier inputs only; this does not execute a CA or delete a key.
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const h=require("../certops-adcs-uncertain-abandon-native"),browser=require("../../tests/e2e/helpers/certops-adcs-browser-abandon");
function parentReport(){
 const parent=require("./certops-native-browser-enrollment.cjs").parentReport(),root=path.resolve(__dirname,"../..");
 const id=n=>`${n.repeat(8)}-${n.repeat(4)}-${n.repeat(4)}-${n.repeat(4)}-${n.repeat(12)}`;
 parent.nativeUncertainAbandon={scope:"native-zero-request-uncertain-abandon",resolvedIssuingCaAddress:"10.64.0.4",leaseRemainingAtFaultMs:60000,recoveryWaitBudgetMs:150000,actualLeaseWaitMs:61000,caRequestsAtFault:0,caRequestsAfterRecovery:0,caRequestsAfterAbandon:0,...Object.fromEntries("ownedObserverDrained ownedTransportBlock observedSubmittingTermination actualLeaseExpiry acknowledgedPublicRecovery sameCsrAndKey noAutomaticResubmit publicAbandonAudited unacceptedKeyRemoved originalOrphanPreserved recoveryPolicyUnchanged".split(" ").map(k=>[k,true]))};
 parent.nativeBrowserAbandon={scope:browser.SCOPE,enrollmentId:id("1"),cleanupJobId:id("4"),abandonPosts:1,keepPosts:0,...Object.fromEntries(browser.FLAGS.map(k=>[k,true]))};
 parent.nativeUncertainAbandonIdentity={enrollmentId:id("1"),originalJobId:id("2"),recoveryJobId:id("3"),cleanupJobId:id("4"),containerName:`tokentimer-enr-${id("1")}`,csrSha256:"a".repeat(64),csrSpkiSha256:"b".repeat(64)};
 parent.fixtureSources=h.nativeRequiredSources().map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));
 const ids=h.nativeRequiredScenarios();for(const row of parent.scenarios){if(ids.includes(row.id)){row.startedAt="2026-10-18T00:01:00.000Z";row.finishedAt="2026-10-18T00:01:00.000Z";}}
 return parent;
}
function nativeReport(){const parent=parentReport();return h.createNativeReport(parent,{candidateSha:parent.candidateSha});}
module.exports={parentReport,nativeReport};
