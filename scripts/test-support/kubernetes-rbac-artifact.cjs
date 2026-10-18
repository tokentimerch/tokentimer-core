"use strict";
/** Synthetic offline collector fixtures, never native execution receipts. */
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const h=require("../certops-kubernetes-rbac");
const contract=require("../certops-qualification-manifest");
const root=path.resolve(__dirname,"../..");
const CANDIDATE="a".repeat(40), SUITE="kubernetes-host";
function proof(){return {schemaVersion:1,scope:h.SCOPE,listStatus:403,watchStatus:403,createStatus:403,certificateUid:"11111111-1111-4111-8111-111111111111",createdCertificateUid:"22222222-2222-4222-8222-222222222222",missedResourceVersion:"101",watchedResourceVersion:"105",...Object.fromEntries(h.FLAGS.map(name=>[name,true]))};}
function artifact(){
  const environment={osFamily:"linux",measurement:"native"};
  const source=file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")});
  const time={startedAt:"2026-10-18T01:00:00Z",finishedAt:"2026-10-18T01:01:00Z"};
  const slot=require("../certops-qualification-manifest").slots.find(row=>row.suite===SUITE);
  const report={schemaVersion:1,suite:SUITE,platform:"linux",architecture:"x64",nodeVersion:"v24.18.0",strict:true,candidateSha:CANDIDATE,evidenceLevel:"real-host",status:"passed",...time,cleanup:{status:"passed"},artifactQualification:"workflow-checkout-source",qualificationEnvironment:environment,requiredScenarios:contract.suites[SUITE],requiredCapabilities:contract.requiredCapabilities[SUITE],missingScenarios:[],missingCapabilities:[],capabilities:Object.fromEntries(contract.requiredCapabilities[SUITE].map(name=>[name,{available:true}])),scenarios:contract.suites[SUITE].map(id=>({id,status:"passed",evidenceLevel:"real-host",...time})),fixtureSource:source(slot.source),fixtureSources:slot.requiredSources.map(source),nativeKubernetesRbacStartupRecovery:proof(),nativeCompaction:{expiredStatus:410,originalResourceVersion:"10",compactedRevision:"20",observedResourceVersion:"21",certificateUid:"11111111-1111-4111-8111-111111111111",productionClient:true,productionObserver:true,controlPlaneRestarted:true,ownedSingleNodeCluster:true}};
  return {kind:"host",suite:SUITE,environment,report};
}
module.exports={proof,artifact,CANDIDATE,SUITE};
