"use strict";
// Synthetic offline report fixture only. Never a native qualification artifact.
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),h=require("../certops-arm64-scm-proof"),runtime=require("../certops-arm64-scm-runtime");
const candidateSha="a".repeat(40),root=path.resolve(__dirname,"../.."),stamp="2026-10-14T10:00:00.000Z";
function artifact(){
 const slot=require("../../docs/certops/qualification-suites.json").slots.find(row=>row.suite===h.suite);
 const native={scope:h.SCOPE,architecture:"arm64",productType:1,build:"26100",hostSha256:"a".repeat(64),archiveSha256:"b".repeat(64),realAgentQualified:false,apiQualified:false,fullInstallerQualified:false,iisQualified:false,serverQualified:false,retirementObservationMs:5001,generations:[0,1,2].map(i=>({hostPid:100+i,childPid:200+i,hostCreated:`2026-10-14T10:00:0${i}.0000000Z`,childCreated:`2026-10-14T10:00:0${i}.1000000Z`})),...Object.fromEntries(h.FLAGS.map(flag=>[flag,true]))};
 const capabilities=["windows","native-arm64","optIn"],sources=runtime.REQUIRED_SOURCES.map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}));
 const report={schemaVersion:1,suite:h.suite,strict:true,platform:"win32",architecture:"arm64",candidateSha,artifactQualification:"workflow-checkout-source",evidenceLevel:"real-host",status:"passed",startedAt:stamp,finishedAt:stamp,cleanup:{status:"passed"},requiredScenarios:[...h.REQUIRED_SCENARIOS],requiredCapabilities:capabilities,missingScenarios:[],missingCapabilities:[],capabilities:Object.fromEntries(capabilities.map(name=>[name,{available:true}])),scenarios:h.REQUIRED_SCENARIOS.map(id=>({id,status:"passed",evidenceLevel:"real-host",startedAt:stamp,finishedAt:stamp})),nativeArm64Scm:native,qualificationEnvironment:{...slot.environment,osVersion:"desktop-26100",measurement:"native"},fixtureSource:sources[0],fixtureSources:sources};
 return {kind:"host",suite:h.suite,environment:{...report.qualificationEnvironment},report};
}
module.exports={artifact,candidateSha};
