"use strict";
/**
 * Verifies bounded experimental standalone CA/CMC reports against candidate and source identity.
 * Invoked by the standalone manual workflow; requires native observations and owned cleanup
 * while deliberately preserving experimental, nonqualified status outside the release matrix.
 */
const fs=require("node:fs");
const crypto=require("node:crypto");
const path=require("node:path");
const required=["pending-request-observed","issued-retrieved-accepted-nonexportable-cng","standalone-issued-iis-sni-trusted-tls"];
function verify(report,{candidateSha=process.env.GITHUB_SHA,sourceDigest}={}){
  const errors=[];
  if(!report||report.scope!=="standalone-native-certreq-cng-smoke"||report.caType!=="StandaloneRootCA")errors.push("Standalone feasibility scope required");
  if(report?.experimental!==true||report?.qualified!==false)errors.push("Standalone smoke must remain experimental and unqualified");
  if(!/^[a-f0-9]{40}$/i.test(candidateSha||"")||report?.candidateSha!==candidateSha)errors.push("Exact candidate identity required");
  if(report?.status!=="passed"||report?.cleanup!=="completed"||!Array.isArray(report?.cleanupErrors)||report.cleanupErrors.length)errors.push("Native cases and cleanup must pass");
  if(!report?.identity||!report?.host?.version||!report?.host?.build||report.host.measurement!=="native")errors.push("Native host and identity evidence required");
  const scenarios=report?.scenarios;
  if(!Array.isArray(scenarios)||scenarios.length!==required.length||new Set(scenarios).size!==required.length||required.some(id=>!scenarios.includes(id)))errors.push("Every mandatory native smoke case must execute once");
  if(sourceDigest&&report?.sourceSha256?.toLowerCase()!==sourceDigest.toLowerCase())errors.push("Current smoke source digest required");
  return errors;
}
if(require.main===module){
  try{
    const report=JSON.parse(fs.readFileSync(process.argv[2],"utf8"));
    const sourceDigest=crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"certops-standalone-adcs-smoke.ps1"))).digest("hex");
    const errors=verify(report,{sourceDigest});
    if(errors.length)throw new Error(errors.join("; "));
    console.log("Standalone native feasibility passed; enterprise qualification remains required");
  }catch{console.error("Standalone feasibility report verification failed");process.exitCode=1;}
}
module.exports={verify,required};
