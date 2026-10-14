"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {filesystemSafeJobId,resolveAdcsCmcHelperPath}=require("../../../packages/agent/src/issuers/adcs-enrollment");
const {decodeCmcResponse}=require("../../../packages/agent/src/issuers/cmc-helper");
async function qualifyNativeCmcBoundaries({gate,configDir,workDir,pendingRecoveryFixtures}){
  await gate.scenario("adcs-real-native-cmc-signed-response-boundaries",async()=>{
    assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");
    const owned=pendingRecoveryFixtures.expire;assert.ok(owned?.created?.jobId);assert.ok(owned.pending.request_id);
    const scratch=path.join(configDir,"adcs-scratch"),prefix=`adcs-${filesystemSafeJobId(owned.created.jobId)}-submit-`;
    const candidates=fs.readdirSync(scratch,{withFileTypes:true}).filter(entry=>entry.isDirectory()&&entry.name.startsWith(prefix)).map(entry=>path.join(scratch,entry.name,"submit-response.rsp")).filter(file=>fs.existsSync(file));
    assert.equal(candidates.length,1,"Require exactly one freshly CA-signed owned initial pending response");
    const original=candidates[0],bytes=fs.readFileSync(original);assert.ok(bytes.length>0&&bytes.length<=65536);
    const digest=value=>crypto.createHash("sha256").update(value).digest("hex"),originalHash=digest(bytes);
    const helper=resolveAdcsCmcHelperPath();assert.equal(helper.error,undefined);const helperHash=digest(fs.readFileSync(helper.path));
    const directory=path.join(workDir,"native-cmc-boundaries");fs.mkdirSync(directory);let primaryError;
    try{
      const caCertPath=path.join(directory,"public-ca.cer");fs.writeFileSync(caCertPath,Buffer.from(owned.authority.certificateB64,"base64"));
      const base={helperPath:helper.path,caKeySha256:owned.authority.keySha256,caCertPath,timeoutMs:10000};
      const pristine=await decodeCmcResponse({...base,responsePath:original});assert.equal(pristine.ok,true);assert.equal(pristine.exitCode,0);assert.equal(pristine.result.disposition,"pending");assert.equal(pristine.result.requestId,Number(owned.pending.request_id));
      const cases=[{id:"empty",bytes:Buffer.alloc(0)},{id:"truncated",bytes:bytes.subarray(0,bytes.length-1)},{id:"trailing-data",bytes:Buffer.concat([bytes,Buffer.from([0])])},{id:"oversized",bytes:Buffer.alloc(65537)}];
      for(const entry of cases){const file=path.join(directory,`${entry.id}.rsp`);fs.writeFileSync(file,entry.bytes);const result=await decodeCmcResponse({...base,responsePath:file});assert.equal(result.ok,false,`${entry.id} must fail closed`);assert.equal(result.exitCode,2);assert.equal(result.result?.requestId,undefined);assert.equal(result.result?.certificateDerB64,undefined);}
      const wrongPin=owned.authority.keySha256==="0".repeat(64)?"1".repeat(64):"0".repeat(64);
      const rejected=await decodeCmcResponse({...base,responsePath:original,caKeySha256:wrongPin});assert.ok(!rejected.ok||rejected.result.disposition==="unknown");assert.notEqual(rejected.exitCode,0);assert.equal(rejected.result?.requestId,undefined);assert.equal(rejected.result?.certificateDerB64,undefined);
      assert.equal(digest(fs.readFileSync(original)),originalHash,"Native agent response must remain byte-for-byte unchanged");
      gate.report.nativeCmcBoundaries={caRequestId:String(owned.pending.request_id),responseSha256:originalHash,nativeHelperSha256:helperHash,actualCaSignedPending:true,actualPinnedSignatureVerified:true,refusedVariants:[...cases.map(entry=>entry.id),"wrong-ca-key-pin"],agentResponseUnchanged:true,syntheticCaResponse:false};
    }catch(error){primaryError=error;throw error;}finally{try{fs.rmSync(directory,{recursive:true,force:true});}catch(error){if(primaryError)throw new AggregateError([primaryError,error],"Native CMC boundaries and owned copy cleanup failed");throw error;}}
  },{evidenceLevel:"real-host",oracle:"fresh real CA-signed pending response decoded by actual compiled native helper, native signature/pin/request-ID independently verified, isolated malformed copies and wrong pin refused without changing the agent response"});
}
module.exports={qualifyNativeCmcBoundaries};
