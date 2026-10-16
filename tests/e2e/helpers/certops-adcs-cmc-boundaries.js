"use strict";
/* Native CMC signed-response boundary checks using real fixture enrollment material and the
 * candidate helper. Supporting protocol observations are distinct from full renewed-certificate
 * installation. Called only by the protected disposable-forest AD CS harness; native
 * qualification requires that workflow to execute.
 */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {filesystemSafeJobId,resolveAdcsCmcHelperPath}=require("../../../packages/agent/src/issuers/adcs-enrollment");
const {decodeCmcResponse}=require("../../../packages/agent/src/issuers/cmc-helper");
const {tamperCmsSignerSignature,responseDerBytes,scope,verifyProof}=require("./certops-adcs-cmc-signature-copy");
async function qualifyNativeCmcBoundaries({gate,configDir,workDir,pendingRecoveryFixtures}){
  await gate.scenario("adcs-real-native-cmc-signed-response-boundaries",async()=>{
    assert.equal(process.platform,"win32");assert.equal(process.env.CERTOPS_ADCS_DISPOSABLE_LAB,"1");
    gate.report.fixtureSources??=[];for(const file of ["tests/e2e/helpers/certops-adcs-cmc-boundaries.js","tests/e2e/helpers/certops-adcs-cmc-signature-copy.js"])if(!gate.report.fixtureSources.some(item=>item.file===file))gate.report.fixtureSources.push({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../../..",file))).digest("hex")});
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
      const der=responseDerBytes(bytes),tampered=tamperCmsSignerSignature(der);
      const pristineDerPath=path.join(directory,"pristine.der");fs.writeFileSync(pristineDerPath,der);const pristineDer=await decodeCmcResponse({...base,responsePath:pristineDerPath});assert.equal(pristineDer.ok,true);assert.equal(pristineDer.exitCode,0);assert.equal(pristineDer.result.disposition,"pending");assert.equal(pristineDer.result.requestId,Number(owned.pending.request_id));
      assert.equal(tampered.bytes.length,der.length);let changed=0;for(let i=0;i<der.length;i++)if(der[i]!==tampered.bytes[i]){changed++;assert.equal(i,tampered.signatureOffset);}assert.equal(changed,1);
      const cases=[{id:"empty",bytes:Buffer.alloc(0)},{id:"truncated",bytes:bytes.subarray(0,bytes.length-1)},{id:"trailing-data",bytes:Buffer.concat([bytes,Buffer.from([0])])},{id:"oversized",bytes:Buffer.alloc(65537)},{id:"signer-signature-tampered",bytes:tampered.bytes}];
      for(const entry of cases){const file=path.join(directory,`${entry.id}.rsp`);fs.writeFileSync(file,entry.bytes);const result=await decodeCmcResponse({...base,responsePath:file});assert.equal(result.ok,false,`${entry.id} must fail closed`);assert.equal(result.exitCode,2);assert.equal(result.result?.requestId,undefined);assert.equal(result.result?.certificateDerB64,undefined);}
      const wrongPin=owned.authority.keySha256==="0".repeat(64)?"1".repeat(64):"0".repeat(64);
      const rejected=await decodeCmcResponse({...base,responsePath:original,caKeySha256:wrongPin});assert.ok(!rejected.ok||rejected.result.disposition==="unknown");assert.notEqual(rejected.exitCode,0);assert.equal(rejected.result?.requestId,undefined);assert.equal(rejected.result?.certificateDerB64,undefined);
      assert.equal(digest(fs.readFileSync(original)),originalHash,"Native agent response must remain byte-for-byte unchanged");
      gate.report.nativeCmcBoundaries={scope,caRequestId:String(owned.pending.request_id),responseSha256:originalHash,nativeHelperSha256:helperHash,actualCaSignedPending:true,actualPinnedSignatureVerified:true,actualSignerSignatureByteTampered:true,actualPristineDerControlVerified:true,originalResponseDerSha256:digest(der),tamperedResponseDerSha256:digest(tampered.bytes),refusedVariants:[...cases.map(entry=>entry.id),"wrong-ca-key-pin"],agentResponseUnchanged:true,syntheticCaResponse:false};verifyProof(gate.report.nativeCmcBoundaries);
    }catch(error){primaryError=error;throw error;}finally{try{fs.rmSync(directory,{recursive:true,force:true});}catch(error){if(primaryError)throw new AggregateError([primaryError,error],"Native CMC boundaries and owned copy cleanup failed");throw error;}}
  },{evidenceLevel:"real-host",oracle:"fresh real CA-signed pending response decoded by actual compiled native helper, native signature/pin/request-ID independently verified, isolated malformed copies, exactly one located outer CMS signer signature byte tamper and wrong pin refused without changing the agent response"});
}
module.exports={qualifyNativeCmcBoundaries};
