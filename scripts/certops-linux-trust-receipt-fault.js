/**
 * Inject a receipt-finalization fault after a genuine native Linux trust refresh succeeds.
 * Imported by certops-linux-trust.js on an explicitly disposable root-owned host.
 * Only this fixture's receipt path is blocked; native refresh output is unchanged.
 * The oracle verifies pending-custody refusal, safe recovery and exact receipt cleanup. */
"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),{execFile}=require("node:child_process"),{randomUUID}=require("node:crypto");
const trust=require("../packages/agent/src/trust-store"),receipt=require("../packages/agent/src/trust-store/receipt");
async function receiptFinalizeRecovery({family,receiptDir,certificate,payload,input,job,verify,sourcePath}){
 assert.equal(process.platform,"linux");assert.equal(process.getuid(),0);assert.equal(process.env.CERTOPS_LINUX_TRUST_DISPOSABLE_HOST,"1");
 const store=family==="rhel"?"rhel-ca-trust":"debian-ca-certificates",row=path.join(receiptDir,receipt.receiptId(store,certificate.fingerprint)+".json"),saved=row+".held-"+randomUUID();
 assert.equal(fs.existsSync(row),false);assert.equal(fs.existsSync(saved),false);
 let held=false,blocker=false,triggered=false,injectionError;
 const restore=()=>{if(blocker){assert.equal(fs.readdirSync(row).length,0);fs.rmdirSync(row);blocker=false;}if(held){fs.renameSync(saved,row);held=false;}};
 const delegate=(file,args,options,callback)=>execFile(file,args,options,(error,stdout,stderr)=>{
  // Preserve the genuine native command and its unchanged result. The fault
  // only changes the run-owned receipt path after actual OS success.
  if(!error&&!triggered){try{assert.equal(path.basename(file),family==="rhel"?"update-ca-trust":"update-ca-certificates");assert.equal(receipt.readReceipt(receiptDir,store,certificate.fingerprint).row.state,"pending_install");fs.renameSync(row,saved);held=true;fs.mkdirSync(row,{mode:0o700});blocker=true;triggered=true;}catch(failure){injectionError=failure;}}
  callback(error,stdout,stderr);
 });
 try{
  const failed=await trust.distributeTrust({...input(payload),seams:{...input(payload).seams,execFileImpl:delegate}});
  assert.equal(injectionError,undefined);assert.equal(triggered,true,"Native refresh must actually succeed before receipt fault");assert.equal(failed.outcome,"installed");assert.equal(failed.mutationPerformed,true);assert.equal(failed.observedFingerprintAfter,certificate.fingerprint);assert.equal(failed.failureCategory,"receipt_finalize_conflict");assert.equal(failed.receipt.state,"intent_written");verify(certificate);assert.ok(fs.existsSync(sourcePath(certificate)));
  restore();assert.equal(receipt.readReceipt(receiptDir,store,certificate.fingerprint).row.state,"pending_install");
  const refused=await trust.revokeTrust(input(job(certificate,"root","revoke-trust")));assert.equal(refused.failureCategory,"receipt_pending_install");assert.equal(refused.mutationAttempted,false);verify(certificate);
  const repaired=await trust.distributeTrust(input({...payload,jobId:randomUUID()}));assert.equal(repaired.failureCategory,null);assert.equal(repaired.receipt.state,"finalized");assert.equal(receipt.readReceipt(receiptDir,store,certificate.fingerprint).row.state,"installed");verify(certificate);
  const revoked=await trust.revokeTrust(input(job(certificate,"root","revoke-trust")));assert.equal(revoked.failureCategory,null);assert.equal(revoked.outcome,"removed");assert.equal(fs.existsSync(sourcePath(certificate)),false);assert.equal(receipt.readReceipt(receiptDir,store,certificate.fingerprint).row.state,"removed");
 }finally{restore();assert.equal(fs.existsSync(saved),false);}
}
module.exports={receiptFinalizeRecovery};
