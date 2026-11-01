"use strict";
const path=require("node:path"),crypto=require("node:crypto"),fs=require("node:fs");
const {createVaultStore,writeProtectedJson,readProtectedFile,UUID,failure}=require("./index");
const {withMaterialLock}=require("./lifecycle");
const {canonicalizeJobPayload}=require("../../vendor/contracts/canonical-json.cjs");
const {cleanupIdentity,cleanupStoreIntent}=require("../../vendor/contracts/material-cleanup.cjs");
async function executeMaterialCleanup({job,stores,stateDir,checkLease,onBeforeMutation=()=>{},fixtureLoopbackHttp=false}){
  const intent=job.materialCleanup;
  if(!intent || ![job.jobId,intent.cleanupId,intent.groupId,intent.materialVersionId,intent.managementPeriodId,job.workspaceId].every(id=>UUID.test(id || "")) ||
    typeof checkLease!=="function")throw failure("material_cleanup_intent_invalid");
  const identity=cleanupIdentity(intent);
  const store=createVaultStore(stores,cleanupStoreIntent(intent,job.workspaceId),{fixtureLoopbackHttp});
  if(store.scope.cleanup?.softDelete!==true)throw failure("material_cleanup_policy_denied");
  if(job.mode==="dry_run")return {status:"dry_run_complete"};
  const hash=crypto.createHash("sha256").update(canonicalizeJobPayload(intent)).digest("hex");
  const record=path.join(stateDir,"material-cleanup",intent.cleanupId,`${job.jobId}.json`);
  return withMaterialLock(path.join(stateDir,"material-locks"),`issuer:${job.workspaceId}:${intent.groupId}`,async()=>{
    if(fs.existsSync(record)){
      const prior=JSON.parse(readProtectedFile(record,16384));
      if(prior.intentHash!==hash)throw failure("material_cleanup_intent_changed");
    }
    let mutated=false;
    try{
      await store.softDeleteVersion(intent.providerVersion,{checkLease,beforeDelete:async()=>{
        await checkLease();onBeforeMutation();
        writeProtectedJson(record,{intentHash:hash,cleanupId:intent.cleanupId,materialVersionId:intent.materialVersionId,uncertain:true});mutated=true;
      }});
      await checkLease();
      const receipt={schemaVersion:1,workspaceId:job.workspaceId,cleanupId:intent.cleanupId,groupId:intent.groupId,
        materialVersionId:intent.materialVersionId,providerVersion:intent.providerVersion,method:identity.method,softDeleted:true,observedAt:new Date().toISOString()};
      writeProtectedJson(record,{intentHash:hash,cleanupId:intent.cleanupId,materialVersionId:intent.materialVersionId,uncertain:false,receipt});
      return {status:"succeeded",cleanupReceipt:receipt};
    }catch(error){return {status:mutated || fs.existsSync(record)?"orphaned_unknown_effect":"blocked",errorMessage:/^material_[a-z_]+$/.test(error.code || "")?error.code:"material_cleanup_failed"};}
  });
}
module.exports={executeMaterialCleanup};
