#!/usr/bin/env node
"use strict";
// Explicit customer-local read-only recovery tool. Only public diagnostics
// leave this process; private material is read only into this agent's RAM.
const path=require("node:path");
const {loadAgentConfig,resolveConfigDir}=require("../src/config");
const {createPolicyEngine,loadPolicyConfig}=require("../src/policy");
const {readProtectedFile,UUID,failure}=require("../src/material-store");
const {preflightPinnedDeployment}=require("../src/material-store/lifecycle");
function readPublicPreflightIntent(file,bindingId){
  const intent=JSON.parse(readProtectedFile(path.resolve(file),16384));
  const fields=["groupId","bindingId","rolloutId","materialVersionId","materialStoreRef","providerVersion","fingerprintSha256","generation","deploymentProfileRef","profileRevision","authorizationRevision","verificationPolicy","verificationOnly","activationPolicy"];
  if(!intent || typeof intent!=="object" || Array.isArray(intent) || Object.keys(intent).some(key=>!fields.includes(key)) || intent.bindingId!==bindingId)throw failure("material_preflight_intent_invalid");
  return intent;
}
async function main(){
  const bindingId=process.argv[2];if(!UUID.test(bindingId || ""))throw new Error("material_binding_id_required");
  if(process.argv.length>3 && (process.argv[3]!=="--intent" || !process.argv[4] || process.argv.length!==5))throw failure("material_preflight_arguments_invalid");
  const config=loadAgentConfig({configDir:resolveConfigDir()});
  if(!config.execution?.keysDir)throw new Error("material_local_policy_unavailable");
  const stateDir=path.dirname(config.execution.keysDir);
  let intent;
  if(process.argv[3]==="--intent")intent=readPublicPreflightIntent(process.argv[4],bindingId);
  else{
    const record=JSON.parse(readProtectedFile(path.join(stateDir,"material-bindings",`${bindingId}.json`),16384));
    if(!record.intent)throw new Error("material_reconciliation_intent_missing");intent=record.intent;
  }
  const binding=config.materialBindings?.[bindingId];if(!binding)throw failure("material_binding_policy_denied");
  const report=await preflightPinnedDeployment({job:{workspaceId:binding.workspaceId,agentId:config.agentId,materialDeployment:intent},
    stores:config.materialStores,bindings:config.materialBindings,stateDir,policyEngine:createPolicyEngine(loadPolicyConfig(config.policy),{declaredTargetSelectors:config.declaredTargetSelectors})});
  process.stdout.write(JSON.stringify(report)+"\n");if(!report.ready)process.exitCode=1;
}
if(require.main===module)main().catch(error=>{process.stderr.write(`${/^material_[a-z_]+$/.test(error.code || error.message)?error.code || error.message:"material_preflight_failed"}\n`);process.exitCode=1;});
module.exports={readPublicPreflightIntent};
