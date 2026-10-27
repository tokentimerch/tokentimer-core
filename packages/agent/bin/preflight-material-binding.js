#!/usr/bin/env node
"use strict";
// Explicit customer-local read-only recovery tool. Only public diagnostics
// leave this process; private material is read only into this agent's RAM.
const path=require("node:path");
const {loadAgentConfig,resolveConfigDir}=require("../src/config");
const {createPolicyEngine,loadPolicyConfig}=require("../src/policy");
const {readProtectedFile,UUID}=require("../src/material-store");
const {preflightPinnedDeployment}=require("../src/material-store/lifecycle");
async function main(){
  const bindingId=process.argv[2];if(!UUID.test(bindingId || ""))throw new Error("material_binding_id_required");
  const config=loadAgentConfig({configDir:resolveConfigDir()});
  if(!config.execution?.keysDir)throw new Error("material_local_policy_unavailable");
  const stateDir=path.dirname(config.execution.keysDir);
  const record=JSON.parse(readProtectedFile(path.join(stateDir,"material-bindings",`${bindingId}.json`),16384));
  if(!record.intent)throw new Error("material_reconciliation_intent_missing");
  const report=await preflightPinnedDeployment({job:{workspaceId:record.intent.workspaceId,agentId:config.agentId,materialDeployment:record.intent},
    stores:config.materialStores,bindings:config.materialBindings,stateDir,policyEngine:createPolicyEngine(loadPolicyConfig(config.policy),{declaredTargetSelectors:config.declaredTargetSelectors})});
  process.stdout.write(JSON.stringify(report)+"\n");if(!report.ready)process.exitCode=1;
}
main().catch(error=>{process.stderr.write(`${/^material_[a-z_]+$/.test(error.code || error.message)?error.code || error.message:"material_preflight_failed"}\n`);process.exitCode=1;});
