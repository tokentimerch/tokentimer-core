#!/usr/bin/env node
"use strict";
// Explicit local operator command. Never prints config, keys, or raw errors.
const path=require("node:path");
const { loadAgentConfig,resolveConfigDir }=require("../src/config");
const { createPolicyEngine,loadPolicyConfig }=require("../src/policy");
const { readProtectedFile,UUID }=require("../src/material-store");
const { reconcilePinnedDeployment }=require("../src/material-store/lifecycle");
async function main() {
  const bindingId=process.argv[2];if(!UUID.test(bindingId||""))throw new Error("material_binding_id_required");
  const dir=resolveConfigDir(),config=loadAgentConfig({configDir:dir});
  const stateDir=path.dirname(config.execution.keysDir);
  const record=JSON.parse(readProtectedFile(path.join(stateDir,"material-bindings",`${bindingId}.json`),16384));
  if(!record.intent)throw new Error("material_reconciliation_intent_missing");
  const result=await reconcilePinnedDeployment({job:{workspaceId:record.intent.workspaceId,agentId:config.agentId,materialDeployment:record.intent},
    bindings:config.materialBindings,stateDir,policyEngine:createPolicyEngine(loadPolicyConfig(config.policy),{declaredTargetSelectors:config.declaredTargetSelectors})});
  process.stdout.write(JSON.stringify(result)+"\n");
}
main().catch((e)=>{process.stderr.write(`${/^material_[a-z_]+$/.test(e.code||e.message)?e.code||e.message:"material_reconciliation_failed"}\n`);process.exitCode=1;});
