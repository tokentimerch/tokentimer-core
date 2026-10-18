"use strict";
// Enforce trusted refs, bounded privileges and owned cleanup across every
// qualification workflow; selection may only narrow the exact main guard.
const fs=require("node:fs"),path=require("node:path");
// Only this closed handoff protocol may deliberately retain its successful lab.
// Every other provisioner still needs unconditional owned teardown.
function retainedDayProtocol(workflow,id,job){
 if(id!=="prepare"||JSON.stringify(Object.keys(workflow.jobs||{}))!==JSON.stringify(["prepare"])||JSON.stringify(Object.keys(workflow.on||{}))!==JSON.stringify(["workflow_dispatch"])||job.environment!=="certops-adcs-lab")return false;
 if(workflow.concurrency?.group!=="certops-retention24h-prepare-${{ github.run_id }}-${{ github.run_attempt }}"||workflow.concurrency?.["cancel-in-progress"]!==false)return false;
 const steps=job.steps||[];
 const locate=predicate=>{const found=steps.map((step,index)=>predicate(step)?index:-1).filter(index=>index>=0);return found.length===1?found[0]:-1;};
 const success=step=>step.if===undefined||step.if==="success()";
 const provision=locate(step=>step.run==="./infra/certops-adcs/provision-lab.ps1 -ResourceGroup $env:LAB_GROUP -Hours 4 -WindowsVersion 2022 -Language en-US -Retention24hPrepare 1 -Retention24hNonce $env:CERTOPS_RETENTION24H_NONCE"&&success(step));
 const seal=locate(step=>step.run==="node scripts/certops-retention24h-azure.js seal"&&success(step));
 const original=locate(step=>step.uses?.startsWith("actions/upload-artifact@")&&step.if==="always()"&&step.with?.path==="qualification-results/retention24h-original.json"&&step.with?.name==="retention24h-original-${{ github.run_attempt }}-${{ env.CERTOPS_RETENTION24H_NONCE }}"&&step.with?.["if-no-files-found"]==="error");
 const handoff=locate(step=>step.run==="node scripts/certops-retention24h-azure.js handoff"&&success(step));
 const owned=locate(step=>step.uses?.startsWith("actions/upload-artifact@")&&step.if==="always()"&&step.with?.path==="qualification-results/retention24h-ownership.json"&&step.with?.name==="retention24h-prepare-ownership-${{ github.run_attempt }}-${{ env.CERTOPS_RETENTION24H_NONCE }}"&&step.with?.["if-no-files-found"]==="error");
 const cleanup=locate(step=>step.if==="failure() || cancelled()"&&step.run==="node scripts/certops-retention24h-azure.js abort");
 return provision>=0&&provision<seal&&seal<original&&original<handoff&&handoff<owned&&owned<cleanup&&cleanup===steps.length-1;
}
function retainedCadenceProtocol(workflow,id,job){
 // The cadence campaign has its own immutable receipts and bounded observer;
 // borrowing the day-long campaign's exception would bypass those controls.
 if(id!=="prepare"||JSON.stringify(Object.keys(workflow.jobs||{}))!==JSON.stringify(["prepare"])||JSON.stringify(Object.keys(workflow.on||{}))!==JSON.stringify(["workflow_dispatch"])||job.environment!=="certops-adcs-lab")return false;
 if(workflow.concurrency?.group!=="certops-retention-cadence-prepare-${{ github.run_id }}-${{ github.run_attempt }}"||workflow.concurrency?.["cancel-in-progress"]!==false)return false;
 const steps=job.steps||[];
 const locate=predicate=>{const found=steps.map((step,index)=>predicate(step)?index:-1).filter(index=>index>=0);return found.length===1?found[0]:-1;};
 const success=step=>step.if===undefined||step.if==="success()";
 const provision=locate(step=>step.run==="./infra/certops-adcs/provision-lab.ps1 -ResourceGroup $env:LAB_GROUP -Hours 4 -WindowsVersion 2022 -Language en-US -RetentionCadencePrepare 1 -RetentionCadenceNonce $env:CERTOPS_RETENTION_CADENCE_NONCE"&&success(step));
 const seal=locate(step=>step.run==="node scripts/certops-retention-cadence-azure.js seal"&&success(step));
 const original=locate(step=>step.uses?.startsWith("actions/upload-artifact@")&&step.if==="always()"&&step.with?.path==="qualification-results/retention-cadence-original.json"&&step.with?.name==="retention-cadence-original-${{ github.run_attempt }}-${{ env.CERTOPS_RETENTION_CADENCE_NONCE }}"&&step.with?.["if-no-files-found"]==="error");
 const handoff=locate(step=>step.run==="node scripts/certops-retention-cadence-azure.js handoff"&&success(step));
 const owned=locate(step=>step.uses?.startsWith("actions/upload-artifact@")&&step.if==="always()"&&step.with?.path==="qualification-results/retention-cadence-ownership.json"&&step.with?.name==="retention-cadence-ownership-${{ github.run_attempt }}-${{ env.CERTOPS_RETENTION_CADENCE_NONCE }}"&&step.with?.["if-no-files-found"]==="error");
 const cleanup=locate(step=>step.if==="failure() || cancelled()"&&step.run==="node scripts/certops-retention-cadence-azure.js abort");
 return provision>=0&&provision<seal&&seal<original&&original<handoff&&handoff<owned&&owned<cleanup&&cleanup===steps.length-1;
}
function retainedAdcsTtlProtocol(workflow,id,job){
 if(id!=="prepare"||JSON.stringify(Object.keys(workflow.jobs||{}))!==JSON.stringify(["prepare"])||JSON.stringify(Object.keys(workflow.on||{}))!==JSON.stringify(["workflow_dispatch"])||job.environment!=="certops-adcs-lab")return false;
 if(workflow.concurrency?.group!=="certops-adcs-ttl24h-prepare-${{ github.run_id }}-${{ github.run_attempt }}"||workflow.concurrency?.["cancel-in-progress"]!==false)return false;
 const steps=job.steps||[];
 const locate=predicate=>{const found=steps.map((step,index)=>predicate(step)?index:-1).filter(index=>index>=0);return found.length===1?found[0]:-1;};
 const success=step=>step.if===undefined||step.if==="success()";
 const provision=locate(step=>step.run==="./infra/certops-adcs/provision-lab.ps1 -ResourceGroup $env:LAB_GROUP -Hours 4 -WindowsVersion 2022 -Language en-US -AdcsTtl24hPrepare 1 -AdcsTtl24hNonce $env:CERTOPS_ADCS_TTL24H_NONCE"&&success(step));
 const seal=locate(step=>step.run==="node scripts/certops-adcs-ttl24h-azure.js seal"&&success(step));
 const original=locate(step=>step.uses?.startsWith("actions/upload-artifact@")&&step.if==="always()"&&step.with?.path==="qualification-results/adcs-ttl24h-original.json"&&step.with?.name==="adcs-ttl24h-original-${{ github.run_attempt }}-${{ env.CERTOPS_ADCS_TTL24H_NONCE }}"&&step.with?.["if-no-files-found"]==="error");
 const handoff=locate(step=>step.run==="node scripts/certops-adcs-ttl24h-azure.js handoff"&&success(step));
 const owned=locate(step=>step.uses?.startsWith("actions/upload-artifact@")&&step.if==="always()"&&step.with?.path==="qualification-results/adcs-ttl24h-ownership.json"&&step.with?.name==="adcs-ttl24h-ownership-${{ github.run_attempt }}-${{ env.CERTOPS_ADCS_TTL24H_NONCE }}"&&step.with?.["if-no-files-found"]==="error");
 const cleanup=locate(step=>step.if==="failure() || cancelled()"&&step.run==="node scripts/certops-adcs-ttl24h-azure.js abort");
 return provision>=0&&provision<seal&&seal<original&&original<handoff&&handoff<owned&&owned<cleanup&&cleanup===steps.length-1;
}

function validateWorkflow(workflow,name="workflow"){

  const errors=[];const fail=message=>errors.push(`${name}: ${message}`);
  for(const issue of require("./certops-azure-scope-policy").validate(name,workflow))fail(issue);
  if(/^certops-.*\.yml$/.test(name)&&!workflow.name?.startsWith("CertOps / "))fail("qualification workflow display name must use the CertOps / prefix");
  const events=typeof workflow.on==="string"?[workflow.on]:Object.keys(workflow.on||{});
  if(!events.length||events.some(event=>!["push","workflow_dispatch","schedule"].includes(event)))fail("qualification may run only trusted push, manual or cleanup schedule events");
  if(events.includes("push")&&JSON.stringify(workflow.on.push?.branches)!==JSON.stringify(["main"]))fail("push qualification must select only main");
  const permissions=workflow.permissions||{};if(typeof permissions!=="object")fail("explicit read-only permissions required");
  for(const [key,value] of Object.entries(permissions))if(!(["contents","actions"].includes(key)&&value==="read")&&!(key==="id-token"&&value==="write"))fail(`unsupported token permission ${key}`);
  if(permissions.contents!=="read")fail("contents read permission required");
  for(const [id,job] of Object.entries(workflow.jobs||{})){
    if(name==="certops-adcs-lab-janitor.yml"&&job.environment!=="certops-adcs-cleanup")fail(`${id} independent expiry cleanup requires its dedicated unattended environment`);
    const scopedApi = name === "certops-qualification.yml" && id === "adcs-api" && job.if === "github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.lane != 'tooling'";
    const scopedAggregate = name === "certops-distribution-qualification.yml" && id === "functional-summary" && JSON.stringify(job.needs) === JSON.stringify(["postgres", "agent-lab"]) && job.if === "${{ always() && github.ref == 'refs/heads/main' }}";
    if(job.if!=="github.ref == 'refs/heads/main'"&&!scopedApi&&!scopedAggregate&&!require("./certops-azure-scope-policy").allowedCondition(name,job.if))fail(`${id} must enforce the exact trusted main reference`);
    if(!Number.isInteger(job["timeout-minutes"])||job["timeout-minutes"]<1||job["timeout-minutes"]>180)fail(`${id} requires a bounded timeout`);
    if(job.permissions)for(const [key,value] of Object.entries(job.permissions))if(!(["contents","actions"].includes(key)&&value==="read")&&!(key==="id-token"&&value==="write"))fail(`${id} expands token permissions`);
    if((permissions["id-token"]==="write"||job.permissions?.["id-token"]==="write")&&!job.environment)fail(`${id} OIDC requires a protected qualification environment`);
    const steps=job.steps||[],runs=steps.map(step=>step.run||"").join("\n");
    const retainedDay=name==="certops-retention24h-prepare.yml"&&retainedDayProtocol(workflow,id,job);
    const retainedCadence=name==="certops-retention-cadence-prepare.yml"&&retainedCadenceProtocol(workflow,id,job);
    if(name==="certops-retention-cadence-prepare.yml"&&!retainedCadence)fail(`${id} installed timer handoff requires its complete original-artifact-first owned lifecycle`);
    if(["certops-retention-cadence-finalize.yml","certops-retention-cadence-janitor.yml"].includes(name)){
      if(job.environment!=="certops-adcs-cleanup")fail(`${id} installed timer cleanup requires its dedicated unattended environment`);
      if(workflow.concurrency?.group!=="certops-retention24h-owned-azure-lifecycle"||workflow.concurrency?.["cancel-in-progress"]!==false)fail(`${id} installed timer cleanup requires fixed non-cancelling serialization`);
    }
    const retainedAdcsTtl=name==="certops-adcs-ttl24h-prepare.yml"&&retainedAdcsTtlProtocol(workflow,id,job);
    if(name==="certops-adcs-ttl24h-prepare.yml"&&!retainedAdcsTtl)fail(`${id} ADCS default TTL handoff requires its complete original-artifact-first owned lifecycle`);
    if(["certops-adcs-ttl24h-finalize.yml","certops-adcs-ttl24h-janitor.yml"].includes(name)&&job.environment!=="certops-adcs-cleanup")fail(`${id} ADCS default TTL cleanup requires its dedicated unattended environment`);
    if(["certops-adcs-ttl24h-finalize.yml","certops-adcs-ttl24h-janitor.yml"].includes(name)&&(workflow.concurrency?.group!=="certops-adcs-ttl24h-cleanup"||workflow.concurrency?.["cancel-in-progress"]!==false))fail(`${id} ADCS default TTL cleanup requires fixed non-cancelling serialization`);
    if(name==="certops-retention24h-prepare.yml"&&!retainedDay)fail(`${id} retention handoff requires its complete original-artifact-first owned lifecycle`);
    if(["certops-retention24h-finalize.yml","certops-retention24h-janitor.yml"].includes(name)&&job.environment!=="certops-adcs-cleanup")fail(`${id} retention cleanup requires its dedicated unattended environment`);
    if(["certops-retention24h-finalize.yml","certops-retention24h-janitor.yml"].includes(name)&&(workflow.concurrency?.group!=="certops-retention24h-owned-azure-lifecycle"||workflow.concurrency?.["cancel-in-progress"]!==false))fail(`${id} retention lifecycle requires fixed non-cancelling serialization`);

    for(const step of steps){
      if(step.uses&&!/^[-A-Za-z0-9_./]+@[a-f0-9]{40}$/.test(step.uses))fail(`${id} action must use an immutable commit`);
      if(step.uses?.startsWith("actions/checkout@")&&step.with?.["persist-credentials"]!==false)fail(`${id} checkout must not persist credentials`);
      if(step.uses?.startsWith("actions/upload-artifact@")){
        if(step.if!=="always()")fail(`${id} must preserve diagnostic reports after failure`);
        const artifact=String(step.with?.path||"");if(!artifact||artifact.split(/\r?\n/).some(line=>line&&(!/^((candidate\/)?qualification-results\/)/.test(line)||line.replace(/\\/g,"/").split("/").includes(".."))))fail(`${id} artifacts must stay in the sanitized report directory`);
      }
      if(typeof step.run==="string"&&/\$\{\{\s*(inputs\.|github\.event\.inputs\.)/.test(step.run))fail(`${id} manual inputs must be passed through environment or typed arguments, not interpolated into shell code`);
    }
    for(const [creates,destroys,label] of [[/docker compose[^\n]*\bup\b/,/docker compose[^\n]*\bdown\b/,"Compose"],[/kind create cluster/,/kind delete cluster/,"kind"],[/provision-lab\.ps1/,/remove-owned-lab\.ps1/,"Azure lab"]]){
      if(creates.test(runs)&&!(label==="Azure lab"&&(retainedDay||retainedAdcsTtl||retainedCadence))&&!steps.some(step=>step.if==="always()"&&destroys.test(step.run||"")))fail(`${id} ${label} requires independent always cleanup`);
    }
  }
  return errors;
}
function check(root=path.resolve(__dirname,"..")){
  const {createRequire}=require("node:module");const yaml=createRequire(require.resolve(path.join(root,"node_modules/mocha/package.json")))("js-yaml");
  const directory=path.join(root,".github/workflows");const errors=[];for(const name of fs.readdirSync(directory).filter(file=>/^certops-.*\.yml$/.test(file)))errors.push(...validateWorkflow(yaml.load(fs.readFileSync(path.join(directory,name),"utf8")),name));return errors;
}
if(require.main===module){const errors=check();if(errors.length){console.error(errors.join("\n"));process.exitCode=1;}else console.log("certops-workflow-security: trusted refs, immutable actions, credential isolation and owned cleanup valid");}
module.exports={validateWorkflow,check};
