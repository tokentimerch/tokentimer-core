"use strict";
// Enforce trusted refs, bounded privileges and owned cleanup across every
// qualification workflow; selection may only narrow the exact main guard.
const fs=require("node:fs"),path=require("node:path");
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
    const scopedApi = name === "certops-qualification.yml" && ["adcs-api", "integration"].includes(id) && job.if === "github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && inputs.lane != 'tooling'";
    const scopedAggregate = name === "certops-distribution-qualification.yml" && id === "functional-summary" && JSON.stringify(job.needs) === JSON.stringify(["postgres", "agent-lab"]) && job.if === "${{ always() && github.ref == 'refs/heads/main' }}";
    if(job.if!=="github.ref == 'refs/heads/main'"&&!scopedApi&&!scopedAggregate&&!require("./certops-azure-scope-policy").allowedCondition(name,job.if))fail(`${id} must enforce the exact trusted main reference`);
    if(!Number.isInteger(job["timeout-minutes"])||job["timeout-minutes"]<1||job["timeout-minutes"]>180)fail(`${id} requires a bounded timeout`);
    if(job.permissions)for(const [key,value] of Object.entries(job.permissions))if(!(["contents","actions"].includes(key)&&value==="read")&&!(key==="id-token"&&value==="write"))fail(`${id} expands token permissions`);
    if((permissions["id-token"]==="write"||job.permissions?.["id-token"]==="write")&&!job.environment)fail(`${id} OIDC requires a protected qualification environment`);
    const steps=job.steps||[],runs=steps.map(step=>step.run||"").join("\n");
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
      if(creates.test(runs)&&!steps.some(step=>step.if==="always()"&&destroys.test(step.run||"")))fail(`${id} ${label} requires independent always cleanup`);
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
