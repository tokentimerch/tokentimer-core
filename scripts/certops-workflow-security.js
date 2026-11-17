"use strict";
// Enforce trusted refs, bounded privileges and owned cleanup across every
// qualification workflow; selection may only narrow the exact main guard.
const fs=require("node:fs"),path=require("node:path");
const NODE_SETUP="./.github/actions/certops-node-setup";
// Only this resource-free local setup action may replace pinned setup steps.
function validateNodeSetup(action){
 const steps=action?.runs?.steps;
 const keys=(value,expected)=>value&&Object.keys(value).sort().join(",")===expected;
 const remote=(step,prefix)=>keys(step,"uses,with")&&new RegExp("^"+prefix+"@[a-f0-9]{40}$").test(step.uses);
 if(!keys(action,"description,name,runs")||!keys(action.runs,"steps,using")||action.runs.using!=="composite"||!Array.isArray(steps)||steps.length!==3||
    !remote(steps[0],"pnpm/action-setup")||!keys(steps[0].with,"version")||steps[0].with.version!==require("../package.json").packageManager.split("@").at(-1)||
    !remote(steps[1],"actions/setup-node")||!keys(steps[1].with,"cache,node-version")||steps[1].with["node-version"]!=="24"||steps[1].with.cache!=="pnpm"||
    !keys(steps[2],"run,shell")||steps[2].run!=="pnpm install --frozen-lockfile"||steps[2].shell!=="bash")return ["Local CertOps setup must contain only pinned Node/pnpm setup and frozen install"];
 return [];
}
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
// A historical manual entry only prints a fixed failure notice. It has no
// checkout, credentials, actions, input interpolation or qualification scope;
// every ref receives an explicit unsupported failure without qualification privileges.
function unsupportedArmNotice(workflow,name){
 const keys=(value,expected)=>!!value&&typeof value==="object"&&!Array.isArray(value)&&JSON.stringify(Object.keys(value).sort())===JSON.stringify(expected.sort());
 if(name!=="certops-windows-arm64-host.yml"||!keys(workflow,["name","on","permissions","jobs"])||workflow.name!=="CertOps / Unsupported Windows ARM64 full host qualification")return false;
 if(!keys(workflow.on,["workflow_dispatch"])||workflow.on.workflow_dispatch!==null||!keys(workflow.permissions,[])||!keys(workflow.jobs,["unsupported-full-host"]))return false;
 const job=workflow.jobs["unsupported-full-host"];
 if(!keys(job,["runs-on","timeout-minutes","steps"])||job["runs-on"]!=="ubuntu-latest"||job["timeout-minutes"]!==1||!Array.isArray(job.steps)||job.steps.length!==1)return false;
 const step=job.steps[0];return keys(step,["name","shell","run"])&&step.name==="Refuse unsupported full host scope"&&step.shell==="bash"&&step.run==="echo '::error::Full windows-host qualification on ARM64 is unsupported. Use certops-windows-arm64-cng.yml for native desktop CNG and certops-windows-arm64-scm.yml for candidate packaged service-host/mock-child lifecycle. These separate scopes do not qualify the full host suite, real agent, API, installer, IIS, Server or domain AD CS.'\nexit 1\n";
}
function validateWorkflow(workflow,name="workflow"){
  if(unsupportedArmNotice(workflow,name))return [];
  const errors=[];const fail=message=>errors.push(`${name}: ${message}`);
  for(const issue of require("./certops-azure-scope-policy").validate(name,workflow))fail(issue);
  if(/^certops-.*\.yml$/.test(name)&&!workflow.name?.startsWith("CertOps / "))fail("qualification workflow display name must use the CertOps / prefix");
  const events=typeof workflow.on==="string"?[workflow.on]:Object.keys(workflow.on||{});
  if(!events.length||events.some(event=>!["push","workflow_dispatch","schedule"].includes(event)))fail("qualification may run only trusted push, manual or cleanup schedule events");
  if(events.includes("push")&&JSON.stringify(workflow.on.push?.branches)!==JSON.stringify(["main"]))fail("push qualification must select only main");
  const permissions=workflow.permissions||{};if(typeof permissions!=="object")fail("explicit read-only permissions required");
  for(const [key,value] of Object.entries(permissions))if(!(["contents","actions"].includes(key)&&value==="read")&&!(key==="id-token"&&value==="write"))fail(`unsupported token permission ${key}`);
  if(permissions.contents!=="read")fail("contents read permission required");
  const distributionWorkflow = name === "certops-distribution-qualification.yml";
  const releaseProducer = "release-distribution-candidate";
  const releaseCases = {
    "release-native-vault-cleanup": ["vault-cleanup", "--native-vault-restart", "--cleanup-native-vault"],
    "release-native-openbao-cleanup": ["openbao-cleanup", "--native-openbao-restart", "--cleanup-native-openbao"],
    "release-native-linux-staging-vault": ["staging", "--native-staging", "--cleanup-native-staging"],
    "release-native-linux-staging-openbao": ["openbao-staging", "--native-openbao-staging", "--cleanup-native-openbao-staging"],
  };
  const mainRef = "github.ref == 'refs/heads/main'";
  const releaseSelector = "inputs.linux_distribution_candidate_sha";
  const supportingDistribution = `${mainRef} && !inputs.native_vault_cleanup && !inputs.native_linux_staging && ${releaseSelector} == ''`;
  const releaseCondition = `${mainRef} && ${releaseSelector} != ''`;
  const distributionConditions = {
    postgres: supportingDistribution,
    "agent-lab": supportingDistribution,
    "functional-summary": `\${{ always() && ${supportingDistribution} }}`,
    "native-vault-cleanup": `${mainRef} && (inputs.native_vault_cleanup || inputs.native_linux_staging) && ${releaseSelector} == ''`,
    [releaseProducer]: releaseCondition,
    ...Object.fromEntries(Object.keys(releaseCases).map(id => [id, releaseCondition])),
  };
  const releaseId = "${{ needs.release-distribution-candidate.outputs.artifact_id }}";
  const releaseChecksum = "${{ needs.release-distribution-candidate.outputs.package_sha256 }}";
  if (distributionWorkflow) {
    const input = workflow.on?.workflow_dispatch?.inputs?.linux_distribution_candidate_sha;
    if (input?.type !== "string" || input.default !== "") fail("release distribution requires an opt-in exact candidate SHA");
    if (![releaseProducer, ...Object.keys(releaseCases)].every(id => Object.hasOwn(workflow.jobs || {}, id))) fail("release distribution requires its producer and all four isolated cases");
  }
  for(const [id,job] of Object.entries(workflow.jobs||{})){
    if(name==="certops-adcs-lab-janitor.yml"&&job.environment!=="certops-adcs-cleanup")fail(`${id} independent expiry cleanup requires its dedicated unattended environment`);
    const scopedKeyVaultPreflight = name === "certops-azure-keyvault-qualification.yml" && id === "preflight" && job.if === undefined;
    const dnsLane=(name==="certops-dns-fixture-janitor.yml"&&id==="cleanup")||(name==="certops-dns-provider-qualification.yml"&&id==="provider");
    const dnsCondition=dnsLane&&job.needs==="enrollment"&&job.if==="github.ref == 'refs/heads/main' && needs.enrollment.outputs.enabled == 'true'";
    if(dnsLane&&!dnsCondition)fail(`${id} must select only explicitly enrolled DNS providers`);
    if(dnsLane&&job.strategy?.matrix?.provider!=="${{ fromJSON(needs.enrollment.outputs.providers) }}")fail(`${id} provider matrix must come from enrollment`);
    if(name==="certops-dns-fixture-janitor.yml"&&id==="cleanup"&&job.environment!=="certops-dns-cleanup-${{ matrix.provider }}")fail(`${id} independent DNS cleanup requires its dedicated unattended environment`);
    const selectedLane={tooling:"tooling","tooling-windows":"tooling",windows:"windows","agent-stack":"stack"}[id];
    const selectedCondition=name==="certops-qualification.yml"&&selectedLane&&job.needs==="selection"&&job.if===`github.ref == 'refs/heads/main' && needs.selection.outputs.${selectedLane} == 'true'`;
    const distributionLane=distributionWorkflow&&Object.hasOwn(distributionConditions,id);
    if(distributionWorkflow&&!distributionLane)fail(`${id} is not a recognized distribution qualification lane`);
    const distributionCondition=distributionLane&&job.if===distributionConditions[id]&&(id!=="functional-summary"||JSON.stringify(job.needs)===JSON.stringify(["postgres","agent-lab"]))&&events.length===1&&events[0]==="workflow_dispatch"&&workflow.on.workflow_dispatch?.inputs?.native_vault_cleanup?.type==="boolean"&&workflow.on.workflow_dispatch.inputs.native_vault_cleanup.default===false;
    if(distributionLane&&!distributionCondition)fail(`${id} must enforce its manual selector and exact trusted main reference`);
    if(job.if!=="github.ref == 'refs/heads/main'"&&!scopedKeyVaultPreflight&&!selectedCondition&&!dnsCondition&&!distributionCondition&&!require("./certops-azure-scope-policy").allowedCondition(name,job.if))fail(`${id} must enforce the exact trusted main reference`);
    if(name==="certops-qualification.yml"&&selectedLane&&!selectedCondition)fail(`${id} must narrow execution to its committed selection output`);
    if(!Number.isInteger(job["timeout-minutes"])||job["timeout-minutes"]<1||job["timeout-minutes"]>(name==="certops-enterprise-adcs-qualification.yml"&&id==="lab"?300:180))fail(`${id} requires a bounded timeout`);
    if(job.permissions)for(const [key,value] of Object.entries(job.permissions))if(!(["contents","actions"].includes(key)&&value==="read")&&!(key==="id-token"&&value==="write"))fail(`${id} expands token permissions`);
    if((permissions["id-token"]==="write"||job.permissions?.["id-token"]==="write")&&!job.environment)fail(`${id} OIDC requires a protected qualification environment`);
    const steps=job.steps||[],runs=steps.map(step=>step.run||"").join("\n");
    const nativeCleanup=distributionWorkflow&&id==="native-vault-cleanup";
    const producesRelease = distributionWorkflow && id === releaseProducer;
    const releaseCase = distributionWorkflow && Object.hasOwn(releaseCases,id) ? releaseCases[id] : null;
    const cleanupFailure="linux-${{ env.NATIVE_CASE }}-failure";
    const releaseReceipt="linux-${{ env.NATIVE_CASE }}-receipt";
    const candidateUpload = step => step.if === undefined && step.with?.name === releaseProducer &&
      step.with?.path === "qualification-results/linux-release-distribution-candidate/" && step.with?.["if-no-files-found"] === "error";
    const releaseReceiptUpload = step => step.if === undefined && step.with?.name === releaseReceipt &&
      step.with?.path === "qualification-results/linux-${{ env.NATIVE_CASE }}-restart.json" && step.with?.["if-no-files-found"] === "error";
    if (producesRelease) {
      const guard = steps.find(step => step.name === "Require the exact trusted main dispatch SHA");
      const build = steps.find(step => step.id === "package");
      if (guard?.env?.EXPECTED_CANDIDATE !== "${{ inputs.linux_distribution_candidate_sha }}" ||
          !guard.run?.includes('test "$EXPECTED_CANDIDATE" = "$GITHUB_SHA"') ||
          !guard.run?.includes('test "$(git rev-parse HEAD)" = "$EXPECTED_CANDIDATE"') ||
          !build?.run?.includes("build-release-distribution-candidate") || steps.indexOf(guard) >= steps.indexOf(build) ||
          steps.filter(step => step.uses?.startsWith("actions/upload-artifact@") && candidateUpload(step)).length !== 1 ||
          job.outputs?.artifact_id !== "${{ steps.candidate.outputs.artifact-id }}" ||
          job.outputs?.package_sha256 !== "${{ steps.package.outputs.sha256 }}") fail(`${id} must build and upload one exact main candidate`);
    }
    if (releaseCase) {
      const [scope, nativeMode, teardownMode] = releaseCase;
      const download = steps.find(step => step.uses?.startsWith("actions/download-artifact@"));
      const install = steps.find(step => step.name === "Run the selected installed restart case");
      const teardown = steps.find(step => step.name === "Verify teardown of only the owned host and containers");
      const receipts = steps.filter(step => step.uses?.startsWith("actions/upload-artifact@") && releaseReceiptUpload(step));
      if (job.needs !== releaseProducer || job["runs-on"] !== "ubuntu-24.04" ||
          job.env?.NATIVE_CASE !== scope || job.env.NATIVE_MODE !== nativeMode || job.env.TEARDOWN_MODE !== teardownMode ||
          download?.with?.["artifact-ids"] !== releaseId || download.with.name !== undefined ||
          download.with.path !== "${{ runner.temp }}/certops-linux-release-distribution/artifacts" ||
          download.with["merge-multiple"] !== true || download.with["digest-mismatch"] !== "error" ||
          install?.env?.TT_CLEANUP_ARTIFACT_ID !== releaseId ||
          install.env.TT_CLEANUP_ARTIFACT_SHA256 !== releaseChecksum || teardown?.if !== "always()" ||
          !install.run?.includes('"$NATIVE_MODE"') || !teardown.run?.includes('"$TEARDOWN_MODE"') ||
          steps.indexOf(download) >= steps.indexOf(install) || steps.indexOf(teardown) <= steps.indexOf(install) ||
          receipts.length !== 1 || steps.indexOf(receipts[0]) <= steps.indexOf(teardown)) {
        fail(`${id} must use the shared archive and independently verify teardown before retaining its receipt`);
      }
    }
    if(nativeCleanup){
      const provider=workflow.on.workflow_dispatch?.inputs?.native_cleanup_provider;
      if(provider?.type!=="choice"||provider.default!=="vault-kv2"||JSON.stringify(provider.options)!==JSON.stringify(["vault-kv2","openbao-kv2"])||job.env?.NATIVE_CLEANUP_STORE!=="${{ inputs.native_cleanup_provider == 'openbao-kv2' && 'openbao' || 'vault' }}")fail(`${id} requires its two exact KV v2 provider choices`);
      const staging=workflow.on.workflow_dispatch?.inputs?.native_linux_staging;
      if(staging?.type!=="boolean"||staging.default!==false||job.env?.NATIVE_CASE!=="${{ inputs.native_linux_staging && 'staging' || (inputs.native_cleanup_provider == 'openbao-kv2' && 'openbao-cleanup' || 'vault-cleanup') }}")fail(`${id} requires the exact staging selector`);
      const failureUploads=steps.filter(step=>step.with?.name===cleanupFailure);
      if(failureUploads.length!==1||failureUploads[0].if!=="failure()"||failureUploads[0].with?.path!==`qualification-results/${cleanupFailure}.json`)fail(`${id} requires only the bounded failure report on failure`);
    }
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
      if(step.uses===NODE_SETUP){if(Object.keys(step).some(key=>!["uses","name"].includes(key)))fail(`${id} shared setup cannot override inputs, environment or conditions`);}
      else if(step.uses&&!/^[-A-Za-z0-9_./]+@[a-f0-9]{40}$/.test(step.uses))fail(`${id} action must use an immutable commit`);
      if(step.uses?.startsWith("actions/checkout@")&&step.with?.["persist-credentials"]!==false)fail(`${id} checkout must not persist credentials`);
      if(step.uses?.startsWith("actions/upload-artifact@")){
        // Azure diagnostics must pass the closed-schema check even on failure;
        // an unconditional upload could expose a malformed sensitive report.
        const sanitizedKeyVaultUpload = name === "certops-azure-keyvault-qualification.yml" && step.if === "always() && steps.evidence-check.outcome == 'success'";
        const earlyAdcsFailureUpload = name === "certops-enterprise-adcs-qualification.yml" && id === "lab" && step.if === "failure() && !inputs.debug_mode" && step.with?.path === "qualification-results/enterprise-adcs-real.json" && step["continue-on-error"] === true && step["timeout-minutes"] === 2 && steps.some(other => other !== step && other.uses?.startsWith("actions/upload-artifact@") && other.if === "always()" && other.with?.path === "qualification-results/enterprise-adcs-*.json");
        const vaultFailureUpload=(nativeCleanup||releaseCase)&&step.if==="failure()"&&step.with?.name===cleanupFailure&&step.with?.path===`qualification-results/${cleanupFailure}.json`;
        const exactReleaseUpload=(producesRelease&&candidateUpload(step))||(releaseCase&&releaseReceiptUpload(step));
        if(step.if!=="always()"&&!sanitizedKeyVaultUpload&&!earlyAdcsFailureUpload&&!vaultFailureUpload&&!exactReleaseUpload)fail(`${id} must preserve diagnostic reports after failure`);
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
  const directory=path.join(root,".github/workflows");const errors=[];let shared=false;for(const name of fs.readdirSync(directory).filter(file=>/^certops-.*\.yml$/.test(file))){const workflow=yaml.load(fs.readFileSync(path.join(directory,name),"utf8"));errors.push(...validateWorkflow(workflow,name));shared ||= Object.values(workflow.jobs||{}).some(job=>(job.steps||[]).some(step=>step.uses===NODE_SETUP));}
  if(shared){try{errors.push(...validateNodeSetup(yaml.load(fs.readFileSync(path.join(root,NODE_SETUP,"action.yml"),"utf8"))));}catch{errors.push("Shared CertOps setup definition missing or invalid");}}
  return errors;
}
if(require.main===module){const errors=check();if(errors.length){console.error(errors.join("\n"));process.exitCode=1;}else console.log("certops-workflow-security: trusted refs, immutable actions, credential isolation and owned cleanup valid");}
module.exports={validateWorkflow,check,validateNodeSetup};
