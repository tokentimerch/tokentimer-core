/**
 * Regression coverage: report docs Python and guard changes select cheap tooling without hosts or DB.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs");
const {selectFiles,manual}=require("./certops-ci-selection");const {discover}=require("./run-certops-tooling-tests");
test("report docs Python and guard changes select cheap tooling without hosts or DB",()=>{for(const file of ["docs/certops/qualification/reporting/ci-selection.md","packages/agent/README.md","packages/contracts/README.md","packages/config/README.md","docs/certops/qualification-suites.json","scripts/certops-release-collector.py","scripts/certops-workflow-security.test.js","scripts/ci-guards/certops-release-matrix.cjs","scripts/generate-skip-inventory.cjs"]){const result=selectFiles([file]);assert.equal(result.tooling,true);assert.equal(result.windows,false);assert.equal(result.stack,false);}});
test("API worker and shared server dependencies require real stack but not Windows native setup",()=>{for(const file of ["apps/api/routes/certops.js","apps/worker/jobs/certops.js","deploy/compose/docker-compose.test.yml","tests/e2e/certops-csr-lifecycle-e2e.test.js",...['config','alert-eligibility','log-scrub','email-address','node-compat','webhook-safety'].map(name=>`packages/${name}/index.js`)]){const result=selectFiles([file]);assert.equal(result.stack,true);assert.equal(result.windows,false);}});
test("agent common contracts and dependency changes conservatively select affected hosts",()=>{for(const file of ["packages/agent/src/index.js","packages/agent/src/windows-iis/index.js","packages/contracts/package.json","pnpm-lock.yaml",".npmrc",".github/workflows/certops-qualification.yml"]){assert.equal(selectFiles([file]).windows,true);assert.equal(selectFiles([file]).stack,true);}});
test("manual selection accepts exactly one supported lane or explicit all",()=>{for(const lane of ["tooling","windows","stack"]){const result=manual(lane);assert.equal([result.tooling,result.windows,result.stack].filter(Boolean).length,1);assert.equal(result[lane],true);}assert.equal(manual("all").windows,true);for(const value of ["",null,"windows || true","paid-lab"])assert.throws(()=>manual(value));});
test("unsafe changed filenames cannot influence shell or escape path ownership",()=>{for(const file of ["../outside","/etc/passwd","a\\b","a\nforged"]){assert.throws(()=>selectFiles([file]));}});
test("framework discovery includes every current report ownership and security regression",()=>{const files=discover();for(const file of fs.readdirSync(require("node:path").join(__dirname)).filter(file=>/^certops-.*\.test\.js$/.test(file)))assert.ok(files.includes(`scripts/${file}`));assert.ok(files.includes("scripts/certops-kubernetes-compaction.test.js"));assert.ok(files.includes("scripts/certops-workflow-security.test.js"));assert.equal(new Set(files).size,files.length);});

const os=require("node:os"),path=require("node:path"),{spawnSync}=require("node:child_process");
test("selector uses actual candidate diff and fails safely on missing history or forged ref/SHA",{timeout:30000},()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),"certops-ci-selector-"));
 const git=args=>{const result=spawnSync("git",args,{cwd:root,encoding:"utf8",timeout:5000});assert.equal(result.status,0,result.stderr);return result.stdout.trim();};
 try{
  git(["init","-q"]);fs.writeFileSync(path.join(root,"README.md"),"baseline");git(["add","."]);const commit=()=>{git(["-c","user.name=Qualification Fixture","-c","user.email=fixture@example.invalid","commit","-qm","owned fixture"]);return git(["rev-parse","HEAD"]);};const before=commit();
  fs.mkdirSync(path.join(root,"apps/api"),{recursive:true});fs.writeFileSync(path.join(root,"apps/api/fixture.js"),"// changed API");git(["add","."]);const after=commit();let index=0;
  const invoke=(event,overrides={})=>{const eventPath=path.join(root,`event-${index}.json`),outputPath=path.join(root,`output-${index++}`);fs.writeFileSync(eventPath,JSON.stringify(event));const result=spawnSync(process.execPath,[path.join(__dirname,"certops-ci-selection.js")],{cwd:root,encoding:"utf8",timeout:5000,env:{...process.env,GITHUB_REF:"refs/heads/main",GITHUB_SHA:after,GITHUB_EVENT_NAME:"push",GITHUB_EVENT_PATH:eventPath,GITHUB_OUTPUT:outputPath,...overrides}});return {...result,output:fs.existsSync(outputPath)?fs.readFileSync(outputPath,"utf8"):""};};
  const scoped=invoke({before,after});assert.equal(scoped.status,0,scoped.stderr);assert.match(scoped.output,/windows=false/);assert.match(scoped.output,/stack=true/);assert.match(scoped.output,new RegExp(`candidate_sha=${after}`));
  for(const event of [{before:"0".repeat(40),after},{before,after,forced:true},{before:"f".repeat(40),after}]){const fallback=invoke(event);assert.equal(fallback.status,0,fallback.stderr);assert.match(fallback.output,/windows=true/);assert.match(fallback.output,/stack=true/);}
  for(const overrides of [{GITHUB_REF:"refs/pull/123/merge"},{GITHUB_SHA:before},{GITHUB_EVENT_NAME:"workflow_dispatch",CERTOPS_CI_LANE:"all || true"}]){const result=invoke({before,after},overrides);assert.notEqual(result.status,0);assert.equal(result.output,"");}
 }finally{fs.rmSync(root,{recursive:true});}
});

// CertOps UI authority changes require real component regressions, while native
// browser journeys remain explicitly dispatched and frontend-only pushes avoid DB/Windows.
test("CertOps frontend paths trigger tooling with actual console authority tests and no native lanes",()=>{
 const path=require("node:path"),yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-qualification.yml"),"utf8"));
 const paths=workflow.on.push.paths;
 const examples=[
  ["apps/dashboard/src/components/certops/**","apps/dashboard/src/components/certops/AgentShellConsole.jsx"],
  ["apps/dashboard/src/pages/certops/**","apps/dashboard/src/pages/certops/CertOpsJobs.jsx"],
  ...["hooks/useCertOpsUrlState.js","components/RequireManagerRoute.jsx","utils/WorkspaceContext.jsx","utils/apiClient.js","utils/lastWorkspacePreference.js","App.jsx"].map(file=>[`apps/dashboard/src/${file}`,`apps/dashboard/src/${file}`]),
  ...["AgentShellConsole","RequireManagerRoute","WorkspaceContext","useCertOpsUrlState"].map(name=>[`apps/dashboard/tests/unit/${name}.test.jsx`,`apps/dashboard/tests/unit/${name}.test.jsx`])
 ];
 for(const [pattern,file] of examples){assert.ok(paths.includes(pattern),pattern);assert.deepEqual(selectFiles([file]),{tooling:true,windows:false,stack:false,reason:"changed-files"});}
 assert.equal(paths.includes("apps/dashboard/**"),false);
 const step=workflow.jobs.tooling.steps.find(item=>item.name==="CertOps console and route authority regressions");assert.ok(step);
 for(const name of ["AgentShellConsole","RequireManagerRoute","WorkspaceContext","useCertOpsUrlState"])assert.ok(step.run.includes(`tests/unit/${name}.test.jsx`));
 assert.match(step.run,/^pnpm --dir apps\/dashboard test /);
});

// Supporting PowerShell filesystem coverage belongs in the existing selected
// Windows lane; it must not silently depend on an opt-in full SCM journey.
test("installer swap regression runs under Windows PowerShell 5.1 in the selective supporting lane",()=>{
 const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-qualification.yml"),"utf8"));
 const step=workflow.jobs.windows.steps.find(item=>item.name==="Installer activation filesystem regression (supporting only)");
 assert.ok(step);assert.equal(step.shell,"powershell");assert.equal(step.if,undefined);assert.notEqual(step["continue-on-error"],true);
 assert.match(step.run,/PSVersionTable\.PSVersion\.Major -ne 5/);assert.match(step.run,/PSVersionTable\.PSVersion\.Minor -ne 1/);
 assert.match(step.run,/& \.\/scripts\/certops-installer-swap\.test\.ps1/);
 assert.deepEqual(selectFiles(["scripts/certops-installer-swap.test.ps1"]),{tooling:true,windows:true,stack:false,reason:"changed-files"});
 assert.equal(selectFiles(["packages/agent/scripts/install-agent.ps1"]).windows,true);
});

test("benign response barrier changes select the existing Windows lane and execute supporting controls",()=>{
 const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-qualification.yml"),"utf8"));
 for(const file of ["scripts/certops-response-barrier-driver.ps1","scripts/certops-response-barrier-worker.ps1","scripts/certops-response-barrier-support.js","scripts/certops-response-barrier-support.test.js"]){
  assert.deepEqual(selectFiles([file]),{tooling:true,windows:true,stack:false,reason:"changed-files"});
  assert.ok(workflow.on.push.paths.includes("scripts/certops-*"));
 }
 for(const file of ["scripts/certops-response-barrier-unrelated.js","docs/certops/qualification/adcs/response-delivery-barrier-support.md"]){assert.equal(selectFiles([file]).windows,false);}
 const step=workflow.jobs.windows.steps.find(item=>item.name==="Temporary file response barriers (supporting only)");
 assert.ok(step);assert.equal(step.shell,"pwsh");assert.equal(step.env.CERTOPS_RESPONSE_BARRIER_SUPPORT,"1");
 assert.equal(step.if,undefined);assert.notEqual(step["continue-on-error"],true);
 assert.match(step.run,/node scripts\/certops-response-barrier-support\.js/);assert.match(step.run,/LASTEXITCODE -ne 0/);
 assert.equal(workflow.jobs.windows.if,"github.ref == 'refs/heads/main' && needs.selection.outputs.windows == 'true'");
});

test("native helper image controls build both architecture packages before selected Windows execution",()=>{
 const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-qualification.yml"),"utf8"));
 const steps=workflow.jobs.windows.steps;
 const control=steps.findIndex(step=>step.name==="Installer native helper image regression (supporting only)");assert.ok(control>=0);
 for(const script of ["build-windows-chain-helper.js","build-windows-service-host.js"]){
  const build=steps.findIndex(step=>step.run===`node packages/agent/scripts/${script}`);assert.ok(build>=0&&build<control,script);
  assert.equal(steps[build].if,undefined);assert.notEqual(steps[build]["continue-on-error"],true);
  // The builder's no-argument contract generates AMD64 and ARM64, with no
  // single-architecture override that would leave the PE control unprepared.
  const builder=require(`../packages/agent/scripts/${script}`);assert.deepEqual(builder.TARGET_ARCHES,["amd64","arm64"]);
 }
 assert.equal(steps[control].shell,"powershell");assert.equal(steps[control].if,undefined);assert.notEqual(steps[control]["continue-on-error"],true);
 assert.match(steps[control].run,/& \.\/scripts\/certops-installer-pe\.test\.ps1/);
 assert.deepEqual(selectFiles(["scripts/certops-installer-pe.test.ps1"]),{tooling:true,windows:true,stack:false,reason:"changed-files"});
});

test("retention owner collection import changes explicitly trigger only tooling",()=>{
 const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-qualification.yml"),"utf8"));
 assert.ok(workflow.on.push.paths.includes("scripts/certops_retention24h_collection.py"));
 assert.ok(workflow.on.push.paths.includes("scripts/certops_retention_policy_expiry.py"));
 assert.deepEqual(selectFiles(["scripts/certops_retention_policy_expiry.py"]),{tooling:true,windows:false,stack:false,reason:"changed-files"});
 assert.equal(workflow.on.push.paths.includes("scripts/**"),false);
 assert.deepEqual(selectFiles(["scripts/certops_retention24h_collection.py"]),{tooling:true,windows:false,stack:false,reason:"changed-files"});
});

test("SAN public temporary file controls select cheap Windows without the domain lab",()=>{
 const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-qualification.yml"),"utf8"));
 for(const file of ["infra/certops-adcs/issued-san-fault.ps1","scripts/certops-adcs-issued-san-file.test.ps1"]){assert.deepEqual(selectFiles([file]),{tooling:true,windows:true,stack:false,reason:"changed-files"});assert.ok(workflow.on.push.paths.includes(file.startsWith("infra/")?"infra/certops-adcs/**":"scripts/certops-*"));}
 for(const file of ["infra/certops-adcs/issued-template-fault.ps1","scripts/certops-adcs-issued-san-unrelated.ps1","docs/certops/qualification/adcs/native-issued-san-refusal.md"])assert.equal(selectFiles([file]).windows,false);
 const step=workflow.jobs.windows.steps.find(item=>item.name==="SAN public temporary file ownership (supporting only)");assert.ok(step);assert.equal(step.shell,"powershell");assert.equal(step.if,undefined);assert.notEqual(step["continue-on-error"],true);assert.match(step.run,/& \.\/scripts\/certops-adcs-issued-san-file\.test\.ps1/);assert.match(step.run,/LASTEXITCODE -ne 0/);assert.doesNotMatch(step.run,/issued-san-fault|certreq|setextension|workflow_dispatch/);
});

test("ARM64 native fixture changes select supporting tooling without dispatching AMD64 or paid labs",()=>{for(const file of ["scripts/certops-arm64-scm-runtime.js","scripts/certops-arm64-scm-native.ps1","scripts/certops-arm64-scm-proof.js",".github/workflows/certops-windows-arm64-scm.yml",".github/workflows/certops-windows-arm64-host.yml"]){const result=selectFiles([file]);assert.equal(result.tooling,true);assert.equal(result.windows,false);assert.equal(result.stack,false);}});

test("bounded ARM64 installed source selects tooling and retains explicit manual native dispatch",()=>{for(const file of ["tests/e2e/helpers/certops-arm64-installed-journey.js","scripts/certops-arm64-installed-agent.js","scripts/certops-arm64-installed-driver.ps1","scripts/certops-arm64-postgres.js","scripts/certops-arm64-postgres-lock.json",".github/workflows/certops-windows-arm64-agent.yml"]){const result=selectFiles([file]);assert.equal(result.tooling,true);assert.equal(result.windows,false);assert.equal(result.stack,false);}});


test("Linux backup DAC Python proof changes select tooling only and explicitly trigger CI",()=>{
 const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-qualification.yml"),"utf8"));
 const file="scripts/certops_linux_backup_dac_proof.py";
 assert.ok(workflow.on.push.paths.includes(file));
 assert.deepEqual(selectFiles([file]),{tooling:true,windows:false,stack:false,reason:"changed-files"});
});

test("concurrent filesystem Python projection selects tooling only and explicitly triggers CI",()=>{
 const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-qualification.yml"),"utf8"));
 const file="scripts/certops_filesystem_concurrent_proof.py";
 assert.ok(workflow.on.push.paths.includes(file));
 assert.deepEqual(selectFiles([file]),{tooling:true,windows:false,stack:false,reason:"changed-files"});
});

test("independent native trust Python projection selects only tooling",()=>{
 const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");
 const workflow=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-qualification.yml"),"utf8"));const file="scripts/certops_linux_trust_independent_proof.py";assert.ok(workflow.on.push.paths.includes(file));assert.deepEqual(selectFiles([file]),{tooling:true,windows:false,stack:false,reason:"changed-files"});
});

// The Python owner authenticator affects cheap tooling, never auto-provisions a forest.
test("installed timer collector path is explicitly triggered without native lanes",()=>{
 const file="scripts/certops_retention_cadence_collection.py";
 assert.deepEqual(selectFiles([file]),{tooling:true,windows:false,stack:false,reason:"changed-files"});
 const source=fs.readFileSync(require("node:path").resolve(__dirname,"../.github/workflows/certops-qualification.yml"),"utf8");
 assert.ok(source.includes("- '"+file+"'"));
});

test("daemon native proof projection changes select tooling and explicitly trigger CI",()=>{const yaml=require("node:module").createRequire(require.resolve("../node_modules/mocha/package.json"))("js-yaml");const w=yaml.load(fs.readFileSync(path.resolve(__dirname,"../.github/workflows/certops-qualification.yml"),"utf8"));const f="scripts/certops_daemon_coordinator_proof.py";assert.ok(w.on.push.paths.includes(f));assert.deepEqual(selectFiles([f]),{tooling:true,windows:false,stack:false,reason:"changed-files"});});
