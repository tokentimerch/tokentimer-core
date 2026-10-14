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
