"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),os=require("node:os"),crypto=require("node:crypto"),http=require("node:http");
const {executeMaterialCleanup}=require("./cleanup");
const {applyRestrictivePermissions}=require("../platform");
const {filterQualifiedCapabilities}=require("../capabilities");
async function fixture(t){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),"tt-cleanup-test-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const tokenFile=path.join(dir,"cleanup-token");fs.writeFileSync(tokenFile,"isolated-cleanup-token-only",{mode:0o600});applyRestrictivePermissions(tokenFile);
  const workspaceId=crypto.randomUUID(),groupId=crypto.randomUUID(),materialVersionId=crypto.randomUUID();
  const metadata={versions:{1:{created_time:new Date(Date.now()-100*86400000).toISOString(),deletion_time:"",destroyed:false},2:{created_time:new Date().toISOString(),deletion_time:"",destroyed:false}}};
  const requests=[],state={loseResponse:false,deletes:0};
  const server=http.createServer((req,res)=>{const url=req.url;requests.push({method:req.method,url});
    if(req.method==="GET" && url===`/v1/secret/metadata/${workspaceId}/${groupId}/bundles/${materialVersionId}`){res.setHeader("content-type","application/json");res.end(JSON.stringify({data:metadata}));return;}
    if(req.method==="POST" && url===`/v1/secret/delete/${workspaceId}/${groupId}/bundles/${materialVersionId}`){let body="";req.on("data",c=>body+=c);req.on("end",()=>{assert.deepEqual(JSON.parse(body),{versions:[1]});state.deletes++;metadata.versions[1].deletion_time=new Date().toISOString();if(state.loseResponse){state.loseResponse=false;res.destroy();}else{res.writeHead(204);res.end();}});return;}
    assert.fail("Cleanup must never read data, destroy versions or delete metadata");});
  // Windows protected journal writes can exceed Node's 5-second idle limit.
  // Deliberate lost-response faults remain explicit in the fixture.
  server.keepAliveTimeout=60000;
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
  const scope={workspaceId,prefix:`${workspaceId}/${groupId}`,sans:["cleanup.example.test"],keyAlgorithm:"rsa",cleanup:{softDelete:true,profileRevision:1,minimumSeconds:86400,tokenFile}};
  const intent={type:"vault-kv2-soft-delete",cleanupId:crypto.randomUUID(),groupId,materialVersionId,managementPeriodId:crypto.randomUUID(),materialStoreRef:"customer",providerVersion:1,profileRevision:1,
    policyRevision:1,scopeHash:"a".repeat(64),expiresAt:new Date(Date.now()+3600000).toISOString(),retentionPolicy:{minimumSeconds:86400,minimumVersions:2,rollbackSeconds:86400,cleanupEnabled:true,reportOnly:false,requiresApproval:true}};
  const options={job:{jobId:crypto.randomUUID(),workspaceId,mode:"real",materialCleanup:intent},stores:{customer:{address:`http://127.0.0.1:${server.address().port}`,mount:"secret",tokenFile:"must-not-read-publication-token",groups:{[groupId]:scope}}},
    stateDir:path.join(dir,"state"),checkLease:async()=>{},fixtureLoopbackHttp:true};
  return {options,scope,intent,metadata,requests,state,run:()=>executeMaterialCleanup(options)};
}
test("cleanup capability remains absent from the unchanged released qualification manifest",()=>{
  assert.deepEqual(filterQualifiedCapabilities(["material-cleanup-vault-kv2-v1"]),[]);
});
test("cleanup soft deletes only the exact version, preserves newer material, never retrieves a key and is idempotent",async t=>{
  const f=await fixture(t);assert.equal((await f.run()).status,"succeeded");assert.equal(f.state.deletes,1);assert.equal(f.metadata.versions[2].deletion_time,"");
  const again=await f.run();assert.equal(again.status,"succeeded");assert.equal(again.cleanupReceipt.softDeleted,true);assert.equal(f.state.deletes,1);
  f.options.job.materialCleanup=Object.fromEntries(Object.entries(f.intent).reverse());assert.equal((await f.run()).status,"succeeded","Wire key ordering cannot change the authorized intent");assert.equal(f.state.deletes,1);
  assert.ok(f.requests.every(r=>!r.url.includes("/data/") && !r.url.includes("/destroy/")));
  assert.doesNotMatch(JSON.stringify(again),/token|PRIVATE KEY|https?:/);
});
test("lost delete response stays uncertain and original-intent retry reconciles metadata without a second delete",async t=>{
  const f=await fixture(t);f.state.loseResponse=true;assert.equal((await f.run()).status,"orphaned_unknown_effect");
  assert.equal((await f.run()).status,"succeeded");assert.equal(f.state.deletes,1);
});
test("cleanup dry-run creates no lock, journal, provider requests or deletion",async t=>{
  const f=await fixture(t);f.options.job.mode="dry_run";assert.equal((await f.run()).status,"dry_run_complete");
  assert.equal(f.requests.length,0);assert.equal(fs.existsSync(f.options.stateDir),false);
});
test("customer-local opt-in and current profile revision are independently required",async t=>{
  const f=await fixture(t);f.scope.cleanup.softDelete=false;await assert.rejects(f.run,{code:"material_cleanup_policy_denied"});assert.equal(f.requests.length,0);
  f.scope.cleanup.softDelete=true;f.scope.cleanup.profileRevision=2;assert.equal((await f.run()).status,"blocked");assert.equal(f.state.deletes,0);
});
test("local retention floor, expired authority and lease loss refuse deletion",async t=>{
  const f=await fixture(t);f.metadata.versions[1].created_time=new Date().toISOString();assert.equal((await f.run()).status,"blocked");assert.equal(f.state.deletes,0);
  f.intent.expiresAt=new Date(Date.now()-1).toISOString();assert.equal((await f.run()).status,"blocked");assert.equal(f.state.deletes,0);
  f.intent.expiresAt=new Date(Date.now()+3600000).toISOString();f.options.checkLease=async()=>{const e=new Error("lease unavailable");e.code="material_lease_unavailable";throw e;};assert.equal((await f.run()).status,"blocked");assert.equal(f.state.deletes,0);
});
test("a changed cleanup intent and cross-workspace store scope cannot reuse an existing authorization",async t=>{
  const f=await fixture(t);assert.equal((await f.run()).status,"succeeded");f.intent.providerVersion=2;
  await assert.rejects(f.run,{code:"material_cleanup_intent_changed"});assert.equal(f.metadata.versions[2].deletion_time,"");
  f.options.job.workspaceId=crypto.randomUUID();await assert.rejects(f.run,{code:"material_scope_denied"});
});
