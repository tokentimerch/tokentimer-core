/**
 * Isolated scheduler/API/PostgreSQL qualification of automatic-renewal toggles.
 * The scheduler-capacity workflow runs this after its own fixture cleanup. Complete
 * linked execution profiles are explicit SQL prerequisites; actual public imports,
 * public profile edits/manual admission and production SQL-NOW sweeps are oracles.
 * Requires an exclusive disposable database; no CA execution or clock rewriting.
 */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),os=require("node:os"),crypto=require("node:crypto"),{spawnSync}=require("node:child_process");
const {createApiFixture}=require("./helpers/certops-api-fixture"),{createHostGate}=require("../../packages/agent/scripts/host-gate");
const scheduler=require("../../apps/api/services/certops/renewalScheduler"),{createCertificateJob}=require("../../apps/api/services/certops/jobs"),{buildRenewalJobPayload}=require("../../apps/api/services/certops/renewalProfile");
const scenarios=["renew-toggle-public-disable","renew-toggle-automatic-admission-refused","renew-toggle-manual-stored-profile-allowed","renew-toggle-bulk-stored-profile-allowed","renew-toggle-disabled-not-batch-starvation","renew-toggle-resume-exactly-once","renew-toggle-owned-cleanup"];
module.exports={scenarios};
test("disabled automatic renewal preserves manual admission and SQL batch fairness",{timeout:120000},async t=>{
 if((!process.env.CERTOPS_CSR_API_URL||process.env.CERTOPS_SCHEDULER_EXCLUSIVE_STACK!=="1")&&process.env.CERTOPS_E2E_REQUIRED!=="1"){
  // skip-reason: no-host - requires exclusive disposable API PostgreSQL and OpenSSL scheduler fixture
  t.skip("Exclusive disposable scheduler fixture required");return;
 }
 assert.equal(process.env.CERTOPS_SCHEDULER_EXCLUSIVE_STACK,"1");assert.ok(process.env.CERTOPS_CSR_API_URL);
 const fixture=await createApiFixture(process.env.CERTOPS_CSR_API_URL),directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-renew-toggle-")),items=[],profiles=[],policies=[],metadataBeforeAdmission=[];
 const prefix=`/api/v1/workspaces/${fixture.workspaceId}/certops`,source="tests/e2e/certops-renewal-toggle-e2e.test.js";
 const gate=createHostGate({suite:"renewal-toggle-scheduler-api",strict:true,evidenceLevel:"integration",reportPath:process.env.CERTOPS_RENEWAL_TOGGLE_REPORT,fixtureSource:{file:source,sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")},requiredCapabilities:["api","postgres","openssl","exclusiveStack"],probeCapabilities:()=>({api:{available:true},postgres:{available:true},openssl:{available:spawnSync("openssl",["version"]).status===0},exclusiveStack:{available:process.env.CERTOPS_SCHEDULER_EXCLUSIVE_STACK==="1"}})});
 gate.report.fixturePrerequisite="Real public certificate imports and explicitly seeded complete agent-local linked profiles; no synthetic expiry/job/observation rows or successful native renewal claim";
 gate.report.fixtureSources=["tests/e2e/helpers/certops-api-fixture.js","apps/api/services/certops/renewalScheduler.js","apps/api/services/certops/jobs.js"].map(file=>({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.resolve(__dirname,"../..",file))).digest("hex")}));
 const jobs=async()=>(await fixture.pool.query("SELECT id,source,status,subject_id,payload FROM certificate_jobs WHERE workspace_id=$1 ORDER BY id",[fixture.workspaceId])).rows;
 const sweep=()=>scheduler.runRenewalSchedulerSweep({dbPool:fixture.pool,env:process.env,batchSize:1});
 const assertStoredContract=async(job,index)=>{
  const expected=policies[index],payload=job.payload;
  assert.equal(job.source,"api");assert.equal(job.status,"pending_approval");assert.equal(job.subject_id,items[index].id);
  assert.equal(payload.commandRef,expected.acme.commandRef);assert.equal(payload.caEndpoint,expected.ca.endpoint);assert.equal(payload.acmeKind,expected.acme.kind);
  assert.deepEqual(payload.sans,expected.sanPolicy.sans);assert.equal(payload.keyAlgorithm,expected.keyAlgorithm);assert.equal(payload.keySize,expected.keySize);assert.equal(payload.keyRotation,expected.keyRotationPolicy.rotateOnRenew);
  assert.deepEqual(payload.target,{type:expected.target.type,reference:expected.target.reference});assert.equal(payload.certPath,expected.target.certPath);assert.deepEqual(payload.deploymentTargets,expected.deploymentTargets);
  assert.equal(payload.verifyHost,expected.verification.host);assert.equal(payload.verifyPort,expected.verification.port);
  for(const field of ["target","deploymentTargets","sanPolicy","keyAlgorithm","keySize","keyRotationPolicy","verification","ca","acme","dns"])assert.deepEqual(payload.renewalProfile[field],expected[field],`Stored ${field} must remain authoritative`);
  assert.deepEqual((await fixture.pool.query("SELECT public_metadata FROM certificate_profiles WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,profiles[index]])).rows[0].public_metadata,metadataBeforeAdmission[index]);
 };
 const toggle=async(index,enabled)=>{const result=await fixture.request(`${prefix}/profiles/${profiles[index]}`,"PATCH",{autoRenewEnabled:enabled});assert.equal(result.status,200);assert.equal(result.body.status,enabled?"active":"disabled");};
 let ready=false,failure,manualJob;
 try{
  await gate.preflight();ready=true;
  assert.equal((await fixture.pool.query("SELECT count(*)::int AS n FROM certops_management_periods WHERE workspace_id<>$1 AND ended_at IS NULL AND automation_enabled=TRUE",[fixture.workspaceId])).rows[0].n,0,"Foreign automation refuses global sweep");
  assert.equal((await fixture.request(`${prefix}/settings`,"PUT",{certOpsRequireApprovalAlways:true,reason:"Owned renewal toggle fixture"})).status,200);
  for(let index=0;index<2;index++){
   const host=`toggle-${index}.example.test`;
   assert.equal(spawnSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",`${index}.key`,"-out",`${index}.crt`,"-days","2","-subj",`/CN=${host}`,"-addext",`subjectAltName=DNS:${host}`],{cwd:directory,stdio:"ignore",timeout:20000}).status,0);
   const imported=await fixture.request(`${prefix}/certificates`,"POST",{certificatePem:fs.readFileSync(path.join(directory,`${index}.crt`),"utf8")});assert.equal(imported.status,201);items.push(imported.body.items[0]);
   const target={type:"domain",reference:host,certPath:path.join(directory,`${index}-deployed.crt`)},profile={schemaVersion:1,profileId:null,profileName:`Toggle ${index}`,sanPolicy:{mode:"exact",sans:[host],allowWildcards:false},keyAlgorithm:"rsa",keySize:2048,keyRotationPolicy:{rotateOnRenew:true},preferredChain:null,ca:{endpoint:"https://renew-toggle.invalid/directory",accountRef:null,eabRef:null},acme:{kind:"certbot",commandRef:"owned.toggle"},dns:{provider:"cloudflare",zone:"example.test"},deploymentTargets:[target],target,verification:{host,port:443,requireMatch:true}};
   policies.push(profile);
   const profileId=(await fixture.pool.query("INSERT INTO certificate_profiles(workspace_id,name,key_mode,public_metadata,created_by) VALUES($1,$2,'agent-local',$3,$4) RETURNING id",[fixture.workspaceId,`Toggle ${index}`,JSON.stringify({renewalProfile:profile}),fixture.userId])).rows[0].id;profiles.push(profileId);
   await fixture.pool.query("UPDATE managed_certificates SET key_mode='agent-local',profile_id=$3 WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,items[index].id,profileId]);
   const period=(await fixture.pool.query("SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",[fixture.workspaceId,items[index].id])).rows[0];assert.ok(period);
   assert.equal((await fixture.request(`${prefix}/sources/${items[index].id}/replace-management`,"POST",{periodId:period.id,renewalProfileId:profileId,automationEnabled:true})).status,201);
  }
  await gate.scenario(scenarios[0],async()=>{await toggle(0,false);await toggle(1,false);for(const id of profiles)metadataBeforeAdmission.push((await fixture.pool.query("SELECT public_metadata FROM certificate_profiles WHERE workspace_id=$1 AND id=$2",[fixture.workspaceId,id])).rows[0].public_metadata);const result=await sweep();assert.equal(result.errors.length,0);assert.equal(result.created,0);assert.equal(result.scanned,0);assert.equal(result.skippedAutoRenewDisabled,2);assert.deepEqual(await jobs(),[]);});
  await gate.scenario(scenarios[1],async()=>{
   const {rows,scheduleFacts}=await scheduler.loadCertificateRenewalRows({db:fixture.pool,workspaceId:fixture.workspaceId,certificateIds:[items[0].id]});assert.equal(rows.length,1);assert.equal(scheduleFacts,true);
   const payload=buildRenewalJobPayload({certificate:rows[0]});
   await assert.rejects(createCertificateJob({client:fixture.pool,workspaceId:fixture.workspaceId,operation:"renew",source:"automation",subjectType:"managed_certificate",subjectId:items[0].id,idempotencyKey:crypto.randomUUID(),payload,env:process.env}),{code:"CERTOPS_RENEWAL_AUTO_RENEW_DISABLED"});assert.deepEqual(await jobs(),[]);
  });
  await gate.scenario(scenarios[2],async()=>{
   const response=await fixture.request(`${prefix}/jobs`,"POST",{operation:"renew",subjectId:items[0].id,idempotencyKey:crypto.randomUUID()});assert.equal(response.status,201);manualJob=response.body.job.id;
   const job=(await jobs()).find(row=>row.id===manualJob);assert.ok(job);await assertStoredContract(job,0);
   assert.equal((await fixture.request(`${prefix}/profiles/${profiles[0]}`)).body.status,"disabled");
   assert.equal((await fixture.request(`${prefix}/jobs/${manualJob}/reject`,"POST",{reason:"Owned manual admission completed without native execution"})).status,200);
  });
  await gate.scenario(scenarios[3],async()=>{
   const response=await fixture.request(`${prefix}/jobs/bulk-renew`,"POST",{certificateIds:[items[0].id],idempotencyKey:crypto.randomUUID()});assert.equal(response.status,200);assert.equal(response.body.results.length,1);assert.equal(response.body.results[0].ok,true);const bulkJob=response.body.results[0].jobId;assert.notEqual(bulkJob,manualJob);
   const job=(await jobs()).find(row=>row.id===bulkJob);assert.ok(job);await assertStoredContract(job,0);assert.equal((await fixture.request(`${prefix}/profiles/${profiles[0]}`)).body.status,"disabled");
   assert.equal((await fixture.request(`${prefix}/jobs/${bulkJob}/reject`,"POST",{reason:"Owned bulk admission completed without native execution"})).status,200);
  });
  await gate.scenario(scenarios[4],async()=>{await toggle(1,true);const result=await sweep();assert.equal(result.errors.length,0);assert.equal(result.scanned,1);assert.equal(result.created,1);assert.equal(result.skippedAutoRenewDisabled,1);const automatic=(await jobs()).filter(row=>row.source==="automation");assert.equal(automatic.length,1);assert.equal(automatic[0].subject_id,items[1].id);assert.equal(automatic[0].payload.commandRef,"owned.toggle");});
  await gate.scenario(scenarios[5],async()=>{await toggle(0,true);const results=await Promise.all([sweep(),sweep()]);assert.equal(results.flatMap(row=>row.errors).length,0);assert.equal(results.reduce((sum,row)=>sum+row.created,0),1);const automatic=(await jobs()).filter(row=>row.source==="automation");assert.equal(automatic.length,2);assert.equal(automatic.filter(row=>row.subject_id===items[0].id).length,1);assert.equal((await sweep()).created,0);assert.equal((await jobs()).length,4);});
 }catch(error){failure=error;}
 finally{const cleanup=async()=>{try{await fixture.cleanup();}finally{fs.rmSync(directory,{recursive:true,force:true});}};try{if(ready){await gate.scenario(scenarios.at(-1),cleanup);await gate.finish({requiredScenarios:scenarios});}else await cleanup();}catch(error){failure=failure?new AggregateError([failure,error],"Renewal toggle and cleanup failed"):error;}if(failure)throw failure;}
});
