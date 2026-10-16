/**
 * Supporting API/PostgreSQL qualification: public renewal issuer changes retain runnable policy and atomic audit.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),crypto=require("node:crypto");
const {createApiFixture}=require("./helpers/certops-api-fixture"),{createHostGate}=require("../../packages/agent/scripts/host-gate");
const scenarios=["issuer-switch-confirmed-update","issuer-switch-unconfirmed-atomic-refusal","issuer-switch-foreign-fence","issuer-switch-incomplete-acme-refusal","issuer-switch-noop-audit-fence","issuer-switch-cleanup"];
test("public renewal issuer changes retain runnable policy and atomic audit",{timeout:120000},async t=>{
 const baseUrl=process.env.CERTOPS_CSR_API_URL;if(!baseUrl&&process.env.CERTOPS_E2E_REQUIRED!=="1"){
  // skip-reason: no-host - requires disposable API and PostgreSQL
  t.skip("Disposable API and PostgreSQL required");return;
 }
 assert.ok(baseUrl);const fixture=await createApiFixture(baseUrl);let foreign,ready=false,failure;
 const gate=createHostGate({suite:"profile-issuer-switch-api",evidenceLevel:"integration",strict:true,reportPath:process.env.CERTOPS_ISSUER_SWITCH_REPORT,requiredCapabilities:["api","postgres"],fixtureSource:{file:"tests/e2e/certops-profile-issuer-switch-e2e.test.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")},probeCapabilities:()=>({api:{available:true},postgres:{available:true}})});
 gate.report.fixturePrerequisite="Confirmed and unconfirmed issuer rows are seeded policy prerequisites only; no native CA validation, deployment, certificate execution or issuer switch renewal success is claimed";
 async function issuer(workspaceId,confirmed){const id=(await fixture.pool.query("INSERT INTO certificate_issuers(workspace_id,kind,name,current_version,revalidation_required) VALUES($1,'adcs','Owned issuer switch fixture',$2,$3) RETURNING id",[workspaceId,confirmed?1:0,!confirmed])).rows[0].id;if(confirmed)await fixture.pool.query("INSERT INTO certificate_issuer_versions(workspace_id,issuer_id,version,ca_config,template,transport,ca_key_sha256,confirmed_at) VALUES($1,$2,1,$3,'QualificationWebServer','dcom',$4,NOW())",[workspaceId,id,"ca.invalid\\Qualification CA","ab".repeat(32)]);return id;}
 try{assert.equal(await gate.preflight(),true);ready=true;foreign=await createApiFixture(baseUrl);const first=await issuer(fixture.workspaceId,true),second=await issuer(fixture.workspaceId,true),pending=await issuer(fixture.workspaceId,false),other=await issuer(foreign.workspaceId,true);const route=`/api/v1/workspaces/${fixture.workspaceId}/certops/profiles`;const made=await fixture.request(route,"POST",{name:"Owned issuer switch profile",issuerId:first,target:{type:"windows-iis",reference:"switch.example.test",store:"WebHosting",binding:{site:"Qualification",port:443,sniHost:"switch.example.test"}},keyAlgorithm:"rsa",keySize:2048,renewBeforeDays:30});assert.equal(made.status,201);const detail=`${route}/${made.body.id}`,read=async()=>(await fixture.request(detail)).body;
 const audit=async()=>(await fixture.pool.query("SELECT count(*)::int AS count FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_RENEWAL_PROFILE_UPDATED' AND metadata->>'profileId'=$2",[fixture.workspaceId,made.body.id])).rows[0].count;
 await gate.scenario(scenarios[0],async()=>{const before=await read(),changed=await fixture.request(detail,"PATCH",{issuerId:second,description:"Approved issuer switch"});assert.equal(changed.status,200);assert.equal(changed.body.issuerId,second);assert.deepEqual(changed.body.renewalProfile,before.renewalProfile);assert.equal(await audit(),1);});
 async function refuse(body,status,code){const before=await read(),count=await audit(),response=await fixture.request(detail,"PATCH",{description:"Must not persist",renewBeforeDays:45,...body});assert.equal(response.status,status);assert.equal(response.body.code,code);assert.deepEqual(await read(),before);assert.equal(await audit(),count);}
 await gate.scenario(scenarios[1],()=>refuse({issuerId:pending},422,"CERTOPS_PROFILE_ISSUER_INCOMPATIBLE"));
 await gate.scenario(scenarios[2],()=>refuse({issuerId:other},404,"CERTOPS_PROFILE_ISSUER_NOT_FOUND"));
 await gate.scenario(scenarios[3],()=>refuse({issuerId:null},422,"CERTOPS_PROFILE_ISSUER_INCOMPATIBLE"));
 await gate.scenario(scenarios[4],async()=>{const before=await read(),count=await audit(),response=await fixture.request(detail,"PATCH",{issuerId:second});assert.equal(response.status,400);assert.equal(response.body.code,"CERTOPS_PROFILE_NO_CHANGES");assert.deepEqual(await read(),before);assert.equal(await audit(),count);assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1",[fixture.workspaceId])).rows[0].count,0);});
 }catch(error){failure=error;}
 finally{const cleanup=async()=>{const errors=[];for(const item of [fixture,foreign].filter(Boolean))try{await item.cleanup();}catch(error){errors.push(error);}if(errors.length)throw new AggregateError(errors,"Owned issuer switch cleanup failed");};try{if(ready){await gate.scenario(scenarios.at(-1),cleanup);await gate.finish({requiredScenarios:scenarios});}else await cleanup();}catch(error){failure=failure?new AggregateError([failure,error],"Issuer switch and cleanup failed"):error;}if(failure)throw failure;}
});
