/**
 * Supporting API/PostgreSQL qualification: independent public trust anchors remain scoped through concurrent approval and retirement.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),os=require("node:os"),crypto=require("node:crypto");
const {spawnSync}=require("node:child_process"),{createApiFixture}=require("./helpers/certops-api-fixture"),{createHostGate}=require("../../packages/agent/scripts/host-gate");
test("independent public trust anchors remain scoped through concurrent approval and retirement",{timeout:120000},async t=>{
 const baseUrl=process.env.CERTOPS_CSR_API_URL;
 if(!baseUrl&&process.env.CERTOPS_E2E_REQUIRED!=="1"){
  // skip-reason: no-host - requires disposable API PostgreSQL and real public CA certificates
  t.skip("Disposable API URL required");return;
 }
 assert.ok(baseUrl);const fixture=await createApiFixture(baseUrl),root=fs.mkdtempSync(path.join(os.tmpdir(),"trust-multi-"));let ready=false,failure;
 const scenarios=["trust-multi-concurrent-approval","trust-multi-distinct-fingerprints","trust-multi-bundle-refusal","trust-multi-retire-independent","trust-multi-reapprove-independent","trust-multi-cleanup"];
 const gate=createHostGate({suite:"trust-multiple-api",evidenceLevel:"integration",strict:process.env.CERTOPS_E2E_REQUIRED==="1",reportPath:process.env.CERTOPS_TRUST_MULTIPLE_REPORT,requiredCapabilities:["api","postgres","openssl"],fixtureSource:{file:"tests/e2e/certops-trust-multiple-e2e.test.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")},probeCapabilities:()=>({api:{available:true},postgres:{available:true},openssl:{available:spawnSync("openssl",["version"]).status===0}})});
 try{
  assert.equal(await gate.preflight(),true);ready=true;const material=[];
  for(const name of ["first","second"]){assert.equal(spawnSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",`${name}.key`,"-out",`${name}.crt`,"-subj",`/CN=${name} qualification CA`,"-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign","-days","2"],{cwd:root,timeout:20000}).status,0,"Public CA fixture failed");material.push(fs.readFileSync(path.join(root,`${name}.crt`),"utf8"));}
  const route=`/api/v1/workspaces/${fixture.workspaceId}/certops/trust-anchors`,approve=(index,name)=>fixture.request(route,"POST",{name,anchorType:"root",pem:material[index]});const list=()=>fixture.request(route);let first,second;
  await gate.scenario(scenarios[0],async()=>{const results=await Promise.all([approve(0,"Concurrent first"),approve(0,"Concurrent second")]);assert.ok(results.every(item=>item.status===201));assert.equal(results[0].body.trustAnchor.id,results[1].body.trustAnchor.id);first=results[0].body.trustAnchor.id;assert.equal((await list()).body.items.length,1);});
  await gate.scenario(scenarios[1],async()=>{const response=await approve(1,"Distinct root");assert.equal(response.status,201);second=response.body.trustAnchor.id;assert.notEqual(first,second);const items=(await list()).body.items;assert.equal(items.length,2);for(const pem of material)assert.ok(items.some(item=>item.fingerprintSha256===new crypto.X509Certificate(pem).fingerprint256.replace(/:/g,"").toLowerCase()));});
  await gate.scenario(scenarios[2],async()=>{const response=await fixture.request(route,"POST",{name:"Ambiguous bundle",anchorType:"root",pem:material.join("\n")});assert.equal(response.status,400);assert.equal(response.body.code,"CERTOPS_TRUST_ANCHOR_PEM_INVALID");assert.equal((await list()).body.items.length,2);});
  await gate.scenario(scenarios[3],async()=>{const retired=await fixture.request(`${route}/${first}/retire`,"POST",{reason:"Independent root lifecycle"});assert.equal(retired.status,200);const items=(await list()).body.items;assert.equal(items.find(item=>item.id===first).status,"revoked");assert.equal(items.find(item=>item.id===second).status,"active");});
  await gate.scenario(scenarios[4],async()=>{const response=await approve(0,"Explicit reapproval");assert.equal(response.status,201);assert.equal(response.body.trustAnchor.id,first);const items=(await list()).body.items;assert.equal(items.length,2);assert.ok(items.every(item=>item.status==="active"));assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM certificate_jobs WHERE workspace_id=$1",[fixture.workspaceId])).rows[0].count,0);},{oracle:"Actual public anchor lifecycle is independent per fingerprint; creating/reapproving one anchor never implicitly prunes another. No OS trust-store installation or native reference cleanup is claimed"});
 }catch(error){failure=error;throw error;}
 finally{const cleanup=async()=>{try{await fixture.cleanup();}finally{fs.rmSync(root,{recursive:true,force:true});}};try{if(ready){await gate.scenario(scenarios.at(-1),cleanup);await gate.finish({requiredScenarios:scenarios});}else await cleanup();}catch(error){if(failure)throw new AggregateError([failure,error],"Multiple trust anchor qualification and cleanup failed");throw error;}}
});
