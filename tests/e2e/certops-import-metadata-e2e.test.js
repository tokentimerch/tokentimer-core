/**
 * Qualification notes: Certificate import metadata preservation
 * `import-metadata-api` checks that repeated and concurrent public reimports preserve
 * certificate/token identity, provenance, operator name, contacts, description and group memberships.
 * Invalid group/contact edits fail atomically. OpenSSL and real API/PostgreSQL persistence support
 * these controls; provider delivery and native host concurrency are not qualified.
 *
 * Shared execution and evidence policy: docs/certops/e2e-qualification.md.
 */
/**
 * Supporting API/PostgreSQL qualification: public reimport preserves operator contacts and group assignments.
 * Run via scripts/certops-api-qualification.js with an explicitly disposable API stack.
 * Public requests and persisted rows are the oracle; prerequisite state is isolated.
 * Native certificate deployment is qualified separately; strict reports and cleanup apply. */
"use strict";
const {test}=require("node:test"), assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),crypto=require("node:crypto"),{spawnSync}=require("node:child_process");
const {createApiFixture}=require("./helpers/certops-api-fixture"),{createHostGate}=require("../../packages/agent/scripts/host-gate");
const scenarios=["import-metadata-public-assignment","import-metadata-repeat-preserves","import-metadata-invalid-group-atomic","import-metadata-concurrent-preserves","import-metadata-cleanup"];
test("public reimport preserves operator contacts and group assignments",{timeout:120000},async(t)=>{
 if (!process.env.CERTOPS_CSR_API_URL && process.env.CERTOPS_E2E_REQUIRED !== "1") {
  // skip-reason: no-host - requires disposable API PostgreSQL and OpenSSL qualification fixture
  t.skip("Required disposable qualification fixture unavailable"); return;
 }
 assert.ok(process.env.CERTOPS_CSR_API_URL,"Disposable API required");const fixture=await createApiFixture(process.env.CERTOPS_CSR_API_URL),directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-import-metadata-"));let ready=false,primary;
 const gate=createHostGate({suite:"import-metadata-api",evidenceLevel:"integration",strict:true,reportPath:process.env.CERTOPS_IMPORT_METADATA_REPORT,requiredCapabilities:["api","postgres","openssl"],fixtureSource:{file:"tests/e2e/certops-import-metadata-e2e.test.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")},probeCapabilities:()=>({api:{available:true},postgres:{available:true},openssl:{available:spawnSync("openssl",["version"]).status===0}})});
 const route=`/api/v1/workspaces/${fixture.workspaceId}/certops/certificates`;let item,certificatePem,before;
 const snapshot=async()=>({token:(await fixture.pool.query("SELECT name,contacts,description FROM tokens WHERE id=$1",[item.tokenId])).rows[0],groups:(await fixture.pool.query("SELECT contact_group_id FROM token_contact_groups WHERE token_id=$1 ORDER BY contact_group_id",[item.tokenId])).rows});
 try{await gate.preflight();ready=true;const generated=spawnSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout","private.key","-out","public.crt","-days","2","-subj","/CN=metadata.example.test"],{cwd:directory,timeout:20000,stdio:"ignore"});assert.equal(generated.status,0);certificatePem=fs.readFileSync(path.join(directory,"public.crt"),"utf8");
 await gate.scenario(scenarios[0],async()=>{const imported=await fixture.request(route,"POST",{certificatePem,sourceRef:"original-metadata-observer"});assert.equal(imported.status,201);item=imported.body.items[0];await fixture.pool.query("INSERT INTO workspace_settings(workspace_id,contact_groups) VALUES ($1,$2::jsonb) ON CONFLICT(workspace_id) DO UPDATE SET contact_groups=EXCLUDED.contact_groups",[fixture.workspaceId,JSON.stringify([{id:"ops",name:"Ops",emails:["ops@example.test"]},{id:"security",name:"Security",emails:["security@example.test"]}])]);const updated=await fixture.request(`/api/tokens/${item.tokenId}`,"PUT",{name:"Operator chosen certificate",contacts:"oncall@example.test",description:"Operator maintained",contact_group_ids:["ops","security"]});assert.equal(updated.status,200);before=await snapshot();assert.equal(before.token.contacts,"oncall@example.test");assert.deepEqual(before.groups.map(x=>x.contact_group_id),["ops","security"]);},{oracle:"Actual public token edit; contact-group configuration seeded only as prerequisite, no delivery claim"});
 await gate.scenario(scenarios[1],async()=>{const result=await fixture.request(route,"POST",{certificatePem,sourceRef:"competing-observer"});assert.equal(result.status,201);assert.equal(result.body.items[0].id,item.id);assert.equal(result.body.items[0].sourceRef,"original-metadata-observer");assert.deepEqual(await snapshot(),before);});
 await gate.scenario(scenarios[2],async()=>{const result=await fixture.request(`/api/tokens/${item.tokenId}`,"PUT",{contacts:"must-not-persist@example.test",contact_group_ids:["foreign-unconfigured"]});assert.equal(result.status,400);assert.deepEqual(await snapshot(),before);});
 await gate.scenario(scenarios[3],async()=>{const results=await Promise.all(Array.from({length:4},(_,i)=>fixture.request(route,"POST",{certificatePem,sourceRef:`observer-${i}`})));for(const result of results){assert.equal(result.status,201);assert.equal(result.body.items[0].tokenId,item.tokenId);}assert.deepEqual(await snapshot(),before);assert.equal((await fixture.pool.query("SELECT count(*)::int AS count FROM tokens WHERE workspace_id=$1 AND type='ssl_cert'",[fixture.workspaceId])).rows[0].count,1);});
 }catch(error){primary=error;throw error;}finally{const cleanup=async()=>{try{await fixture.cleanup();}finally{fs.rmSync(directory,{recursive:true,force:true});}};try{if(ready){await gate.scenario(scenarios[4],cleanup);await gate.finish({requiredScenarios:scenarios});}else await cleanup();}catch(error){if(primary)throw new AggregateError([primary,error],"Import metadata qualification and cleanup failed");throw error;}}
});
