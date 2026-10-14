/**
 * Qualify historical-to-candidate CertOps schema migration on an empty owned database.
 * certops-migration-upgrade.yml supplies exact baseline/candidate checkouts and a
 * digest-bound PostgreSQL image. Public API transitions and repeated startup are
 * checked against persisted rows; neither checkout nor a shared database is rewritten. */
"use strict";
const assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path"),os=require("node:os"),crypto=require("node:crypto"),https=require("node:https"),net=require("node:net");
const {spawn,spawnSync}=require("node:child_process");
const {createRequire}=require("node:module");
const {createApiFixture}=require("../tests/e2e/helpers/certops-api-fixture");
const {createHostGate}=require("../packages/agent/scripts/host-gate");
const BASELINE="b6ad7fc3d38db35b4c41a2c6137b0c39afc72158";
const IDS=["migration-source-identity","migration-baseline-public-state","migration-candidate-preserves-state","migration-resumes-approval-and-csr-observation","migration-repeat-idempotent","migration-owned-cleanup"];
async function run(){
  assert.ok(process.env.GITHUB_ACTIONS==="true"||process.env.CERTOPS_MIGRATION_LOCAL_FIXTURE==="1","Requires an isolated hosted or explicitly owned local fixture");assert.equal(process.env.CERTOPS_MIGRATION_DISPOSABLE_STACK,"1");
  assert.equal(process.env.DB_HOST,"127.0.0.1");assert.equal(process.env.DB_NAME,"certops_migration");assert.ok(Number(process.env.DB_PORT)>0);assert.notEqual(Number(process.env.DB_PORT),55432);
  const candidate=path.resolve(__dirname,".."),baseline=path.resolve(process.env.CERTOPS_MIGRATION_BASELINE_DIR||"");assert.notEqual(candidate,baseline);
  const git=(root,args)=>{const r=spawnSync("git",args,{cwd:root,encoding:"utf8",timeout:10000});assert.equal(r.status,0,"Source identity inspection failed");return r.stdout.trim();};
  const apiRequire=createRequire(path.join(candidate,"apps/api/package.json"));const {Pool}=apiRequire("pg");
  const pool=new Pool({host:process.env.DB_HOST,port:Number(process.env.DB_PORT),user:process.env.DB_USER,password:process.env.DB_PASSWORD,database:process.env.DB_NAME});
  const scratch=fs.mkdtempSync(path.join(os.tmpdir(),"certops-migration-"));let child,server,fixture,approver,primaryError,ready=false;
  const gate=createHostGate({suite:"core-api-migration-upgrade",strict:true,evidenceLevel:"e2e",reportPath:process.env.CERTOPS_MIGRATION_REPORT,requiredCapabilities:["postgres","openssl","historical-source","candidate-source"],fixtureSource:{file:"scripts/certops-migration-upgrade.js",sha256:crypto.createHash("sha256").update(fs.readFileSync(__filename)).digest("hex")},probeCapabilities:()=>({postgres:{available:true},openssl:{available:spawnSync("openssl",["version"]).status===0},"historical-source":{available:fs.existsSync(path.join(baseline,"apps/api/index.js"))},"candidate-source":{available:true}})});
  gate.report.artifactQualification=process.env.GITHUB_ACTIONS==="true"?"workflow-checkout-source":"local-worktree-source-baseline-sha-only";gate.report.sourceProvenance="historical-source-build-to-candidate-source";

  gate.report.fixtureTraffic="Real historical API public job/import/CSR/TLS-monitor operations; only login identities and memberships are fixture-seeded. Candidate migrations and public approval/TLS observation complete historical pending resources.";
  const openssl=args=>assert.equal(spawnSync("openssl",args,{cwd:scratch,stdio:"ignore",timeout:30000}).status,0,"Owned public certificate fixture failed");
  const read=name=>fs.readFileSync(path.join(scratch,name),"utf8");
  const schema=async()=>({migrations:(await pool.query("SELECT version,name FROM migrations ORDER BY version")).rows,tables:Number((await pool.query("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")).rows[0].count),columns:Number((await pool.query("SELECT count(*) FROM information_schema.columns WHERE table_schema='public'")).rows[0].count)});
  const stop=async()=>{if(!child)return;const current=child;child=null;if(current.exitCode!==null||current.signalCode!==null)return;let forced=false;await new Promise((resolve,reject)=>{let timer;const exited=()=>{clearTimeout(timer);if(forced)reject(new Error("Owned API required forced termination"));else resolve();};current.once("exit",exited);timer=setTimeout(()=>{forced=true;current.kill("SIGKILL");timer=setTimeout(()=>{current.removeListener("exit",exited);reject(new Error("Owned API survived forced termination deadline"));},5000);},20000);current.kill("SIGTERM");});};
  let apiPort;const baseUrl=()=>`http://127.0.0.1:${apiPort}`;
  const start=async root=>{child=spawn(process.execPath,["index.js"],{cwd:path.join(root,"apps/api"),env:{...process.env,NODE_ENV:"test",HOST:"127.0.0.1",PORT:String(apiPort),API_URL:baseUrl(),APP_URL:"http://127.0.0.1:15173",CERTOPS_ENABLED:"true",DISABLE_ADMIN_BOOTSTRAP:"true",SESSION_SECRET:"migration-fixture-session-only",CERTOPS_SIGNING_ENCRYPTION_KEY:"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",CERTOPS_REGISTRATION_ENCRYPTION_KEY:"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},stdio:"ignore"});const started=child;for(let i=0;i<120;i++){assert.equal(started.exitCode,null,"Owned API failed startup/migration");try{if((await fetch(baseUrl(),{signal:AbortSignal.timeout(1000)})).ok)return;}catch{}await new Promise(resolve=>setTimeout(resolve,500));}throw new Error("Owned API readiness exceeded deadline");};
  let oldSchema,oldJob,imported,csr,targetId,monitorId;
  try{
    assert.equal(await gate.preflight(),true);ready=true;
    await gate.scenario(IDS[0],async()=>{gate.report.databaseRuntime={serverVersion:(await pool.query("SHOW server_version")).rows[0].server_version,imageId:process.env.CERTOPS_MIGRATION_PG_IMAGE_ID};assert.match(gate.report.databaseRuntime.imageId||"",/^sha256:[a-f0-9]{64}$/);assert.equal(git(baseline,["rev-parse","HEAD"]),BASELINE);assert.equal(git(candidate,["rev-parse","HEAD"]),process.env.GITHUB_SHA);assert.match(process.env.GITHUB_SHA,/^[a-f0-9]{40}$/);assert.notEqual(process.env.GITHUB_SHA,BASELINE);assert.equal((await pool.query("SELECT count(*)::int AS n FROM information_schema.tables WHERE table_schema='public'")).rows[0].n,0,"Migration fixture database must start empty");gate.report.sourceIdentity={baseline:{sha:BASELINE,version:JSON.parse(fs.readFileSync(path.join(baseline,"package.json"))).version,lockfileSha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(baseline,"pnpm-lock.yaml"))).digest("hex")},candidate:{sha:process.env.GITHUB_SHA,version:JSON.parse(fs.readFileSync(path.join(candidate,"package.json"))).version,lockfileSha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(candidate,"pnpm-lock.yaml"))).digest("hex")}};});
    apiPort=await new Promise((resolve,reject)=>{const s=net.createServer();s.once("error",reject);s.listen(0,"127.0.0.1",()=>{const port=s.address().port;s.close(error=>error?reject(error):resolve(port));});});
    await start(baseline);process.env.CERTOPS_CSR_DISPOSABLE_STACK="1";fixture=await createApiFixture(baseUrl());approver=await createApiFixture(baseUrl());await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES ($1,$2,'workspace_manager')",[fixture.workspaceId,approver.userId]);
    const prefix=`/api/v1/workspaces/${fixture.workspaceId}`;
    await gate.scenario(IDS[1],async()=>{
      openssl(["req","-x509","-newkey","rsa:2048","-nodes","-keyout","old.key","-out","old.crt","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost,IP:127.0.0.1","-days","2"]);
      openssl(["req","-new","-newkey","rsa:2048","-nodes","-keyout","new.key","-out","new.csr","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost,IP:127.0.0.1"]);
      openssl(["x509","-req","-in","new.csr","-signkey","new.key","-copy_extensions","copy","-days","2","-out","new.crt"]);
      server=https.createServer({key:read("old.key"),cert:read("old.crt")},(_req,res)=>res.end("Owned migration TLS fixture"));await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve);});
      const added=await fixture.request(`${prefix}/domains`,"POST",{url:`https://127.0.0.1:${server.address().port}`,health_check_enabled:false,check_interval:"1min"});assert.equal(added.status,201);monitorId=added.body.id;
      targetId=(await pool.query("SELECT target_id FROM certificate_instances WHERE workspace_id=$1 AND domain_monitor_id=$2 ORDER BY observed_at DESC LIMIT 1",[fixture.workspaceId,monitorId])).rows[0].target_id;assert.ok(targetId);
      const imp=await fixture.request(`${prefix}/certops/imports`,"POST",{certificates:[read("old.crt")],sourceRef:"migration-baseline-public-certificate"});assert.equal(imp.status,202);imported=imp.body.items[0];assert.ok(imported.id);assert.equal(imported.fingerprintSha256,new crypto.X509Certificate(read("old.crt")).fingerprint256.replace(/:/g,"").toLowerCase());
      assert.equal((await fixture.request(`${prefix}/certops/settings`,"PUT",{certOpsRequireApprovalAlways:true,reason:"Migration pending approval fixture"})).status,200);
      const job=await fixture.request(`${prefix}/certops/jobs`,"POST",{operation:"noop",idempotencyKey:crypto.randomUUID()});assert.equal(job.status,201);assert.equal(job.body.job.status,"pending_approval");oldJob=(await pool.query("SELECT id,status,payload,requested_by_user_id FROM certificate_jobs WHERE id=$1",[job.body.job.id])).rows[0];assert.equal(oldJob.requested_by_user_id,fixture.userId);
      const created=await fixture.request(`${prefix}/certops/csrs`,"POST",{csrPem:read("new.csr"),targetId});assert.equal(created.status,201);
      const signed=await fixture.request(`${prefix}/certops/csrs/${created.body.id}/signed-certificate`,"POST",{certificatePem:read("new.crt")});assert.equal(signed.status,200);assert.equal(signed.body.status,"signed_pending_install");csr=signed.body;
      oldSchema=await schema();gate.report.baselineSchema=oldSchema;
    });
    await stop();await start(candidate);
    await gate.scenario(IDS[2],async()=>{
      const current=await schema();for(const migration of oldSchema.migrations)assert.ok(current.migrations.some(row=>row.version===migration.version&&row.name===migration.name));assert.ok(current.migrations.length>oldSchema.migrations.length,"Candidate must actually apply additional historical-to-candidate migrations");assert.ok(current.tables>=oldSchema.tables);assert.ok(current.columns>=oldSchema.columns);gate.report.candidateSchema=current;
      assert.deepEqual((await pool.query("SELECT id,status,payload,requested_by_user_id FROM certificate_jobs WHERE id=$1",[oldJob.id])).rows[0],oldJob);
      const preserved=await fixture.request(`${prefix}/certops/csrs/${csr.id}`);assert.equal(preserved.status,200);for(const field of ["id","targetId","managedCertificateId","spkiFingerprintSha256","signedFingerprintSha256","status"])assert.equal(preserved.body[field],csr[field]);
      const detail=await fixture.request(`${prefix}/certops/certificates/${imported.id}`);assert.equal(detail.status,200);for(const field of ["id","tokenId","fingerprintSha256","spkiFingerprintSha256","sourceRef"])assert.equal(detail.body.certificate[field],imported[field]);
      const imp=await fixture.request(`${prefix}/certops/imports`,"POST",{certificates:[read("old.crt")],sourceRef:imported.sourceRef});assert.equal(imp.status,202);for(const field of ["id","tokenId","fingerprintSha256","spkiFingerprintSha256","sourceRef"])assert.equal(imp.body.items[0][field],imported[field]);
    });
    await gate.scenario(IDS[3],async()=>{
      assert.equal((await fixture.request(`${prefix}/certops/jobs/${oldJob.id}/approve`,"POST",{reason:"Self approval migration refusal"})).status,403);
      assert.equal((await approver.request(`${prefix}/certops/jobs/${oldJob.id}/approve`,"POST",{reason:"Independent approval after actual migration"})).status,200);
      const approved=(await pool.query("SELECT status,approved_by_user_id,payload,approved_payload_hash FROM certificate_jobs WHERE id=$1",[oldJob.id])).rows[0];assert.equal(approved.status,"pending");assert.equal(approved.approved_by_user_id,approver.userId);assert.deepEqual(approved.payload,oldJob.payload);assert.match(approved.approved_payload_hash,/^[a-f0-9]{64}$/);
      server.setSecureContext({key:read("new.key"),cert:read("new.crt")});assert.equal((await fixture.request(`${prefix}/domains`,"POST",{url:`https://127.0.0.1:${server.address().port}`,health_check_enabled:false,check_interval:"1min"})).status,200);
      const completed=(await fixture.request(`${prefix}/certops/csrs/${csr.id}`)).body;assert.equal(completed.status,"completed");assert.ok(completed.observedInstanceId);assert.equal(completed.confirmationMethod,null);assert.equal(completed.confirmedAt,null);assert.equal(completed.signedFingerprintSha256,new crypto.X509Certificate(read("new.crt")).fingerprint256.replace(/:/g,"").toLowerCase());gate.report.actualTlsObservedPromotion=true;
    });
    await gate.scenario(IDS[4],async()=>{const before=await schema();const state=(await fixture.request(`${prefix}/certops/csrs/${csr.id}`)).body;await stop();await start(candidate);assert.deepEqual(await schema(),before);const replay=(await fixture.request(`${prefix}/certops/csrs/${csr.id}`)).body;assert.equal(replay.status,"completed");assert.equal(replay.observedInstanceId,state.observedInstanceId);assert.equal((await approver.request(`${prefix}/certops/jobs/${oldJob.id}/approve`,"POST",{reason:"Duplicate approval refusal"})).status,409);gate.report.repeatMigrationSchemaUnchanged=true;});
  }catch(error){primaryError=error;throw error;}
  finally{
    const cleanup=async()=>{const errors=[];for(const action of [()=>fixture?.cleanup(),()=>approver?.cleanup(),()=>stop(),async()=>{if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}},()=>pool.end(),()=>fs.rmSync(scratch,{recursive:true,force:true})]){try{await action();}catch(error){errors.push(error);}}if(errors.length)throw new AggregateError(errors,"Owned migration fixture cleanup failed");};
    try{if(ready){await gate.scenario(IDS[5],cleanup);await gate.finish({requiredScenarios:IDS});}else await cleanup();}catch(error){if(primaryError)throw new AggregateError([primaryError,error],"Migration journey and finalization failed");throw error;}
  }
}
if(require.main===module)run().catch(()=>{process.stderr.write("Historical-to-candidate migration qualification failed; consult sanitized report\n");process.exitCode=1;});
module.exports={run,BASELINE,IDS};
