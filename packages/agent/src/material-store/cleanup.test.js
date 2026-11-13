"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),os=require("node:os"),crypto=require("node:crypto"),http=require("node:http");
const {executeMaterialCleanup}=require("./cleanup");
const {applyRestrictivePermissions}=require("../platform");
const {filterQualifiedCapabilities}=require("../capabilities");
const {markSideEffectReached,scanUnresolvedJournalEntries}=require("../job-journal");
async function fixture(t){
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),"tt-cleanup-test-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const tokenFile=path.join(dir,"cleanup-token");fs.writeFileSync(tokenFile,"isolated-cleanup-token-only",{mode:0o600});applyRestrictivePermissions(tokenFile);
  const workspaceId=crypto.randomUUID(),groupId=crypto.randomUUID(),materialVersionId=crypto.randomUUID();
  const metadata={versions:{1:{created_time:new Date(Date.now()-100*86400000).toISOString(),deletion_time:"",destroyed:false},2:{created_time:new Date().toISOString(),deletion_time:"",destroyed:false}}};
  const requests=[],state={loseResponse:false,deletes:0,afterDelete:undefined};
  const server=http.createServer((req,res)=>{const url=req.url;requests.push({method:req.method,url});
    if(req.method==="GET" && url===`/v1/secret/metadata/${workspaceId}/${groupId}/bundles/${materialVersionId}`){res.setHeader("content-type","application/json");res.end(JSON.stringify({data:metadata}));return;}
    if(req.method==="POST" && url===`/v1/secret/delete/${workspaceId}/${groupId}/bundles/${materialVersionId}`){let body="";req.on("data",c=>body+=c);req.on("end",()=>{assert.deepEqual(JSON.parse(body),{versions:[1]});state.onDelete?.();state.deletes++;metadata.versions[1].deletion_time=state.afterDelete===undefined?new Date().toISOString():state.afterDelete;if(state.loseResponse){state.loseResponse=false;res.destroy();}else{res.writeHead(204);res.end();}});return;}
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
  assert.deepEqual(filterQualifiedCapabilities(["material-cleanup-openbao-kv2-v1","material-consumer-staging-v1"]),[]);
});
test("cleanup soft deletes only the exact version, preserves newer material, never retrieves a key and is idempotent",async t=>{
  const f=await fixture(t);assert.equal((await f.run()).status,"succeeded");assert.equal(f.state.deletes,1);assert.equal(f.metadata.versions[2].deletion_time,"");
  const again=await f.run();assert.equal(again.status,"succeeded");assert.equal(again.cleanupReceipt.softDeleted,true);assert.equal(f.state.deletes,1);
  f.options.job.materialCleanup=Object.fromEntries(Object.entries(f.intent).reverse());assert.equal((await f.run()).status,"succeeded","Wire key ordering cannot change the authorized intent");assert.equal(f.state.deletes,1);
  assert.ok(f.requests.every(r=>!r.url.includes("/data/") && !r.url.includes("/destroy/")));
  assert.doesNotMatch(JSON.stringify(again),/token|PRIVATE KEY|https?:/);
});
test("real execution journal records cleanup before the exact provider delete",async t=>{
  const f=await fixture(t),attemptId=crypto.randomUUID(),claimId=crypto.randomUUID();
  f.options.onBeforeMutation=stage=>markSideEffectReached({stateDir:f.options.stateDir,jobId:f.options.job.jobId,attemptId,claimId,stage});
  f.state.onDelete=()=>{
    const [entry]=scanUnresolvedJournalEntries(f.options.stateDir);
    assert.equal(entry.jobId,f.options.job.jobId);assert.equal(entry.attemptId,attemptId);assert.equal(entry.claimId,claimId);
    assert.equal(entry.stage,"material_cleanup_soft_delete");
  };
  const result=await f.run();
  assert.equal(result.status,"succeeded");assert.equal(result.cleanupReceipt.softDeleted,true);assert.equal(f.state.deletes,1);
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

test("only past/present effective deletion can shortcut cleanup, while a future scheduled deletion must still be deleted",async t=>{
  const f=await fixture(t);
  for(const timestamp of [new Date(Date.now()-60000).toISOString(),new Date().toISOString()]){
    f.metadata.versions[1].deletion_time=timestamp;
    const result=await f.run();assert.equal(result.status,"succeeded");assert.equal(result.cleanupReceipt.softDeleted,true);assert.equal(f.state.deletes,0);
  }
  f.metadata.versions[1].deletion_time=new Date(Date.now()+86400000).toISOString();
  const result=await f.run();assert.equal(result.status,"succeeded");assert.equal(f.state.deletes,1,"Scheduled deletion is still readable and needs an explicit delete");
});
test("future, missing and invalid post-delete metadata never produce a successful cleanup receipt",async t=>{
  const f=await fixture(t);
  for(const timestamp of [new Date(Date.now()+86400000).toISOString(),"",null,"not-a-date"]){
    f.metadata.versions[1].deletion_time="";f.state.afterDelete=timestamp;
    const result=await f.run();assert.equal(result.status,"orphaned_unknown_effect");assert.equal(result.cleanupReceipt,undefined);
  }
  f.state.afterDelete=new Date(Date.now()-1000).toISOString();f.metadata.versions[1].deletion_time="";
  assert.equal((await f.run()).status,"succeeded","Original-intent retry remains recoverable after ineffective deletion");
});
test("missing or invalid pre-delete timestamps fail closed before any mutation",async t=>{
  const f=await fixture(t);
  for(const timestamp of [undefined,null,"not-a-date"]){
    f.metadata.versions[1].deletion_time=timestamp;
    assert.equal((await f.run()).status,"blocked");assert.equal(f.state.deletes,0);
  }
});
test("new provider/operation identity and previously signed legacy intents both retain the exact cleanup retry path",async t=>{
  const f=await fixture(t);
  const legacy=JSON.stringify(f.intent);
  assert.equal((await f.run()).status,"succeeded");assert.equal(JSON.stringify(f.intent),legacy);
  const modern={...f.intent,operation:"soft-delete",provider:"vault-kv2"};delete modern.type;
  f.options.job={...f.options.job,jobId:crypto.randomUUID(),materialCleanup:modern};
  assert.equal((await f.run()).status,"succeeded");assert.equal(f.state.deletes,1);
  f.options.stores.customer.provider="openbao-kv2";
  f.options.job.jobId=crypto.randomUUID();
  await assert.rejects(f.run,{code:"material_provider_mismatch"},"Another provider cannot use a Vault-only cleanup authorization");
});

test("explicit OpenBao cleanup uses its own exact-version method and cannot reuse a Vault intent",async t=>{
  const f=await fixture(t);f.options.stores.customer.provider="openbao-kv2";
  const intent={...f.intent,operation:"soft-delete",provider:"openbao-kv2"};delete intent.type;
  f.options.job.materialCleanup=intent;
  const result=await f.run();assert.equal(result.status,"succeeded");assert.equal(result.cleanupReceipt.method,"openbao-kv2-soft-delete");
  assert.equal(f.state.deletes,1);assert.equal(f.metadata.versions[2].deletion_time,"");
  assert.equal((await f.run()).status,"succeeded");assert.equal(f.state.deletes,1);
});
test("expiry while persisting the destructive journal prevents the subsequent provider delete",async t=>{
  const f=await fixture(t);let time=Date.now();t.mock.method(Date,"now",()=>time);
  f.options.onBeforeMutation=()=>{time=Date.parse(f.intent.expiresAt)+1;};
  const result=await f.run();assert.equal(result.status,"orphaned_unknown_effect");
  assert.equal(result.errorMessage,"material_cleanup_authorization_expired");assert.equal(f.state.deletes,0);
});


/* The dispatcher supports cleanup only on Linux. Test capability injection is
 * confined to this process and the preceding manifest test verifies the release gate. */
test("signed cleanup dispatcher recovers an interrupted provider delete without repeating it", {
  skip: process.platform !== "linux", // skip-reason: platform
}, async (t) => {
  const f = await fixture(t);
  const modulePath = require.resolve("../index");
  let dispatcher = require(modulePath);
  const originalModule = require.cache[modulePath];
  t.after(() => { require.cache[modulePath] = originalModule; });
  const { generateSigningKeyPair, signJobPayload } = require("../signing");
  const { AgentProtocolError } = require("../protocol");
  const capability = "material-cleanup-vault-kv2-v1";
  const signingKey = generateSigningKeyPair();
  const config = {
    execution: {
      enabled: true, dryRun: false, keysDir: path.join(f.options.stateDir, "keys"),
      replayStorePath: path.join(f.options.stateDir, "replay.json"),
      outboxDir: path.join(f.options.stateDir, "outbox"), clockDriftToleranceMs: 30000,
    },
    pinnedSigningKey: { signingKeyId: signingKey.signingKeyId, publicKeyPem: signingKey.publicKeyPem },
  };
  const store = f.options.stores.customer;
  const loopback = store.address;
  store.address = loopback.replace("http:", "https:");
  t.mock.method(require("node:https"), "request", (url, options, listener) => {
    assert.equal(url.origin, store.address);
    return http.request(new URL(url.pathname, loopback), options, listener);
  });
  const certificateId = crypto.randomUUID();
  function dispatch(intent = f.intent, options = {}) {
    const claimId = crypto.randomUUID();
    const job = {
      schemaVersion: 1, jobId: f.options.job.jobId, workspaceId: options.workspaceId || f.options.job.workspaceId,
      agentId: "cleanup-fixture-agent", certificateId,
      action: "cleanup-from-store", mode: "real", keyMode: "vault-managed",
      target: { type: "domain", reference: "cleanup.example.test" },
      claimId, nonce: crypto.randomUUID(), materialCleanup: intent,
      requestedAt: new Date().toISOString(), issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 5 * 60000).toISOString(), signingKeyId: signingKey.signingKeyId,
    };
    job.signature = signJobPayload({ job, privateKeyPem: signingKey.privateKeyPem });
    const reports = [];
    const client = {
      renewLease: async () => {
        if (options.staleLease) throw new AgentProtocolError("claim expired", { status: 410 });
        return { ok: true, jobId: job.jobId, claimId, status: "running",
          leaseExpiresAt: new Date(Date.now() + 5 * 60000).toISOString() };
      },
      reportResult: async (body) => { reports.push(body); },
      reportEvidence: async () => {},
    };
    const executionContext = { ...dispatcher.buildExecutionContext({ config }), materialStores: f.options.stores };
    return dispatcher.handleClaimedJob({ job, client, executionContext, boundAgentId: job.agentId,
      policyEngine: { evaluateJob: () => ({ allowed: true }) },
    }).then(outcome => ({ ...outcome, report: reports.at(-1), claimId }));
  }

  assert.match((await dispatch()).report.errorMessage, /has not qualified/);
  assert.equal(f.requests.length, 0);
  t.mock.method(require("../capabilities"), "filterQualifiedCapabilities", (candidates) => {
    const qualified = filterQualifiedCapabilities(candidates);
    return candidates.includes(capability) ? [...qualified, capability] : qualified;
  });
  delete require.cache[modulePath];
  dispatcher = require(modulePath);

  f.state.loseResponse = true;
  const outbox = config.execution.outboxDir;
  f.state.onDelete = () => {
    fs.renameSync(outbox, outbox + ".saved");
    fs.writeFileSync(outbox, "unavailable after the provider mutation");
  };
  await assert.rejects(dispatch());
  fs.unlinkSync(outbox);
  fs.renameSync(outbox + ".saved", outbox);
  delete f.state.onDelete;
  assert.equal(f.state.deletes, 1);
  const [interrupted] = scanUnresolvedJournalEntries(f.options.stateDir);
  assert.equal(interrupted.stage, "material_cleanup_soft_delete");

  const denied = [
    await dispatch({ ...f.intent, expiresAt: new Date(Date.now() - 60000).toISOString() }),
    await dispatch({ ...f.intent, providerVersion: 2 }),
    await dispatch(f.intent, { workspaceId: crypto.randomUUID() }),
    await dispatch(f.intent, { staleLease: true }),
  ];
  assert.ok(denied.every(result => result.status !== "succeeded" && !result.report?.cleanupReceipt));
  assert.equal(f.state.deletes, 1);

  const { withMaterialLock } = require("./lifecycle");
  await withMaterialLock(path.join(f.options.stateDir, "material-locks"),
    "issuer:" + f.options.job.workspaceId + ":" + f.intent.groupId, async () => {
      assert.notEqual((await dispatch()).status, "succeeded");
    });
  const priorDeletion = f.metadata.versions[1].deletion_time;
  f.metadata.versions[1].deletion_time = "";
  assert.notEqual((await dispatch()).status, "succeeded", "a journal does not authorize another mutation");
  assert.equal(f.state.deletes, 1);
  f.metadata.versions[1].deletion_time = priorDeletion;

  const recovered = await dispatch();
  assert.equal(recovered.status, "succeeded", recovered.report?.errorMessage);
  assert.equal(recovered.report.claimId, recovered.claimId);
  assert.notEqual(recovered.claimId, interrupted.claimId);
  const receipt = recovered.report.cleanupReceipt;
  assert.equal(receipt.workspaceId, f.options.job.workspaceId);
  assert.equal(receipt.groupId, f.intent.groupId);
  assert.equal(receipt.materialVersionId, f.intent.materialVersionId);
  assert.equal(receipt.providerVersion, 1);
  assert.equal(receipt.softDeleted, true);
  assert.equal(f.state.deletes, 1);
  assert.equal(scanUnresolvedJournalEntries(f.options.stateDir).length, 0);
});
