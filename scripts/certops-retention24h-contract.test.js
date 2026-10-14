"use strict";
/** Synthetic lease/cost-guard refusals only; these checks never grant native proof. */
const test = require("node:test"), assert = require("node:assert/strict");
const c = require("./certops-retention24h-contract"), controller = require("./certops-retention24h-controller");
const owner = { candidateSha: "a".repeat(40), runId: "123", runAttempt: "1", nonce: "b".repeat(64), vmResourceId: "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/tt-certops-123-1/providers/Microsoft.Compute/virtualMachines/windows-agent", vmId: "22222222-2222-2222-2222-222222222222", taskName: `TokenTimer-Retention24h-${"b".repeat(64)}`, nodeSha256: "c".repeat(64), keeperSha256: "d".repeat(64) };
const created = "2026-10-14T00:00:00.000Z", at = hours => new Date(Date.parse(created) + hours * c.HOUR).toISOString();
function evidence() { return { ...owner, ...Object.fromEntries(["taskXmlVerified", "vmIdentityVerified", "nodeHashVerified", "keeperHashVerified", "residentProcessVerified", "soleAgentStoppedAndDrained", "productionCutoverVerified", "nativeCustodyVerified", "trustedTlsVerified", "ledgerUnmodified"].map(k => [k, true])), principalSid: "S-1-5-18", taskState: "Running", processId: 1234, bootTime: created, monotonicElapsedMs: 1000, verifiedCutoverAt: at(1), oldNotAfter: at(48), cleanupDeadline: at(25) }; }
function github() { return { ...owner, repository: "tokentimerch/tokentimer-core", event: "workflow_dispatch", headBranch: "main", workflowPath: ".github/workflows/certops-retention24h-prepare.yml", status: "completed", conclusion: "success" }; }
test("ordinary lease stays four hours; independently attested handoff is immutable32h", () => {
 const lease = c.createLease(owner, created); assert.equal(lease.expiresAt, at(4));
 const intent = controller.handoffIntent({ lease, preparedLease: lease, observed: evidence(), observedAt: at(2) });
 assert.equal(intent.lease.expiresAt, at(32)); assert.equal(intent.lease.createdAt, created); assert.equal(lease.phase, "preparing");
 assert.throws(() => c.attestHandoff(intent.lease, evidence(), at(3)));
 assert.throws(() => c.attestHandoff(lease, evidence(), at(4)));
 for (const patch of [{expiresAt:at(33)},{hardExpiresAt:at(33)},{createdAt:at(1)},{phase:"unknown"}]) assert.throws(() => c.verifyLease({...intent.lease,...patch}));
});
test("every task/process/VM/cutover custody requirement fails closed", () => {
 const lease=c.createLease(owner,created), good=evidence();
 for (const key of Object.keys(good)) { const missing={...good};delete missing[key]; assert.throws(()=>c.attestHandoff(lease,missing,at(2)),key); }
 for (const [key,value] of Object.entries(good)) if(value===true)assert.throws(()=>c.attestHandoff(lease,{...good,[key]:false},at(2)));
 for(const patch of [{principalSid:"S-1-5-20"},{taskState:"Ready"},{processId:0},{monotonicElapsedMs:c.INITIAL},{cleanupDeadline:at(24)},{oldNotAfter:at(26)},{verifiedCutoverAt:at(3)},{vmId:"44444444-4444-4444-4444-444444444444"}])assert.throws(()=>c.attestHandoff(lease,{...good,...patch},at(2)));
});
test("cancellation and hard expiry independently require owned cleanup",()=>{
 const lease=c.createLease(owner,created), long=c.attestHandoff(lease,evidence(),at(2));
 assert.equal(c.cleanupDecision(lease,github(),at(4)),"delete-owned-expired");
 assert.equal(c.cleanupDecision(long,{...github(),conclusion:"cancelled"},at(3)),"delete-owned-failed-owner");
 assert.equal(c.cleanupDecision(long,github(),at(31)),"retain-within-owned-lease");
 assert.equal(c.cleanupDecision(long,null,at(32)),"delete-owned-expired");
 assert.throws(()=>c.cleanupDecision(long,{...github(),candidateSha:"e".repeat(40)},at(3)));
});
test("short finalizer verifies trusted successful owning workflow and exact currentVM",()=>{
 const lease=c.attestHandoff(c.createLease(owner,created),evidence(),at(2));
 assert.equal(controller.finalizeIntent({lease,preparedLease:c.createLease(owner,created),githubOwner:github(),observed:evidence(),observedAt:at(26)}).action,"collect-owned-public-report-then-delete");
 for(const patch of [{repository:"foreign/core"},{event:"pull_request"},{headBranch:"feature"},{status:"in_progress"},{conclusion:"cancelled"},{workflowPath:".github/workflows/ci.yml"}])assert.throws(()=>controller.finalizeIntent({lease,preparedLease:c.createLease(owner,created),githubOwner:{...github(),...patch},observed:evidence(),observedAt:at(26)}));
 assert.throws(()=>controller.finalizeIntent({lease,preparedLease:c.createLease(owner,created),githubOwner:github(),observed:{...evidence(),nonce:"f".repeat(64)},observedAt:at(26)}));
 assert.throws(()=>controller.finalizeIntent({lease,preparedLease:c.createLease(owner,created),githubOwner:github(),observed:evidence(),observedAt:at(32)}));
});

test("resident clock samples reject regression, wall jumps and unbounded lifetime",()=>{
 const {verifyResidentSample}=require("../tests/e2e/helpers/certops-retention24h-keeper");
 assert.equal(verifyResidentSample({startWallMs:100000,wallMs:110000,elapsedMs:10000,priorElapsedMs:9000}),true);
 for(const patch of [{elapsedMs:8000},{wallMs:120000},{wallMs:90000},{elapsedMs:NaN},{elapsedMs:c.DAY+c.HOUR+1}])assert.throws(()=>verifyResidentSample({startWallMs:100000,wallMs:110000,elapsedMs:10000,priorElapsedMs:9000,...patch}));
});

test("mutable guest lease cannot move original trusted preparation creation/hardexpiry",()=>{
 const prepared=c.createLease(owner,created), long=c.attestHandoff(prepared,evidence(),at(2));
 assert.equal(c.verifyOriginalLease(long,prepared),true);
 const forged={...long,createdAt:at(1),expiresAt:at(33),hardExpiresAt:at(33)};
 assert.equal(c.verifyLease(forged),forged);
 assert.throws(()=>c.verifyOriginalLease(forged,prepared));
 assert.throws(()=>controller.handoffIntent({lease:prepared,observed:evidence(),observedAt:at(2)}));
});

test("native runtime config rejects foreign paths, missing source custody and fabricated expiry",()=>{
 const fs=require("node:fs"),crypto=require("node:crypto"),path=require("node:path"),runtime=require("./certops-retention24h-runtime");
 const cert=name=>new crypto.X509Certificate(fs.readFileSync(path.join(__dirname,"../packages/agent/src/verify/fixtures",name)));
 const a=cert("leaf.crt.pem"),b=cert("selfsigned.crt.pem"),containerName="tokentimer-enr-11111111-1111-1111-1111-111111111111",next="tokentimer-enr-22222222-2222-2222-2222-222222222222";
 const directory=`C:\\ttqualification\\retention24h\\${owner.nonce}`,file=path.win32.join(directory,"keeper-config.json");
 const cfg={drainedTree:[{pid:123,createdAt:created}],lease:c.createLease(owner,created),stateDir:path.win32.join(directory,"agent"),retentionHours:24,collectorHelper:{file:"packages/agent/bin/tokentimer-adcs-chain-amd64.exe",sha256:"f".repeat(64)},requiredSources:[...new Set([...runtime.REQUIRED_SOURCES,...require("../tests/e2e/certops-adcs-retention24h-prepare").PREPARATION_SOURCES])].map(file=>({file,sha256:"e".repeat(64)})),predecessor:{thumbprint:a.fingerprint.replace(/:/g,""),containerName,certificateDerB64:a.raw.toString("base64")},replacement:{thumbprint:b.fingerprint.replace(/:/g,""),containerName:next,certificateDerB64:b.raw.toString("base64")},domain:"certops-adcs-1234567890-retention24h.example.test",site:"TTADCS-1234567890-retention24h",port:443,caPem:a.toString(),cleanupDeadline:at(25),originalLedgerRow:{oldThumbprint:a.fingerprint.replace(/:/g,""),replacementThumbprint:b.fingerprint.replace(/:/g,""),cngKeyContainerId:containerName,verifiedCutoverAt:at(1),oldNotAfter:new Date(a.validTo).toISOString(),ownershipProvenance:"tokentimer_installed",store:"My",jobOrRollbackJournalRefs:[],lifecycleState:"pending_retention",deferralReason:null}};
 assert.equal(runtime.verifyConfig(cfg,file),true);
 const declared64=structuredClone(cfg);
 for(const name of fs.readdirSync(__dirname).filter(name=>name.endsWith(".js"))){const publicPath="scripts/"+name;if(declared64.requiredSources.some(item=>item.file===publicPath))continue;declared64.requiredSources.push({file:publicPath,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(__dirname,name))).digest("hex")});if(declared64.requiredSources.length===64)break;}
 assert.equal(declared64.requiredSources.length,64);assert.equal(runtime.verifyConfig(declared64,file),true);
 assert.throws(()=>runtime.verifyConfig({...declared64,requiredSources:[...declared64.requiredSources,{file:"scripts/not-declared.js",sha256:"f".repeat(64)}]},file));
 for(const patch of [{stateDir:"C:\\foreign"},{retentionHours:23},{requiredSources:[]},{requiredSources:[...cfg.requiredSources,cfg.requiredSources[0]]},{cleanupDeadline:at(24)},{domain:"foreign.example.test"},{predecessor:{...cfg.predecessor,containerName:next}},{originalLedgerRow:{...cfg.originalLedgerRow,oldNotAfter:at(48)}},{originalLedgerRow:{...cfg.originalLedgerRow,ownershipProvenance:"preexisting"}}])assert.throws(()=>runtime.verifyConfig({...cfg,...patch},file));
 assert.throws(()=>runtime.verifyConfig(cfg,file.replace(owner.nonce,"f".repeat(64))));
});

test("native DateTimeOffset tag formats normalize once before immutable lease creation",()=>{
 for(const raw of ["2026-10-14T00:00:00.0000000+00:00","2026-10-14T00:00:00.0000000Z","2026-10-14T02:00:00.0000000+02:00"]){assert.throws(()=>c.createLease(owner,raw));assert.equal(c.createLease(owner,c.canonicalCreatedAt(raw)).createdAt,created);}
 assert.throws(()=>c.canonicalCreatedAt("not-a-date"));
});

test("native control path validators accept only their exact owned nonce paths",()=>{
 const fs=require("node:fs"),path=require("node:path");
 for(const [name,field,suffix]of [["native","ConfigPath","keeper-config.json"],["task","ConfigPath","keeper-config.json"],["stop-agent","StateDir","agent"]]){
  const source=fs.readFileSync(path.join(__dirname,`certops-retention24h-${name}.ps1`),"utf8");
  const pattern=source.match(new RegExp("ValidatePattern\\('([^']+)'\\)\\]\\[string\\]\\$"+field))[1];
  const owned=`C:\\ttqualification\\retention24h\\${owner.nonce}\\${suffix}`;assert.equal(new RegExp(pattern).test(owned),true,name);
  assert.equal(new RegExp(pattern).test(owned.replace(owner.nonce,"foreign")),false);assert.equal(new RegExp(pattern).test("C:\\foreign\\"+suffix),false);
 }
});

test("fresh resident fixture admits only its exact production ledger and sweep outcome",()=>{
 const fs=require("node:fs"),path=require("node:path"),runtime=require("./certops-retention24h-runtime"),retention=require("../packages/agent/src/windows-retention");
 const root=path.resolve(__dirname,"../.build");fs.mkdirSync(root,{recursive:true});const owned=fs.mkdtempSync(path.join(root,"retention24h-ledger-proof-")),dir=path.join(owned,"windows-retention"),a="A".repeat(40),b="B".repeat(40);fs.mkdirSync(dir);
 try{
  assert.throws(()=>runtime.assertOwnedLedgerInventory(owned,a));fs.writeFileSync(path.join(dir,a+".json"),"{}");runtime.assertOwnedLedgerInventory(owned,a);
  fs.writeFileSync(path.join(dir,b+".json"),"{}");assert.throws(()=>runtime.assertOwnedLedgerInventory(owned,a));fs.unlinkSync(path.join(dir,b+".json"));runtime.assertOwnedLedgerInventory(owned,a);
  const counts=removed=>Object.fromEntries(retention.DEFERRAL_REASONS.map(reason=>[reason,!removed&&reason==="deadline_not_reached"?1:0]));
  const kept={removed:[],deferred:[{oldThumbprint:a,reason:"deadline_not_reached"}],deferredCountByReason:counts(false)},removed={removed:[a],deferred:[],deferredCountByReason:counts(true)};
  runtime.assertOwnedSweepSummary(kept,a,"kept-before-deadline");runtime.assertOwnedSweepSummary(removed,a,"removed-after-real-day");
  for(const patch of [{removed:[a]},{deferred:[]},{deferred:[{oldThumbprint:b,reason:"deadline_not_reached"}]},{deferred:[{oldThumbprint:a,reason:"shared_key_container"}]},{deferredCountByReason:counts(true)}])assert.throws(()=>runtime.assertOwnedSweepSummary({...kept,...patch},a,"kept-before-deadline"));
  for(const patch of [{removed:[a,b]},{removed:[]},{deferred:kept.deferred},{deferredCountByReason:counts(false)}])assert.throws(()=>runtime.assertOwnedSweepSummary({...removed,...patch},a,"removed-after-real-day"));
 }finally{assert.equal(path.dirname(owned),root);assert.match(path.basename(owned),/^retention24h-ledger-proof-/);fs.rmSync(owned,{recursive:true});}
});
