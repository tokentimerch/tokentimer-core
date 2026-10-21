/**
 * Qualification: authenticated published Linux predecessor upgrade
 *
 * Use trusted-main certops-linux-published-upgrade.yml separately on Ubuntu 22.04/24.04.
 * Install actual public v0.17.2 asset 612562598, tokentimer-agent-0.17.2.tgz, 410054
 * bytes, SHA256 c602fe36825c74d423c2c9b89680df3b1ac76542f71804de14dc5e2ec5aa85bf;
 * validate official release metadata/checksum/archive version/runtime. Reject links,
 * special/duplicate/unsafe members before owned extraction. Build candidate with real
 * pack-release.js/required Go Windows payload; version must be later, never inject
 * candidate runtime into historical package. This is hash provenance, not code signing.
 * Compare every regular extracted/installed package filename, size, digest before/after;
 * only installer root node_modules exclusion is permitted. Historical real signed noop
 * must complete; upgrade preserves exact config/credential/private modes/API
 * registration, job/evidence history and still-valid historical replay-cache entry.
 * Remove bootstrap then fresh restart/authenticated heartbeat must execute candidate
 * noop without consuming spare token. Fail expired replay window rather than fake it.
 * Restore only owned config, revoke spare token, never delete unexpected bootstrap.
 * Upload linux-systemd-published-upgrade.json only; receipt-bound teardown always runs.
 * No certificate custody/renewal, schema-upgrade or automatic version-rollback claim.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/* Install/execute an immutable public Linux predecessor, then upgrade the owned
 * service with the candidate's real release archive. Production job creation and
 * actual agent HTTP claim/results supply history; config/credentials never enter
 * reports. Requires the parent disposable-host ownership/teardown contract.
 */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {createHostGate}=require("../../../packages/agent/scripts/host-gate");
const {baseline,laterVersion,verifyTree}=require("../../../scripts/certops-linux-published-package");
const SCENARIOS=["linux-published-baseline-executes-job","linux-published-upgrade-preserves-state","linux-published-upgrade-reuses-authority","linux-published-upgrade-preserves-job-history","linux-published-upgrade-owned-restoration"];
const sha=file=>crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
function verifyProof(value){assert.equal(value.baselineVersion,baseline.version);assert.equal(value.publishedAssetId,baseline.assetId);assert.equal(value.publishedArchiveSha256,baseline.sha256);assert.equal(value.publishedArchiveSize,baseline.size);laterVersion(value.candidateVersion);assert.equal(value.candidateVersion,require("../../../packages/agent/package.json").version,"Upgrade evidence must describe the checked-out candidate package");assert.match(value.candidateArchiveSha256,/^[a-f0-9]{64}$/);for(const field of ["publishedFilesVerified","baselineJobExecuted","candidateFilesVerified","configBytesPreserved","credentialBytesPreserved","sameRegistration","bootstrapUnconsumed","freshHeartbeat","candidateJobExecuted","oldJobHistoryUnchanged","oldReplayEntryPreserved","privatePermissionsPreserved","originalConfigRestored"])assert.equal(value[field],true,field);assert.ok(Number.isInteger(value.beforePid)&&value.beforePid>1);assert.ok(Number.isInteger(value.afterPid)&&value.afterPid>1);assert.notEqual(value.beforePid,value.afterPid);assert.equal(value.rollbackClaimed,false);return true;}
function assertReplayWindow(entry,minimumRemainingMs=0,nowMs=Date.now()){
 assert.ok(entry&&Number.isFinite(entry.expiresAtMs),"Persisted replay entry requires finite numeric expiresAtMs");
 assert.ok(Number.isFinite(nowMs)&&Number.isFinite(minimumRemainingMs)&&minimumRemainingMs>=0);
 assert.ok(entry.expiresAtMs>nowMs+minimumRemainingMs,"Actual signed replay window must cover the bounded upgrade");return true;
}
async function qualifyPublishedUpgrade(context){
 const {published,pool,workspaceId,userId,agentId,baseUrl,repoRoot,nodeBinary,writeFixture,command,waitFor,mainPid,identity,lastSeen,createBootstrap,uid,gid}=context;
 assert.equal(process.platform,"linux");assert.equal(process.getuid(),0);require("../../../scripts/certops-linux-systemd-ownership").validateHostedEnvironment(process.env);
 const state="/opt/tokentimer-agent/state",configFile=path.join(state,"config.json"),credential=path.join(state,"credential"),replayFile=path.join(state,"replay-store.json"),unit="tokentimer-agent.service";
 const source="tests/e2e/helpers/linux-systemd-published-upgrade.js";
 const gate=createHostGate({suite:"linux-systemd-published-upgrade",strict:true,evidenceLevel:"real-host",reportPath:path.join(repoRoot,"qualification-results/linux-systemd-published-upgrade.json"),fixtureSource:{file:source,sha256:sha(__filename)},requiredCapabilities:["linux","systemd","publishedArchive","candidateArchive"],probeCapabilities:()=>({linux:{available:process.platform==="linux"},systemd:{available:mainPid()>0},publishedArchive:{available:published.baseline.archiveSha256===baseline.sha256},candidateArchive:{available:published.candidate.version===require("../../../packages/agent/package.json").version}})});
 gate.report.fixtureSources=["scripts/certops-linux-published-package.js","tests/e2e/linux-systemd-real-journey.js","packages/agent/scripts/install-agent.sh","packages/agent/scripts/pack-release.js"].map(file=>({file,sha256:sha(path.join(repoRoot,file))}));
 gate.report.executionScope="Immutable public v0.17.2 archive to checked-out candidate release archive on actual installed Linux service; production-service-created noop jobs exercise actual HTTP dispatch/results, not certificate mutation or automatic rollback";
 const original=fs.readFileSync(configFile),credentialHash=sha(credential);let changed=false,ready=false,primary,spare,operatorHash,oldJob,history,replayEntry,beforePid,afterPid,proof;
 const registrations=async()=>(await pool.query("SELECT id,agent_id,credential_prefix,created_at FROM certops_agents WHERE workspace_id=$1 ORDER BY id",[workspaceId])).rows;
 const originalRows=await registrations();const own=originalRows.find(row=>row.agent_id===agentId);assert.ok(own);
 const installedMatches=artifact=>verifyTree("/opt/tokentimer-agent/app",artifact.fileInventory,{installed:true});
 const readJob=async id=>(await pool.query("SELECT to_jsonb(j) AS row FROM certificate_jobs j WHERE workspace_id=$1 AND id=$2",[workspaceId,id])).rows[0]?.row;
 const jobHistory=async id=>({job:await readJob(id),evidence:(await pool.query("SELECT * FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 ORDER BY id",[workspaceId,id])).rows});
 const executeNoop=async()=>{const job=await require("../../../apps/api/services/certops/jobs").createCertificateJob({client:pool,workspaceId,operation:"noop",mode:"real",requestedByUserId:userId,assignedAgentId:own.id,idempotencyKey:`published-upgrade-${crypto.randomUUID()}`});await waitFor(async()=>(await readJob(job.id))?.status==="succeeded","installed release agent executes actual signed noop",60000);const result=await readJob(job.id);assert.equal(result.claimed_by_agent_id,own.id);assert.equal(result.attempt_count,1);assert.ok((await pool.query("SELECT 1 FROM certificate_evidence WHERE workspace_id=$1 AND job_id=$2 AND evidence_type='validation.passed'",[workspaceId,job.id])).rows.length);return job.id;};
 try{
  await gate.preflight();ready=true;
  await gate.scenario(SCENARIOS[0],async()=>{
   installedMatches(published.baseline);assert.equal(JSON.parse(fs.readFileSync("/opt/tokentimer-agent/app/package.json")).version,baseline.version);beforePid=identity();
   command("systemctl",["stop",unit]);assert.equal(mainPid(),0);const config=JSON.parse(original);config.pollIntervalMs=1000;config.heartbeatIntervalMs=3000;config.execution={...config.execution,enabled:true,dryRun:false};fs.writeFileSync(configFile,JSON.stringify(config,null,2)+"\n",{mode:0o600});changed=true;operatorHash=sha(configFile);command("systemctl",["start",unit]);await waitFor(()=>mainPid()>0,"published package service starts enabled fixture policy");identity();
   oldJob=await executeNoop();beforePid=identity();history=await jobHistory(oldJob);assert.ok(fs.existsSync(replayFile));replayEntry=JSON.parse(fs.readFileSync(replayFile,"utf8")).entries.find(entry=>entry.jobId===oldJob);assert.ok(replayEntry);assertReplayWindow(replayEntry,180000);assert.equal(sha(credential),credentialHash);
  });
  await gate.scenario(SCENARIOS[1],async()=>{
   command("systemctl",["stop",unit]);assert.equal(mainPid(),0);spare=await createBootstrap();
   command("sh",[path.join(published.candidate.directory,"scripts/install-agent.sh"),"--api-url",baseUrl,"--workspace-id",workspaceId,"--allow-insecure-local-http","--no-trust-store","--write-path",writeFixture.allowed],{env:{...process.env,PATH:`${path.dirname(nodeBinary)}:/usr/sbin:/usr/bin:/sbin:/bin`,TOKENTIMER_AGENT_BOOTSTRAP_TOKEN:spare.plaintextToken}});
   await waitFor(()=>mainPid()>0&&!fs.existsSync(path.join(state,"bootstrap.env")),"candidate package activates and scrubs spare bootstrap");afterPid=identity(false);assert.notEqual(afterPid,beforePid);installedMatches(published.candidate);
   assert.equal(JSON.parse(fs.readFileSync("/opt/tokentimer-agent/app/package.json")).version,published.candidate.version);assert.equal(sha(configFile),operatorHash);assert.equal(sha(credential),credentialHash);
   for(const [file,mode]of[[state,0o700],[configFile,0o600],[credential,0o600]]){const info=fs.statSync(file);assert.equal(info.uid,uid);assert.equal(info.gid,gid);assert.equal(info.mode&0o777,mode);}
  });
  await gate.scenario(SCENARIOS[2],async()=>{
   const seen=await lastSeen(),pid=mainPid();command("systemctl",["restart",unit]);await waitFor(()=>mainPid()>0&&mainPid()!==pid,"candidate restart without bootstrap environment");identity();await waitFor(async()=>Date.parse(await lastSeen())>Date.parse(seen),"candidate authenticates with preserved credential");assert.deepEqual(await registrations(),originalRows);
   const unused=(await pool.query("SELECT status,used_at,used_by_agent_id FROM certops_agent_bootstrap_tokens WHERE workspace_id=$1 AND id=$2",[workspaceId,spare.token.id])).rows[0];assert.equal(unused.status,"active");assert.equal(unused.used_at,null);assert.equal(unused.used_by_agent_id,null);
  });
  await gate.scenario(SCENARIOS[3],async()=>{
   const newJob=await executeNoop();assert.notEqual(newJob,oldJob);assert.deepEqual(await jobHistory(oldJob),history);assertReplayWindow(replayEntry);assert.deepEqual(JSON.parse(fs.readFileSync(replayFile,"utf8")).entries.find(entry=>entry.jobId===oldJob),replayEntry);assert.equal(sha(credential),credentialHash);assert.equal(sha(configFile),operatorHash);
   proof={baselineVersion:baseline.version,publishedAssetId:baseline.assetId,publishedArchiveSha256:baseline.sha256,publishedArchiveSize:baseline.size,candidateVersion:published.candidate.version,candidateArchiveSha256:published.candidate.archiveSha256,publishedFilesVerified:true,baselineJobExecuted:true,candidateFilesVerified:true,configBytesPreserved:true,credentialBytesPreserved:true,sameRegistration:true,bootstrapUnconsumed:true,freshHeartbeat:true,candidateJobExecuted:true,oldJobHistoryUnchanged:true,oldReplayEntryPreserved:true,privatePermissionsPreserved:true,beforePid,afterPid,rollbackClaimed:false};
  });
 }catch(error){primary=error;}
 finally{
  const cleanup=async()=>{const errors=[];if(changed){try{command("systemctl",["stop",unit]);assert.equal(mainPid(),0);const file=path.join(state,"bootstrap.env");if(fs.existsSync(file)){assert.ok(spare&&fs.readFileSync(file).equals(Buffer.from(`TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=${spare.plaintextToken}\n`)),"Refuse unrecognized bootstrap cleanup");fs.unlinkSync(file);}fs.writeFileSync(configFile,original,{mode:0o600});assert.deepEqual(fs.readFileSync(configFile),original);}catch(error){errors.push(error);}try{command("systemctl",["start",unit]);await waitFor(()=>mainPid()>0,"restore original service configuration");identity();}catch(error){errors.push(error);}}if(spare){try{await pool.query("UPDATE certops_agent_bootstrap_tokens SET status='revoked',revoked_at=NOW() WHERE workspace_id=$1 AND id=$2 AND status='active'",[workspaceId,spare.token.id]);}catch(error){errors.push(error);}}if(errors.length)throw new AggregateError(errors,"Published upgrade owned restoration failed");if(proof){proof.originalConfigRestored=true;verifyProof(proof);gate.report.nativePublishedLinuxUpgrade=proof;}};
  try{if(ready){await gate.scenario(SCENARIOS[4],cleanup);await gate.finish({requiredScenarios:SCENARIOS});}else await cleanup();}catch(error){if(primary)throw new AggregateError([primary,error],"Published upgrade and restoration failed");throw error;}
 }
 if(primary)throw primary;
}
module.exports={SCENARIOS,qualifyPublishedUpgrade,verifyProof,assertReplayWindow};
