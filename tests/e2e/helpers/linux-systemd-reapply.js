/**
 * Qualification: same-candidate installed reapplication
 *
 * Run three linux-systemd-reapply cases inside owned Ubuntu 22.04/24.04 journey after
 * crash recovery, before retirement. Stop service, set supported operator
 * poll/heartbeat/ execution settings, capture exact config/credential/runtime-drop-in,
 * then rerun same candidate installer with existing write-path and fresh spare bootstrap
 * token. Installed package must match candidate; config/credential/drop-in/private
 * modes/ effective write paths stay exact, no staging/previous tree remains. Fresh
 * service scrubs spare bootstrap without replacing/creating registration. After SECOND
 * real restart inspect native environment for no bootstrap, advance authenticated
 * heartbeat, and prove spare token still unconsumed in Postgres. Restore original
 * config/restart and revoke only unused token; never remove unexpected bootstrap. Parent
 * independent receipt-bound teardown survives failure. Keep the 10-minute test inside 12
 * minutes producer, 25 minutes workflow. Public booleans/PIDs/source hashes only. No
 * historical package upgrade, rollback or ARM64 qualification is implied by candidate
 * reapplication.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";
/* Native same-candidate installer reapplication inside the already owned Linux
 * systemd journey. Requires a disposable hosted VM, existing registration and
 * exact state/unit paths. It does not claim a released-version upgrade. All
 * private state stays on the VM; reports contain source hashes and public facts.
 */
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { createHostGate } = require("../../../packages/agent/scripts/host-gate");
const SCENARIOS = ["linux-systemd-reapply-preserves-operator-state", "linux-systemd-reapply-reuses-registration", "linux-systemd-reapply-owned-cleanup"];
function digest(file) { return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"); }
function verifyProof(value) {
  assert.equal(value.installation,"same-candidate-reapplication");
  for (const field of ["operatorConfigBytesPreserved","credentialBytesPreserved","candidatePackageInstalled","dropinPreserved","privatePermissionsPreserved","sameRegistration","spareBootstrapUnconsumed","bootstrapFileAbsent","bootstrapAbsentAfterFreshRestart","freshAuthenticatedHeartbeat","originalConfigRestored"]) assert.equal(value[field],true,field);
  for (const key of ["beforePid","reappliedPid","freshRestartPid"]) assert.ok(Number.isInteger(value[key])&&value[key]>1,key);
  assert.equal(new Set([value.beforePid,value.reappliedPid,value.freshRestartPid]).size,3);
  assert.ok(Number.isInteger(value.nativeUid)&&value.nativeUid>0);return true;
}
async function qualifyReapply(context) {
  const {pool,workspaceId,agentId,baseUrl,repoRoot,installer,nodeBinary,writeFixture,command,waitFor,mainPid,serviceProperty,identity,lastSeen,createBootstrap,uid,gid}=context;
  assert.equal(process.platform,"linux");assert.equal(process.getuid(),0);
  require("../../../scripts/certops-linux-systemd-ownership").validateHostedEnvironment(process.env);
  const state="/opt/tokentimer-agent/state",configFile=path.join(state,"config.json"),credential=path.join(state,"credential"),dropin="/etc/systemd/system/tokentimer-agent.service.d/99-qualification.conf";
  require("../../../scripts/certops-linux-systemd-ownership").assertNoSymlinkTargets([state,configFile,credential,dropin,writeFixture.root]);
  const source="tests/e2e/helpers/linux-systemd-reapply.js";
  const gate=createHostGate({suite:"linux-systemd-reapply",strict:true,evidenceLevel:"real-host",reportPath:path.join(repoRoot,"qualification-results/linux-systemd-reapply.json"),fixtureSource:{file:source,sha256:digest(__filename)},requiredCapabilities:["linux","systemd"],probeCapabilities:()=>({linux:{available:process.platform==="linux"},systemd:{available:mainPid()>0&&serviceProperty("LoadState")==="loaded"}})});
  gate.report.executionScope="Actual same-candidate installer rerun over existing supported operator settings and registration; not a cross-version or released-package upgrade";
  gate.report.fixtureSources=["packages/agent/scripts/install-agent.sh","tests/e2e/linux-systemd-real-journey.js"].map(file=>({file,sha256:digest(path.join(repoRoot,file))}));
  assert.equal(fs.existsSync(path.join(state,"bootstrap.env")),false,"Initial registration must have removed bootstrap material");
  const original=fs.readFileSync(configFile),credentialHash=digest(credential),dropinHash=digest(dropin),beforePid=identity();
  const registrations=async()=>(await pool.query("SELECT id,agent_id,credential_prefix,created_at FROM certops_agents WHERE workspace_id=$1 ORDER BY id",[workspaceId])).rows;
  const beforeRows=await registrations();assert.ok(beforeRows.some(row=>row.agent_id===agentId));
  let operatorConfigHash,reappliedPid,freshRestartPid,spare,proof,primary,ready=false,changed=false;
  try {
    await gate.preflight();ready=true;
    await gate.scenario(SCENARIOS[0],async()=>{
      command("systemctl",["stop","tokentimer-agent.service"]);assert.equal(mainPid(),0);
      const operator=JSON.parse(original);operator.pollIntervalMs=1000;operator.heartbeatIntervalMs=3000;
      operator.execution={...operator.execution,enabled:false,dryRun:true};
      fs.writeFileSync(configFile,JSON.stringify(operator,null,2)+"\n",{mode:0o600});changed=true;operatorConfigHash=digest(configFile);
      spare=await createBootstrap();
      command("sh",[installer,"--api-url",baseUrl,"--workspace-id",workspaceId,"--allow-insecure-local-http","--no-trust-store","--write-path",writeFixture.allowed],{env:{...process.env,PATH:`${path.dirname(nodeBinary)}:/usr/sbin:/usr/bin:/sbin:/bin`,TOKENTIMER_AGENT_BOOTSTRAP_TOKEN:spare.plaintextToken}});
      await waitFor(()=>mainPid()>0&&mainPid()!==beforePid&&!fs.existsSync(path.join(state,"bootstrap.env")),"same-candidate installer starts a fresh registered process");
      reappliedPid=identity(false);assert.equal(digest(configFile),operatorConfigHash);assert.equal(digest(credential),credentialHash);assert.equal(digest(dropin),dropinHash);
      for(const relative of ["package.json","bin/tokentimer-agent.js","src/index.js","src/config/index.js"])assert.equal(digest(path.join("/opt/tokentimer-agent/app",relative)),digest(path.join(repoRoot,"packages/agent",relative)),"Installed candidate file mismatch");
      for(const [file,mode] of [[state,0o700],[configFile,0o600],[credential,0o600]]){const stat=fs.statSync(file);assert.equal(stat.uid,uid);assert.equal(stat.gid,gid);assert.equal(stat.mode&0o777,mode);}
      const writable=serviceProperty("ReadWritePaths").split(/\s+/);assert.ok(writable.includes(writeFixture.allowed));assert.equal(writable.includes(writeFixture.denied),false);
      assert.equal(fs.readdirSync("/opt/tokentimer-agent").some(name=>/^app\.(staging|previous)\./.test(name)),false);
    });
    await gate.scenario(SCENARIOS[1],async()=>{
      const seen=await lastSeen();command("systemctl",["restart","tokentimer-agent.service"]);
      await waitFor(()=>mainPid()>0&&mainPid()!==reappliedPid,"restart after spare bootstrap removal");freshRestartPid=identity();
      await waitFor(async()=>Date.parse(await lastSeen())>Date.parse(seen),"same registered identity authenticates after reapplication");
      assert.deepEqual(await registrations(),beforeRows,"Installer rerun must not create or replace a registration");
      const token=(await pool.query("SELECT status,used_at,used_by_agent_id FROM certops_agent_bootstrap_tokens WHERE workspace_id=$1 AND id=$2",[workspaceId,spare.token.id])).rows[0];assert.ok(token);assert.equal(token.status,"active");assert.equal(token.used_at,null);assert.equal(token.used_by_agent_id,null);
      assert.equal(digest(credential),credentialHash);assert.equal(digest(configFile),operatorConfigHash);
      proof={installation:"same-candidate-reapplication",operatorConfigBytesPreserved:true,credentialBytesPreserved:true,candidatePackageInstalled:true,dropinPreserved:true,privatePermissionsPreserved:true,sameRegistration:true,spareBootstrapUnconsumed:true,bootstrapFileAbsent:!fs.existsSync(path.join(state,"bootstrap.env")),bootstrapAbsentAfterFreshRestart:true,freshAuthenticatedHeartbeat:true,beforePid,reappliedPid,freshRestartPid,nativeUid:uid};
    });
  } catch(error){primary=error;}
  finally {
    const cleanup=async()=>{
      const errors=[];
      if(changed){
        try{command("systemctl",["stop","tokentimer-agent.service"]);assert.equal(mainPid(),0);const bootstrap=path.join(state,"bootstrap.env");if(fs.existsSync(bootstrap)){assert.ok(spare&&fs.readFileSync(bootstrap).equals(Buffer.from(`TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=${spare.plaintextToken}\n`)),"Refuse cleanup of unrecognized bootstrap file");fs.unlinkSync(bootstrap);}fs.writeFileSync(configFile,original,{mode:0o600});assert.deepEqual(fs.readFileSync(configFile),original);}catch(error){errors.push(error);}
        try{command("systemctl",["start","tokentimer-agent.service"]);await waitFor(()=>mainPid()>0,"restore original owned service configuration");identity();}catch(error){errors.push(error);}
      }
      if(spare){try{await pool.query("UPDATE certops_agent_bootstrap_tokens SET status='revoked',revoked_at=NOW() WHERE workspace_id=$1 AND id=$2 AND status='active'",[workspaceId,spare.token.id]);}catch(error){errors.push(error);}}
      if(errors.length)throw new AggregateError(errors,"Same-candidate reapply configuration restoration failed");
      if(proof){proof.originalConfigRestored=true;verifyProof(proof);gate.report.nativeInstallerReapply=proof;}
    };
    try{if(ready){await gate.scenario(SCENARIOS[2],cleanup);await gate.finish({requiredScenarios:SCENARIOS});}else await cleanup();}
    catch(error){if(primary)throw new AggregateError([primary,error],"Installer reapply and owned restoration failed");throw error;}
  }
  if(primary)throw primary;
}
module.exports={qualifyReapply,verifyProof,SCENARIOS};
