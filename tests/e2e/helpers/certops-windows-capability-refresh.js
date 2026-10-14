"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),os=require("node:os");
const {spawn}=require("node:child_process");
async function qualifyWindowsCapabilityRefresh({pool,workspaceId,agentId,state,packageRoot}){
  assert.equal(process.platform,"win32");assert.equal(path.basename(state),"fresh-registration-state");const relative=path.relative(os.tmpdir(),state);assert.ok(relative&&!relative.startsWith("..")&&!path.isAbsolute(relative),"Only the owned temporary registration fixture can refresh declarations");
  const platform=require(path.join(packageRoot,"src/platform"));const file=path.join(state,"config.json"),original=fs.readFileSync(file);const initial=JSON.parse(original);assert.equal(initial.agentId,agentId);assert.equal(initial.execution.enabled,false);
  const credential=fs.readFileSync(path.join(state,"credential"));const pinFile=path.join(state,"signing-key-pin.json");const pin=fs.existsSync(pinFile)?fs.readFileSync(pinFile):null;
  const row=async()=>(await pool.query("SELECT id,credential_hash,declared_command_profile_names,declared_capabilities,supported_operations,last_seen_at,capabilities_updated_at FROM certops_agents WHERE workspace_id=$1 AND agent_id=$2",[workspaceId,agentId])).rows[0];
  const before=await row();assert.ok(before);const jobs=async()=>(await pool.query("SELECT id,status,attempt_count,claim_id FROM certificate_jobs WHERE workspace_id=$1 AND assigned_agent_id=$2 ORDER BY id",[workspaceId,before.id])).rows;const originalJobs=await jobs();let child,primaryError;
  const stop=async()=>{if(!child)return;const owned=child;child=null;if(owned.exitCode!==null||owned.signalCode!==null)return;await new Promise((resolve,reject)=>{let timer=setTimeout(()=>{owned.kill("SIGKILL");timer=setTimeout(()=>reject(new Error("Owned observe-only process did not terminate")),5000);},10000);owned.once("close",()=>{clearTimeout(timer);resolve();});owned.kill("SIGTERM");});};
  try{
    for(const phase of [{profiles:["qualification-heartbeat-only"],stream:"on"},{profiles:[],stream:"off"}]){
      const prior=await row();const config={...initial,declaredCommandProfileNames:phase.profiles,policy:{...(initial.policy||{}),allowedCommands:{"qualification-heartbeat-only":{argv:[process.execPath,"--version"]}}}};
      fs.writeFileSync(file,JSON.stringify(config));platform.applyRestrictivePermissions(file,{kind:"file"});
      child=spawn(process.execPath,[path.join(packageRoot,"bin/tokentimer-agent.js")],{env:{PATH:process.env.PATH,SystemRoot:process.env.SystemRoot,WINDIR:process.env.WINDIR,COMSPEC:process.env.COMSPEC,TEMP:process.env.TEMP,TMP:process.env.TMP,TOKENTIMER_AGENT_CONFIG_DIR:state,TT_AGENT_LOG_STREAM:phase.stream},stdio:"ignore"});const owned=child;let observed;const deadline=Date.now()+45000;
      do{assert.equal(owned.exitCode,null);assert.equal(owned.signalCode,null);observed=await row();if(Date.parse(observed.last_seen_at)>Date.parse(prior.last_seen_at)&&JSON.stringify(observed.declared_command_profile_names)===JSON.stringify(phase.profiles)&&observed.declared_capabilities.includes("job-log-stream-v1")===(phase.stream==="on"))break;await new Promise(resolve=>setTimeout(resolve,100));}while(Date.now()<deadline);
      assert.ok(Date.parse(observed.last_seen_at)>Date.parse(prior.last_seen_at),"Fresh authenticated heartbeat required");assert.ok(Date.parse(observed.capabilities_updated_at)>Date.parse(prior.capabilities_updated_at));assert.deepEqual(observed.declared_command_profile_names,phase.profiles);assert.deepEqual(observed.supported_operations,[]);assert.equal(observed.declared_capabilities.includes("job-log-stream-v1"),phase.stream==="on");assert.equal(observed.id,before.id);assert.ok(observed.credential_hash===before.credential_hash,"Registered credential changed during refresh");
      assert.ok(fs.readFileSync(path.join(state,"credential")).equals(credential));assert.equal(JSON.parse(fs.readFileSync(file)).agentId,agentId);if(pin)assert.ok(fs.readFileSync(pinFile).equals(pin));else assert.equal(fs.existsSync(pinFile),false);
      assert.deepEqual(await jobs(),originalJobs,"Observe-only configuration refresh cannot claim or replay assigned work");await stop();
    }
    return {observeOnlyProfileAddition:true,observeOnlyProfileRemoval:true,logCapabilityWithdrawal:true,stableIdentityCredentialAndPin:true,observeOnlyNoClaims:true};
  }catch(error){primaryError=error;throw error;}
  finally{const errors=[];try{await stop();}catch(error){errors.push(error);}try{fs.writeFileSync(file,original);platform.applyRestrictivePermissions(file,{kind:"file"});}catch(error){errors.push(error);}if(errors.length)throw new AggregateError([...(primaryError?[primaryError]:[]),...errors],"Observe-only declaration refresh finalization failed");}
}
module.exports={qualifyWindowsCapabilityRefresh};
