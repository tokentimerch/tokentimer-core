"use strict";
const assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path");
function assertExpectedAgentUid(status,uid){
  assert.ok(Number.isSafeInteger(uid)&&uid>0,"Expected service account UID must be nonroot");
  assert.match(status,new RegExp(`^Uid:\\s+${uid}\\s+${uid}\\s+${uid}\\s+${uid}$`,"m"));
}
// This samples existing threads; it cannot prove the absence of a short-lived
// thread or credential change between reads.
function assertAgentThreadUids(pid,uid,{procRoot="/proc",fsApi=fs}={}){
  assert.ok(Number.isSafeInteger(pid)&&pid>1,"Agent PID unavailable");
  assert.ok(Number.isSafeInteger(uid)&&uid>0,"Expected service account UID must be nonroot");
  const task=path.join(procRoot,String(pid),"task");
  const inventory=()=>{
    let entries;try{entries=fsApi.readdirSync(task);}catch{throw Error("Agent thread inventory unavailable");}
    assert.ok(entries.length>0&&entries.every(tid=>/^[1-9]\d*$/.test(tid)&&Number.isSafeInteger(Number(tid))),"Agent thread inventory invalid");
    assert.ok(new Set(entries).size===entries.length&&entries.includes(String(pid)),"Agent thread inventory invalid");
    return entries.sort((a,b)=>Number(a)-Number(b));
  };
  const read=(tid,name)=>{try{return fsApi.readFileSync(path.join(task,tid,name),"utf8");}catch{throw Error("Agent thread observation unavailable");}};
  const birth=tid=>{
    const raw=read(tid,"stat"),end=raw.lastIndexOf(")");
    assert.ok(raw.startsWith(`${tid} (`)&&end>=0,"Agent thread identity unavailable");
    const fields=raw.slice(end+1).trim().split(/\s+/),value=fields[19];
    assert.ok(/^\d+$/.test(value||""),"Agent thread identity unavailable");return value;
  };
  const first=inventory(),births=new Map();
  for(const tid of first){
    const before=birth(tid),status=read(tid,"status");
    assert.ok(new RegExp(`^Tgid:\\s+${pid}\\s*$`,"m").test(status)&&new RegExp(`^Pid:\\s+${tid}\\s*$`,"m").test(status),"Agent thread identity mismatch");
    try{assertExpectedAgentUid(status,uid);}catch{throw Error("Agent thread UID mismatch");}
    assert.equal(birth(tid),before,"Agent thread changed during observation");births.set(tid,before);
  }
  const unchanged=()=>assert.ok(inventory().join(",")===first.join(","),"Agent thread inventory changed");
  unchanged();for(const tid of first)assert.equal(birth(tid),births.get(tid),"Agent thread changed during observation");unchanged();
}
function identifyAgentProcess({pid,birth,exe,args,nodeBinary,agentScript}){
  assert.ok(Number.isSafeInteger(pid)&&pid>1);
  assert.ok(/^\d+$/.test(birth||""),"Agent process birth unavailable");
  assert.ok(Buffer.isBuffer(args)&&args.length<=16384,"Agent command observation unavailable");
  if(args.length===0)return {pid,birth,identified:false};
  assert.equal(args[args.length-1],0,"Agent command observation truncated");
  const parts=args.toString("utf8").split("\0");
  if(parts.at(-1)==="")parts.pop();
  if(!parts.includes(agentScript))return {pid,birth,identified:false};
  assert.equal(exe,nodeBinary,"Confirmed agent has unexpected executable");
  assert.equal(parts[0],nodeBinary,"Confirmed agent has unexpected command");
  assert.ok(parts.length===2&&parts[1]===agentScript,"Confirmed agent has unexpected arguments");
  return {pid,birth,identified:true};
}
// An observation is produced only after exe and argv identify the actual agent.
// No raw process data is retained by this function.
async function waitForAgentIdentity({observe,verify,previousPid=0,timeoutMs=70000,sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms))}) {
  assert.ok(Number.isInteger(timeoutMs)&&timeoutMs>0);
  const deadline=Date.now()+timeoutMs;
  let anchor;
  while(Date.now()<deadline){
    const first=observe();
    if(anchor&&(!first||first.pid<=1||first.pid===previousPid))throw Error("Agent process disappeared before identification");
    if(first && first.pid>0 && first.pid!==previousPid){
      assert.ok(/^\d+$/.test(first.birth||""),"Agent process birth unavailable");
      if(!anchor)anchor={pid:first.pid,birth:first.birth};
      else assert.ok(first.pid===anchor.pid&&first.birth===anchor.birth,"Agent process changed before identification");
      if(!first.identified){await sleep(50);continue;}
      await verify(first); // Never retry a verified agent with incorrect credentials.
      const last=observe();
      assert.ok(last&&last.identified&&last.pid===first.pid&&last.birth===first.birth,"Agent process changed during identity verification");
      return {pid:first.pid,birth:first.birth};
    }
    await sleep(50);
  }
  throw Error("Timed out waiting for the exact agent process");
}
module.exports={waitForAgentIdentity,identifyAgentProcess,assertExpectedAgentUid,assertAgentThreadUids};
