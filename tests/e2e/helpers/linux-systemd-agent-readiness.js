"use strict";
const assert=require("node:assert/strict");
function assertExpectedAgentUid(status,uid){
  assert.ok(Number.isSafeInteger(uid)&&uid>0,"Expected service account UID must be nonroot");
  assert.match(status,new RegExp(`^Uid:\\s+${uid}\\s+${uid}\\s+${uid}\\s+${uid}$`,"m"));
}
function identifyAgentProcess({pid,birth,exe,args,nodeBinary,agentScript}){
  assert.ok(Number.isSafeInteger(pid)&&pid>1);
  assert.ok(/^\d+$/.test(birth||""),"Agent process birth unavailable");
  assert.ok(Buffer.isBuffer(args)&&args.length<=16384,"Agent command observation unavailable");
  if(args.length===0)return {pid,birth,identified:false};
  assert.equal(args[args.length-1],0,"Agent command observation truncated");
  const parts=args.toString("utf8").split("\0");
  if(parts.at(-1)==="")parts.pop();
  if(parts[1]!==agentScript)return {pid,birth,identified:false};
  assert.equal(exe,nodeBinary,"Confirmed agent has unexpected executable");
  assert.equal(parts[0],nodeBinary,"Confirmed agent has unexpected command");
  assert.equal(parts.length,2,"Confirmed agent has unexpected arguments");
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
module.exports={waitForAgentIdentity,identifyAgentProcess,assertExpectedAgentUid};
