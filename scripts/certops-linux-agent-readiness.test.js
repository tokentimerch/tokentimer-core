"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {waitForAgentIdentity,identifyAgentProcess,assertExpectedAgentUid}=require("../tests/e2e/helpers/linux-systemd-agent-readiness");
test("waits for the exact agent after a transient helper, then validates it once",async()=>{
  const samples=[{pid:42,birth:"100",identified:false},{pid:42,birth:"100",identified:true},{pid:42,birth:"100",identified:true}], checked=[];
  const result=await waitForAgentIdentity({observe:()=>samples.shift(),verify:s=>checked.push(s.pid),previousPid:11,timeoutMs:1000,sleep:async()=>{}});
  assert.deepEqual(result,{pid:42,birth:"100"});assert.deepEqual(checked,[42]);
});
test("a confirmed root agent fails immediately without another observation",async()=>{
  let observations=0;
  await assert.rejects(waitForAgentIdentity({observe:()=>{observations++;return {pid:42,birth:"100",identified:true};},verify:()=>assertExpectedAgentUid(observations===1?"Uid:\t0\t0\t0\t0":"Uid:\t1000\t1000\t1000\t1000",1000),timeoutMs:1000,sleep:async()=>{}}));
  assert.equal(observations,1);
});
test("replacement during UID verification is refused",async()=>{
  const samples=[{pid:42,birth:"100",identified:true},{pid:42,birth:"101",identified:true}];
  await assert.rejects(waitForAgentIdentity({observe:()=>samples.shift(),verify:()=>{},timeoutMs:1000,sleep:async()=>{}}),/process changed/);
});
test("command changing during UID verification is refused even with the same PID and birth",async()=>{
  const samples=[{pid:42,birth:"100",identified:true},{pid:42,birth:"100",identified:false}];
  await assert.rejects(waitForAgentIdentity({observe:()=>samples.shift(),verify:()=>{},timeoutMs:1000,sleep:async()=>{}}),/process changed/);
});
test("missing exact agent times out closed",async()=>{
  await assert.rejects(waitForAgentIdentity({observe:()=>null,verify:()=>{throw Error("must not verify");},timeoutMs:5,sleep:()=>new Promise(r=>setTimeout(r,1))}),/Timed out/);
});
test("exact executable and script identify the agent without returning argv",()=>{
  const input={pid:42,birth:"100",exe:"/node",args:Buffer.from("/node\0/agent.js\0"),nodeBinary:"/node",agentScript:"/agent.js"};
  assert.deepEqual(identifyAgentProcess(input),{pid:42,birth:"100",identified:true});
  assert.deepEqual(identifyAgentProcess({...input,args:Buffer.from("/node\0/probe.js\0")}),{pid:42,birth:"100",identified:false});
  assert.throws(()=>identifyAgentProcess({...input,exe:"/unexpected"}),/unexpected executable/);
  assert.throws(()=>identifyAgentProcess({...input,args:Buffer.from("/node\0/agent.js")}),/truncated/);
});
test("a changed process before agent identification fails instead of retrying",async()=>{
  const samples=[{pid:42,birth:"100",identified:false},{pid:43,birth:"101",identified:true}];let verified=0;
  await assert.rejects(waitForAgentIdentity({observe:()=>samples.shift(),verify:()=>{verified++;},timeoutMs:1000,sleep:async()=>{}}),/changed before identification/);
  assert.equal(verified,0);
});
test("a process that disappears before identification fails closed",async()=>{
  const samples=[{pid:42,birth:"100",identified:false},null];
  await assert.rejects(waitForAgentIdentity({observe:()=>samples.shift(),verify:()=>{},timeoutMs:1000,sleep:async()=>{}}),/disappeared before identification/);
});
