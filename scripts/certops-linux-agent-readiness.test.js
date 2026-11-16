"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {waitForAgentIdentity,identifyAgentProcess,assertExpectedAgentUid,assertAgentThreadUids}=require("../tests/e2e/helpers/linux-systemd-agent-readiness");
const fs=require("node:fs"),os=require("node:os"),path=require("node:path");
function procFixture(t){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),"ttqual-threads-"));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const task=path.join(root,"42","task");fs.mkdirSync(task,{recursive:true});
  const add=(tid,uid,birth="123")=>{const dir=path.join(task,String(tid));fs.mkdirSync(dir,{recursive:true});fs.writeFileSync(path.join(dir,"status"),`Name:\tworker\nTgid:\t42\nPid:\t${tid}\nUid:\t${uid}\t${uid}\t${uid}\t${uid}\n`);fs.writeFileSync(path.join(dir,"stat"),`${tid} (thread) S ${Array(18).fill("0").join(" ")} ${birth} 0\n`);};
  add(42,1000);add(43,1000);return {root,task,add};
}
test("checks four UIDs on every stable thread, not just the leader",t=>{
  const {root,add}=procFixture(t);assert.doesNotThrow(()=>assertAgentThreadUids(42,1000,{procRoot:root}));
  add(43,0);assert.throws(()=>assertAgentThreadUids(42,1000,{procRoot:root}),/UID/);
  add(43,1000);fs.writeFileSync(path.join(root,"42","task","43","status"),"Tgid:\t42\nPid:\t43\nUid:\t1000\t1000\t0\t1000\n");
  assert.throws(()=>assertAgentThreadUids(42,1000,{procRoot:root}),/UID/);
});
test("refuses thread appearance or disappearance during inventory",t=>{
  const {root,add}=procFixture(t);let scans=0;
  const api={...fs,readdirSync(...args){const result=fs.readdirSync(...args);if(++scans===1)add(44,1000);return result;}};
  assert.throws(()=>assertAgentThreadUids(42,1000,{procRoot:root,fsApi:api}),/inventory changed/);
  scans=0;const missing={...fs,readdirSync(...args){const result=fs.readdirSync(...args);return ++scans===2?result.filter(tid=>tid!=="43"):result;}};
  assert.throws(()=>assertAgentThreadUids(42,1000,{procRoot:root,fsApi:missing}),/inventory changed/);
});
test("refuses a reused thread ID or unreadable task status",t=>{
  const {root,add}=procFixture(t);let reads=0;
  const api={...fs,readFileSync(file,...args){const result=fs.readFileSync(file,...args);if(String(file).endsWith(`${path.sep}43${path.sep}stat`)&&++reads===1)add(43,1000,"124");return result;}};
  assert.throws(()=>assertAgentThreadUids(42,1000,{procRoot:root,fsApi:api}),/thread changed/);
  fs.rmSync(path.join(root,"42","task","43","status"));assert.throws(()=>assertAgentThreadUids(42,1000,{procRoot:root}));
});
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
test("an observed agent script with unexpected leading arguments fails closed",()=>{
  const input={pid:42,birth:"100",exe:"/node",args:Buffer.from("/node\0--inspect\0/agent.js\0"),nodeBinary:"/node",agentScript:"/agent.js"};
  assert.throws(()=>identifyAgentProcess(input),/unexpected arguments/);
  assert.throws(()=>identifyAgentProcess({...input,args:Buffer.from("/agent.js\0")}),/unexpected command/);
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
