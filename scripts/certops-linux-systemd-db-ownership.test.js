"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),crypto=require("node:crypto");
const db=require("./certops-linux-systemd-db-ownership"),linuxTest=(name,fn)=>test(name,{skip:process.platform!=="linux" || process.getuid()!==0},fn);
const workspaceId="52d0545a-5844-4e07-8bd1-4524416c970a",agentRowId="d89b4df5-f82a-4db7-a10d-53f45a507181",agentId="candidate-linux-42";
function setup(t,prepare=true){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),"tt-db-marker-"));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const runner=path.join(root,"runner"),guardRoot=path.join(root,"root");fs.mkdirSync(runner,{mode:0o700});fs.mkdirSync(guardRoot,{mode:0o700});
  const opts={guardRoot},receipt={installedDiscoveryNonce:"a".repeat(64)},guard=path.join(guardRoot,"ttqual-db-"+crypto.createHash("sha256").update(fs.realpathSync.native(runner)).digest("hex"));
  if(prepare)db.preparePre(receipt,runner,workspaceId,opts);return {root,runner,guardRoot,opts,receipt,guard};
}
const file=(guard,state)=>path.join(guard,`${state}.json`);
test("non-root-owned guard parent is rejected before marker creation", {skip:process.platform!=="linux"}, t=>{
  const {runner,receipt,opts,guard,guardRoot}=setup(t,false);
  if(process.getuid()===0)fs.chownSync(guardRoot,65534,65534);
  assert.throws(()=>db.preparePre(receipt,runner,workspaceId,opts),/parent not private to root/);
  assert.equal(fs.lstatSync(guard,{throwIfNoEntry:false}),undefined);
});
linuxTest("pre permits cleanup before installation and removal preserves no marker",t=>{
  const {runner,receipt,opts}=setup(t),state=db.assertSafe(receipt,runner,opts);assert.equal(state.state,"pre");db.remove(receipt,runner,state,opts);db.assertNoMarkers(runner,opts);
});
linuxTest("installation blocks fallback until committed result is durably recorded",t=>{
  const {runner,receipt,opts}=setup(t);db.start(receipt,runner,opts);assert.throws(()=>db.assertSafe(receipt,runner,opts),/unresolved/i);
  db.markDone(receipt,runner,{workspaceId,agentRowId,agentId},opts);const state=db.assertSafe(receipt,runner,opts);assert.equal(state.state,"done");db.remove(receipt,runner,state,opts);db.assertNoMarkers(runner,opts);
});
linuxTest("pre replacement is rejected even for byte-identical data",t=>{
  const {runner,receipt,opts,guard}=setup(t),p=file(guard,"pre"),old=fs.readFileSync(p),fd=fs.openSync(p,"r");try{fs.unlinkSync(p);fs.writeFileSync(p,old,{mode:0o600,flag:"wx"});assert.throws(()=>db.assertSafe(receipt,runner,opts));}finally{fs.closeSync(fd);}
});
linuxTest("ambiguous link transition and sync failure remain blocked",t=>{
  const {runner,receipt,opts}=setup(t),original=fs.fsyncSync;fs.fsyncSync=()=>{throw Error("injected sync failure");};
  try{assert.throws(()=>db.start(receipt,runner,opts),/injected/);}finally{fs.fsyncSync=original;}
  assert.throws(()=>db.assertSafe(receipt,runner,opts));assert.throws(()=>db.assertNoMarkers(runner,opts));
});
linuxTest("failed active removal after done creation leaves a blocked mixed state",t=>{
  const {runner,receipt,opts,guard}=setup(t);db.start(receipt,runner,opts);const original=fs.unlinkSync;
  fs.unlinkSync=(name,...args)=>{if(String(name)===file(guard,"active"))throw Error("injected unlink failure");return original(name,...args);};
  try{assert.throws(()=>db.markDone(receipt,runner,{workspaceId,agentRowId,agentId},opts),/injected/);}finally{fs.unlinkSync=original;}
  assert.throws(()=>db.assertSafe(receipt,runner,opts),/Ambiguous/);assert.throws(()=>db.assertNoMarkers(runner,opts));
});
linuxTest("wrong workspace or missing row identity cannot establish done",t=>{
  const {runner,receipt,opts}=setup(t);db.start(receipt,runner,opts);
  assert.throws(()=>db.markDone(receipt,runner,{workspaceId:"e52f78b0-3e4a-4d65-9a8d-4859a9f0c261",agentRowId,agentId},opts));
  assert.throws(()=>db.markDone(receipt,runner,{workspaceId,agentRowId:"invalid",agentId},opts));assert.throws(()=>db.assertSafe(receipt,runner,opts),/unresolved/i);
});
linuxTest("done identity mutation and wrong nonce are rejected before fallback accepts",t=>{
  const {runner,receipt,opts,guard}=setup(t);db.start(receipt,runner,opts);db.markDone(receipt,runner,{workspaceId,agentRowId,agentId},opts);
  assert.throws(()=>db.assertSafe({...receipt,installedDiscoveryNonce:"b".repeat(64)},runner,opts));
  const d=file(guard,"done"),value=JSON.parse(fs.readFileSync(d,"utf8"));value.agentId="foreign";fs.writeFileSync(d,JSON.stringify(value));
  assert.throws(()=>db.assertSafe(receipt,runner,opts),/authentication/);
});
linuxTest("snapshot deletion rejects in-place replacement, bad mode and missing marker",t=>{
  const {runner,receipt,opts,guard}=setup(t),state=db.assertSafe(receipt,runner,opts),p=file(guard,"pre");
  fs.writeFileSync(p,fs.readFileSync(p).toString().replace('"ownerPid":','"ownerPid":1'));assert.throws(()=>db.remove(receipt,runner,state,opts));
  fs.chmodSync(p,0o644);assert.throws(()=>db.assertSafe(receipt,runner,opts));fs.unlinkSync(p);assert.throws(()=>db.assertSafe(receipt,runner,opts));
});
linuxTest("private guard replacement, public parent and symlink states refuse",t=>{
  const {runner,receipt,opts,guard,guardRoot}=setup(t),pre=file(guard,"pre");fs.unlinkSync(pre);fs.symlinkSync("nonexistent",pre);assert.throws(()=>db.assertSafe(receipt,runner,opts));assert.throws(()=>db.assertNoMarkers(runner,opts));
  fs.chmodSync(guardRoot,0o777);assert.throws(()=>db.assertNoMarkers(runner,opts),/parent not private/);
});
linuxTest("orphan guard before receipt creation is detected by deterministic path",t=>{
  const {runner,receipt,opts,guard}=setup(t,false);fs.mkdirSync(guard,{mode:0o700});assert.throws(()=>db.assertNoMarkers(runner,opts),/guard remains/);assert.throws(()=>db.preparePre(receipt,runner,workspaceId,opts));
});
linuxTest("unknown file or replaced guard directory prevents any cleanup",t=>{
  const {runner,receipt,opts,guard}=setup(t);fs.writeFileSync(path.join(guard,"unknown"),"x");assert.throws(()=>db.assertSafe(receipt,runner,opts),/Unknown/);
  fs.unlinkSync(path.join(guard,"unknown"));fs.renameSync(guard,`${guard}.renamed`);fs.mkdirSync(guard,{mode:0o700});assert.throws(()=>db.assertSafe(receipt,runner,opts),/identity changed/);
});
linuxTest("owner PID is bound to pre and authenticated done",t=>{
  const {runner,receipt,opts}=setup(t);assert.equal(receipt.dbOwnerPid,process.pid);
  assert.throws(()=>db.assertSafe({...receipt,dbOwnerPid:process.pid+1},runner,opts));
  db.start(receipt,runner,opts);db.markDone(receipt,runner,{workspaceId,agentRowId,agentId},opts);
  assert.throws(()=>db.assertSafe({...receipt,dbOwnerPid:process.pid+1},runner,opts));
});
linuxTest("invalid authentication key is never included in assertion",t=>{
  const {runner,receipt,opts}=setup(t),secret="invalid-secret-never-log";
  assert.throws(()=>db.assertSafe({...receipt,dbAuthKey:secret},runner,opts),error=>!String(error.stack).includes(secret)&&/key invalid/.test(error.message));
});
test("fallback permits only an absent owner PID",()=>{
  let calls=0;db.assertOwnerExited({dbOwnerPid:42},(pid,signal)=>{calls++;assert.equal(pid,42);assert.equal(signal,0);const error=Error();error.code="ESRCH";throw error;});assert.equal(calls,1);
  assert.throws(()=>db.assertOwnerExited({dbOwnerPid:process.pid}),/still exists/);
  assert.throws(()=>db.assertOwnerExited({dbOwnerPid:42},()=>{}),/still exists/);
  for(const code of ["EPERM","EINVAL",undefined])assert.throws(()=>db.assertOwnerExited({dbOwnerPid:42},()=>{const error=Error();error.code=code;throw error;}),/uncertain/);
  for(const pid of [undefined,0,1,-1,1.5,"42"])assert.throws(()=>db.assertOwnerExited({dbOwnerPid:pid},()=>{throw Error("must not call kill");}),/PID invalid/);
});
linuxTest("host receipt guard blocks active, orphan and receipt before seeded cleanup",t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),"tt-host-guard-")),runner=path.join(root,"runner");fs.mkdirSync(runner,{mode:0o700});
  const guard=path.join("/run","ttqual-db-"+crypto.createHash("sha256").update(fs.realpathSync.native(runner)).digest("hex"));
  t.after(()=>{fs.rmSync(guard,{recursive:true,force:true});fs.rmSync(root,{recursive:true,force:true});});
  const ownership=require("./certops-linux-systemd-ownership"),receipt={installedDiscoveryNonce:"a".repeat(64)};
  const beforeMutation=()=>{ownership.assertHostReceiptRemoved(runner);return "mutation permitted";};
  db.preparePre(receipt,runner,workspaceId);db.start(receipt,runner);assert.throws(beforeMutation,/guard remains/);
  fs.rmSync(guard,{recursive:true});fs.mkdirSync(guard,{mode:0o700});assert.throws(beforeMutation,/guard remains/);
  fs.rmdirSync(guard);fs.writeFileSync(path.join(runner,"certops-linux-systemd-owned.json"),"receipt");assert.throws(beforeMutation,/ownership remains unresolved/);
  fs.unlinkSync(path.join(runner,"certops-linux-systemd-owned.json"));assert.equal(beforeMutation(),"mutation permitted");
});
