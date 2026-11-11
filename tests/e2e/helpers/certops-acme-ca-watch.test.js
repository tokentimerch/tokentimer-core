"use strict";
const { test } = require("node:test"), assert = require("node:assert/strict"), { PassThrough } = require("node:stream"), { EventEmitter } = require("node:events");
const { classifyWatcherStart, createCaWatchChannel, startCaProcessWatch } = require("./certops-acme-ca-watch");
test("watcher startup diagnostic is classified without returning raw stderr",()=>{
 assert.equal(classifyWatcherStart("AuthorizationManager secret-like-test-value","watcher-stream-closed"),"watcher-authorization-manager-denied");
 assert.equal(classifyWatcherStart("unrelated private content","watcher-stream-closed"),"watcher-stream-closed");
 assert.equal(classifyWatcherStart("","watcher-not-started"),"watcher-start-timeout");
});
function fixture() {
  let clock = 0, failure = null; const stream = new PassThrough(), process = new EventEmitter();
  const watch = createCaWatchChannel({stream,process,expectedPid:42,binarySha256:"a".repeat(64),onFailure:reason=>{failure=reason;},now:()=>clock});
  const send = record => stream.write(JSON.stringify(record)+"\n");
  const start = () => send({event:"started",watchId:"b".repeat(32),processId:42,binarySha256:"a".repeat(64),coverageComplete:false});
  return {watch,stream,process,send,start,tick:ms=>{clock+=ms;},failure:()=>failure};
}
test("watcher starts before use and never claims complete observation",()=>{
 const f=fixture(); assert.equal(f.watch.inspect().processContinuity,false); f.start();
 assert.equal(f.watch.inspect().processContinuity,true); assert.equal(f.watch.inspect().coverageComplete,false);
 f.send({event:"heartbeat",watchId:"b".repeat(32),elapsedSeconds:1,coverageComplete:false});
 assert.equal(f.watch.inspect().captureId,"b".repeat(32));
});
test("watcher failure, stream loss, stale heartbeat and identity change fail closed",()=>{
 for(const action of [f=>f.process.emit("exit",1),f=>f.stream.emit("end"),f=>f.tick(3001),
  f=>f.send({event:"heartbeat",watchId:"c".repeat(32),elapsedSeconds:1,coverageComplete:false}),
  f=>f.send({event:"process-exited",watchId:"b".repeat(32),coverageComplete:false})]){
  const f=fixture();f.start();action(f);assert.equal(f.watch.inspect().processContinuity,false);assert.equal(f.watch.inspect().coverageComplete,false);assert.ok(f.failure());f.watch.close();
 }
});

// skip-reason: platform
test("real Windows process exit aborts the dedicated watcher without claiming coverage", {skip:process.platform!=="win32"}, async()=>{
 const {spawn}=require("node:child_process"),fs=require("node:fs"),crypto=require("node:crypto");
 const target=spawn(process.execPath,["-e","setTimeout(()=>{},30000)"],{windowsHide:true,stdio:"ignore"});
 const binarySha256=crypto.createHash("sha256").update(fs.readFileSync(process.execPath)).digest("hex");
 const abortController=new AbortController(); let watch;
 try {
  watch=await startCaProcessWatch({expectedPid:target.pid,executable:process.execPath,binarySha256,abortController});
  assert.equal(watch.inspect().coverageComplete,false); assert.equal(abortController.signal.aborted,false);
  target.kill();
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error("watcher did not abort")),5000);abortController.signal.addEventListener("abort",()=>{clearTimeout(timer);resolve();},{once:true});});
  assert.equal(watch.inspect().processContinuity,false);
 } finally {target.kill();if(watch)await watch.stop();}
});

// skip-reason: platform
test("real watcher interruption aborts the run while its target stays alive", {skip:process.platform!=="win32"}, async()=>{
 const {spawn}=require("node:child_process"),fs=require("node:fs"),crypto=require("node:crypto");
 const target=spawn(process.execPath,["-e","setTimeout(()=>{},30000)"],{windowsHide:true,stdio:"ignore"});
 const binarySha256=crypto.createHash("sha256").update(fs.readFileSync(process.execPath)).digest("hex");
 const abortController=new AbortController();let watch;
 try {
  watch=await startCaProcessWatch({expectedPid:target.pid,executable:process.execPath,binarySha256,abortController});
  process.kill(watch.watcherPid);
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error("watcher interruption not detected")),5000);abortController.signal.addEventListener("abort",()=>{clearTimeout(timer);resolve();},{once:true});});
  assert.equal(target.exitCode,null);assert.equal(watch.inspect().coverageComplete,false);
 } finally {target.kill();if(watch)await watch.stop();}
});
