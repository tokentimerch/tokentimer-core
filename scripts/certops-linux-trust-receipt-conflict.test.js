"use strict";
/** Offline receipt/protocol adversaries only. No trust store or native refresh
 * executes here; synthetic proof objects cannot qualify a disposable host. */
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const h=require("./certops-linux-trust-receipt-conflict");
function proof(){return {schemaVersion:1,scope:h.SCOPE,family:"debian",writerCount:2,serializationQualified:false,partialWriteRecoveryQualified:false,detachedDescendantContainmentQualified:false,losingFailureCategory:"receipt_finalize_conflict",firstJobId:"11111111-1111-4111-8111-111111111111",secondJobId:"22222222-2222-4222-8222-222222222222",fingerprints:["a".repeat(64),"b".repeat(64)],...Object.fromEntries(h.FLAGS.map(name=>[name,true]))};}
test("native trust conflict proof requires truthful losing disposition and every separate-process/recovery observation",()=>{
  assert.equal(h.verifyProof(proof()),true);
  for(const flag of h.FLAGS){for(const wrong of [false,1,"true",null])assert.throws(()=>h.verifyProof({...proof(),[flag]:wrong}));const missing=proof();delete missing[flag];assert.throws(()=>h.verifyProof(missing));}
  for(const change of [{detachedDescendantContainmentQualified:true},{serializationQualified:true},{partialWriteRecoveryQualified:true},{family:"windows"},{writerCount:1},{losingFailureCategory:null},{losingFailureCategory:"os_mutation_failed"},{secondJobId:proof().firstJobId},{fingerprints:["a".repeat(64),"a".repeat(64)]},{scope:"serialized-writers"},{privateKey:"withheld"}])assert.throws(()=>h.verifyProof({...proof(),...change}));
});
test("closed no-clobber barriers preserve prior bytes and failed publication temp",()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),"certops-trust-protocol-test-"));
  try{const file=path.join(root,"ready.json"),value={token:"a".repeat(32),nativeExitCode:0};h.publish(file,value);assert.deepEqual(JSON.parse(fs.readFileSync(file,"utf8")),value);assert.throws(()=>h.publish(file,{token:"b".repeat(32)}));assert.deepEqual(JSON.parse(fs.readFileSync(file,"utf8")),value);const leftovers=fs.readdirSync(root).filter(name=>name.endsWith(".tmp"));assert.equal(leftovers.length,1);assert.equal(JSON.parse(fs.readFileSync(path.join(root,leftovers[0]),"utf8")).token,"b".repeat(32));}
  finally{for(const name of fs.readdirSync(root)){const file=path.join(root,name);assert.ok(fs.lstatSync(file).isFile()&&!fs.lstatSync(file).isSymbolicLink());fs.unlinkSync(file);}fs.rmdirSync(root);}
});
test("unresolved native writer marker blocks parent trust cleanup",()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),"certops-trust-custody-test-")),marker=path.join(root,".preserve-trust-receipt-conflict-owned.json");
  try{assert.equal(h.assertCleanupSafe(root),undefined);fs.writeFileSync(marker,"owned",{flag:"wx"});assert.throws(()=>h.assertCleanupSafe(root));assert.equal(fs.readFileSync(marker,"utf8"),"owned");}
  finally{if(fs.existsSync(marker))fs.unlinkSync(marker);fs.rmdirSync(root);}
});
test("post-condition override cannot hide a refresh timeout behind expected finalized/conflict results",()=>{
  for(const failureCategory of [null,"receipt_finalize_conflict"]){const result={failureCategory,outcome:"installed",mutationPerformed:true,receipt:{state:"finalized"}};assert.doesNotThrow(()=>h.assertCleanNativeResult(result));for(const metadata of [[{name:"post_condition_override_applied",value:true}],[{name:"refresh_command_exit_code",value:null}],[{name:"refresh_command_exit_code",value:1}]])assert.throws(()=>h.assertCleanNativeResult({...result,metadata}));}
});
test("process group parser preserves native PID/session/birth even with parenthesized command names",()=>{
  const fields=["S","10","55","55",...Array(15).fill("0"),"12345"];
  assert.deepEqual(h.parseProcess(55,`55 (owned (worker) name) ${fields.join(" ")}`),{pid:55,parent:10,group:55,session:55,birth:"12345"});
  const kernel=[...fields];kernel[1]="0";kernel[2]="0";kernel[3]="0";
  assert.equal(h.parseProcess(55,`55 (kernel) ${kernel.join(" ")}`).parent,0);
  for(const raw of [`56 (foreign) ${fields.join(" ")}`,"55 (truncated) S 1 55",`55 (bad) ${fields.map((value,index)=>index===2?"unknown":value).join(" ")}`])assert.throws(()=>h.parseProcess(55,raw));
});
