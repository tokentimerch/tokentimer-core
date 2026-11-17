/* Durable state for one disposable Linux qualification. A trusted root caller
 * may mark done only after COMMIT confirms; markers are not proof against root. */
"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const files={pre:"pre.json",active:"active.json",done:"done.json"};
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const hash=bytes=>crypto.createHash("sha256").update(bytes).digest("hex");
function rootCheck(root){
  assert.ok(typeof root==="string"&&path.isAbsolute(root));assert.equal(fs.realpathSync.native(root),path.resolve(root));
  const s=fs.lstatSync(root,{bigint:true});assert.ok(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===0n&&(s.mode&0o022n)===0n,"Database guard parent not private to root");
}
function runnerInfo(runnerTemp){
  assert.ok(typeof runnerTemp==="string"&&path.isAbsolute(runnerTemp));const real=fs.realpathSync.native(runnerTemp);assert.equal(real,path.resolve(runnerTemp));
  const s=fs.lstatSync(real,{bigint:true});assert.ok(s.isDirectory()&&!s.isSymbolicLink());return {real,dev:s.dev.toString(),ino:s.ino.toString()};
}
function guardPath(runnerTemp,opts={}){const root=opts.guardRoot||"/run";rootCheck(root);const runner=runnerInfo(runnerTemp);return path.join(root,"ttqual-db-"+hash(Buffer.from(runner.real)));}
function syncDir(dir){const fd=fs.openSync(dir,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function receiptCheck(receipt){assert.ok(receipt&&typeof receipt==="object");assert.match(receipt.installedDiscoveryNonce,/^[a-f0-9]{64}$/);}
function guardCheck(receipt,runnerTemp,opts={}){
  receiptCheck(receipt);const info=runnerInfo(runnerTemp);assert.equal(info.dev,receipt.dbRunnerDev);assert.equal(info.ino,receipt.dbRunnerIno);
  const dir=guardPath(runnerTemp,opts),s=fs.lstatSync(dir,{bigint:true});
  assert.ok(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===0n&&(s.mode&0o777n)===0o700n&&s.dev.toString()===receipt.dbGuardDev&&s.ino.toString()===receipt.dbGuardIno,"Database guard identity changed");
  assert.ok(typeof receipt.dbAuthKey==="string"&&/^[a-f0-9]{64}$/.test(receipt.dbAuthKey),"Database guard authentication key invalid");assert.ok(Number.isSafeInteger(receipt.dbOwnerPid)&&receipt.dbOwnerPid>1,"Database owner PID invalid");assert.match(receipt.dbWorkspaceId,uuid);return dir;
}
function inspect(file){
  const before=fs.lstatSync(file,{bigint:true});
  assert.ok(before.isFile()&&!before.isSymbolicLink()&&before.uid===0n&&(before.mode&0o777n)===0o600n&&before.nlink===1n&&before.size>0n&&before.size<=4096n,"Database marker invalid");
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try{
    const opened=fs.fstatSync(fd,{bigint:true});
    assert.ok(opened.isFile()&&opened.dev===before.dev&&opened.ino===before.ino&&opened.uid===before.uid&&opened.mode===before.mode&&opened.nlink===1n&&opened.size===before.size,"Database marker changed");
    const data=Buffer.alloc(Number(before.size)+1),n=fs.readSync(fd,data,0,data.length,0),after=fs.fstatSync(fd,{bigint:true});
    assert.equal(n,Number(before.size));assert.ok(after.dev===opened.dev&&after.ino===opened.ino&&after.size===opened.size&&after.mtimeNs===opened.mtimeNs&&after.ctimeNs===opened.ctimeNs,"Database marker changed");
    const bytes=data.subarray(0,n);return {dev:before.dev.toString(),ino:before.ino.toString(),sha256:hash(bytes),bytes};
  }finally{fs.closeSync(fd);}
}
function stateFile(dir,state){return path.join(dir,files[state]);}
function present(dir){const entries=fs.readdirSync(dir);assert.ok(entries.every(x=>Object.values(files).includes(x)),"Unknown database guard entry");return Object.entries(files).filter(([,name])=>entries.includes(name)).map(([s])=>s);}
function writeExclusive(file,bytes){const fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function preparePre(receipt,runnerTemp,workspaceId,opts={}){
  receiptCheck(receipt);assert.match(workspaceId,uuid);const runner=runnerInfo(runnerTemp),dir=guardPath(runnerTemp,opts),root=opts.guardRoot||"/run";
  assert.equal(fs.lstatSync(dir,{throwIfNoEntry:false}),undefined,"Database guard already exists");fs.mkdirSync(dir,{mode:0o700});syncDir(root);
  const gs=fs.lstatSync(dir,{bigint:true});assert.ok(gs.isDirectory()&&!gs.isSymbolicLink()&&gs.uid===0n&&(gs.mode&0o777n)===0o700n);
  const bytes=Buffer.from(JSON.stringify({schemaVersion:1,nonce:receipt.installedDiscoveryNonce,ownerPid:process.pid}));
  writeExclusive(stateFile(dir,"pre"),bytes);syncDir(dir);const state=inspect(stateFile(dir,"pre"));assert.equal(state.sha256,hash(bytes));
  Object.assign(receipt,{dbRunnerDev:runner.dev,dbRunnerIno:runner.ino,dbGuardDev:gs.dev.toString(),dbGuardIno:gs.ino.toString(),dbPreDev:state.dev,dbPreIno:state.ino,dbPreHash:state.sha256,dbWorkspaceId:workspaceId.toLowerCase(),dbOwnerPid:process.pid,dbAuthKey:crypto.randomBytes(32).toString("hex")});
}
function validatePreOrActive(receipt,runnerTemp,state,opts={}){
  const dir=guardCheck(receipt,runnerTemp,opts);assert.ok(state==="pre"||state==="active");assert.deepEqual(present(dir),[state],"Ambiguous database cleanup state");
  const current=inspect(stateFile(dir,state));assert.equal(current.dev,receipt.dbPreDev);assert.equal(current.ino,receipt.dbPreIno);assert.equal(current.sha256,receipt.dbPreHash);
  const payload=JSON.parse(current.bytes);assert.deepEqual(Object.keys(payload).sort(),["nonce","ownerPid","schemaVersion"]);assert.equal(payload.schemaVersion,1);assert.equal(payload.nonce,receipt.installedDiscoveryNonce);assert.equal(payload.ownerPid,receipt.dbOwnerPid);
  return {...current,state};
}
function start(receipt,runnerTemp,opts={}){
  validatePreOrActive(receipt,runnerTemp,"pre",opts);const dir=guardCheck(receipt,runnerTemp,opts);
  fs.linkSync(stateFile(dir,"pre"),stateFile(dir,"active"));syncDir(dir);fs.unlinkSync(stateFile(dir,"pre"));syncDir(dir);
  validatePreOrActive(receipt,runnerTemp,"active",opts);
}
function donePayload(receipt,proof){return {schemaVersion:1,nonce:receipt.installedDiscoveryNonce,preHash:receipt.dbPreHash,ownerPid:receipt.dbOwnerPid,workspaceId:proof.workspaceId.toLowerCase(),agentRowId:proof.agentRowId,agentId:proof.agentId};}
function mac(receipt,payload){return crypto.createHmac("sha256",Buffer.from(receipt.dbAuthKey,"hex")).update(JSON.stringify(payload)).digest("hex");}
function validateDone(receipt,runnerTemp,opts={}){
  const dir=guardCheck(receipt,runnerTemp,opts);assert.deepEqual(present(dir),["done"],"Ambiguous database cleanup state");assert.match(receipt.dbPreHash,/^[a-f0-9]{64}$/);
  const current=inspect(stateFile(dir,"done")),value=JSON.parse(current.bytes);
  assert.deepEqual(Object.keys(value).sort(),["agentId","agentRowId","mac","nonce","ownerPid","preHash","schemaVersion","workspaceId"]);
  assert.equal(value.schemaVersion,1);assert.equal(value.nonce,receipt.installedDiscoveryNonce);assert.equal(value.preHash,receipt.dbPreHash);assert.equal(value.ownerPid,receipt.dbOwnerPid);assert.equal(value.workspaceId,receipt.dbWorkspaceId);
  assert.match(value.agentRowId,uuid);assert.match(value.agentId,/^[A-Za-z0-9_.:-]{1,128}$/);assert.match(value.mac,/^[a-f0-9]{64}$/);
  const expected=mac(receipt,donePayload(receipt,value));assert.ok(crypto.timingSafeEqual(Buffer.from(value.mac,"hex"),Buffer.from(expected,"hex")),"Database completion marker authentication failed");
  return {...current,state:"done"};
}
function markDone(receipt,runnerTemp,proof,opts={}){
  validatePreOrActive(receipt,runnerTemp,"active",opts);assert.ok(proof&&typeof proof==="object");assert.match(proof.workspaceId,uuid);
  assert.equal(proof.workspaceId.toLowerCase(),receipt.dbWorkspaceId);assert.match(proof.agentRowId,uuid);assert.match(proof.agentId,/^[A-Za-z0-9_.:-]{1,128}$/);
  const dir=guardCheck(receipt,runnerTemp,opts),payload=donePayload(receipt,proof),bytes=Buffer.from(JSON.stringify({...payload,mac:mac(receipt,payload)}));
  writeExclusive(stateFile(dir,"done"),bytes);syncDir(dir);const active=inspect(stateFile(dir,"active"));assert.equal(active.dev,receipt.dbPreDev);assert.equal(active.ino,receipt.dbPreIno);assert.equal(active.sha256,receipt.dbPreHash);
  const done=inspect(stateFile(dir,"done"));assert.equal(done.sha256,hash(bytes));fs.unlinkSync(stateFile(dir,"active"));syncDir(dir);return validateDone(receipt,runnerTemp,opts);
}
function assertSafe(receipt,runnerTemp,opts={}){
  const dir=guardCheck(receipt,runnerTemp,opts),states=present(dir);assert.equal(states.length,1,"Ambiguous database cleanup state");
  if(states[0]==="pre")return validatePreOrActive(receipt,runnerTemp,"pre",opts);if(states[0]==="done")return validateDone(receipt,runnerTemp,opts);
  throw Error("Database ownership unresolved; preserve receipt and state");
}
function remove(receipt,runnerTemp,proof,opts={}){
  assert.ok(proof&&["pre","done"].includes(proof.state));const current=assertSafe(receipt,runnerTemp,opts);
  assert.equal(current.state,proof.state);assert.equal(current.dev,proof.dev);assert.equal(current.ino,proof.ino);assert.equal(current.sha256,proof.sha256);
  const dir=guardCheck(receipt,runnerTemp,opts),root=opts.guardRoot||"/run";fs.unlinkSync(stateFile(dir,current.state));syncDir(dir);fs.rmdirSync(dir);syncDir(root);
}
function assertNoMarkers(runnerTemp,opts={}){const dir=guardPath(runnerTemp,opts);assert.equal(fs.lstatSync(dir,{throwIfNoEntry:false}),undefined,"Preserve database while guard remains");}
function assertOwnerExited(receipt,kill=process.kill){
  assert.ok(receipt&&Number.isSafeInteger(receipt.dbOwnerPid)&&receipt.dbOwnerPid>1,"Database owner PID invalid");
  try{kill(receipt.dbOwnerPid,0);}catch(error){if(error&&error.code==="ESRCH")return;throw Error("Database owner process state uncertain");}
  throw Error("Database owner process still exists");
}
module.exports={preparePre,start,markDone,assertSafe,remove,assertNoMarkers,assertOwnerExited};
