/**
 * Prove disposable hosted-VM and exact installed unit/process ownership before mutation.
 * Shared by the systemd journey and its interruption cleanup; command results and
 * ownership receipts are validated before stopping or removing an agent. Environment
 * flags alone never authorize touching a foreign service. */
"use strict";
const assert=require("node:assert/strict"),path=require("node:path"),fs=require("node:fs");
function validateWriteFixture(value){
  assert.ok(value&&typeof value==="object");assert.match(value.runId,/^[a-f0-9]{10}$/);const root=`/var/lib/tokentimer-qualification-${value.runId}`;assert.equal(value.root,root);assert.equal(value.allowed,path.posix.join(root,"allowed"));assert.equal(value.denied,path.posix.join(root,"denied"));assert.equal(value.probe,path.posix.join(root,"write-probe.js"));assert.match(value.probeSha256,/^[a-f0-9]{64}$/);return value;
}
function validateHostedEnvironment(env){
  assert.equal(env.GITHUB_ACTIONS,"true");assert.equal(env.RUNNER_ENVIRONMENT,"github-hosted");assert.equal(env.CERTOPS_LINUX_SYSTEMD_DISPOSABLE_HOST,"1");assert.ok(env.RUNNER_TEMP&&path.isAbsolute(env.RUNNER_TEMP));
}
function assertNoSymlinkTargets(targets){for(const target of targets){const stat=fs.lstatSync(target,{throwIfNoEntry:false});assert.equal(stat?.isSymbolicLink()||false,false,"Refuse symlink ownership target before installer/uninstaller execution");}}
function claimOwnershipReceipt(file,receipt){const fd=fs.openSync(file,"wx",0o600);try{fs.writeFileSync(fd,JSON.stringify(receipt));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}if(process.platform==="linux"){const dir=fs.openSync(path.dirname(file),fs.constants.O_RDONLY);try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}}
// Hold the original receipt while cleanup runs; refuse replacement or mutation.
function captureOwnershipReceipt(file){
  const before=fs.lstatSync(file,{bigint:true});
  assert.ok(before.isFile()&&!before.isSymbolicLink()&&before.uid===0n&&(before.mode&0o777n)===0o600n&&before.nlink===1n&&before.size>0n&&before.size<=65536n);
  const fd=fs.openSync(file,fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0));let closed=false,original;
  function read(){assert.equal(closed,false);const opened=fs.fstatSync(fd,{bigint:true}),current=fs.lstatSync(file,{bigint:true});for(const s of [opened,current])assert.ok(s.isFile()&&!s.isSymbolicLink()&&s.dev===before.dev&&s.ino===before.ino&&s.nlink===1n&&s.uid===before.uid&&s.gid===before.gid&&s.mode===before.mode&&s.size===before.size,"Ownership receipt identity changed");const bytes=Buffer.alloc(Number(opened.size)+1),n=fs.readSync(fd,bytes,0,bytes.length,0),after=fs.fstatSync(fd,{bigint:true});assert.equal(n,Number(opened.size));assert.ok(after.size===opened.size&&after.mtimeNs===opened.mtimeNs&&after.ctimeNs===opened.ctimeNs,"Ownership receipt changed during read");const value=bytes.subarray(0,n);if(original)assert.ok(value.equals(original),"Ownership receipt content changed");return Buffer.from(value);}
  try{original=read();}catch(error){fs.closeSync(fd);throw error;}
  return {original,assertUnchanged:read,close(){if(!closed){fs.closeSync(fd);closed=true;}}};
}
function removeOwnershipReceipt(file,held){held.assertUnchanged();fs.unlinkSync(file);const dir=fs.openSync(path.dirname(file),fs.constants.O_RDONLY);try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}
function assertHostReceiptRemoved(runnerTemp){assert.ok(typeof runnerTemp==="string"&&path.isAbsolute(runnerTemp));require("./certops-linux-systemd-db-ownership").assertNoMarkers(runnerTemp);for(const name of ["certops-linux-systemd-owned.json","certops-linux-systemd-discovery-active.json","certops-linux-systemd-discovery-pre.json"])assert.equal(fs.lstatSync(path.join(runnerTemp,name),{throwIfNoEntry:false}),undefined,"Preserve owned database while installed-host ownership remains unresolved");}
module.exports={validateWriteFixture,validateHostedEnvironment,claimOwnershipReceipt,captureOwnershipReceipt,removeOwnershipReceipt,assertNoSymlinkTargets,assertHostReceiptRemoved};
