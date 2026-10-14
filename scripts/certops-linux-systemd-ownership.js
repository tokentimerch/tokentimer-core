"use strict";
const assert=require("node:assert/strict"),path=require("node:path"),fs=require("node:fs");
function validateWriteFixture(value){
  assert.ok(value&&typeof value==="object");assert.match(value.runId,/^[a-f0-9]{10}$/);const root=`/var/lib/tokentimer-qualification-${value.runId}`;assert.equal(value.root,root);assert.equal(value.allowed,path.posix.join(root,"allowed"));assert.equal(value.denied,path.posix.join(root,"denied"));assert.equal(value.probe,path.posix.join(root,"write-probe.js"));assert.match(value.probeSha256,/^[a-f0-9]{64}$/);return value;
}
function validateHostedEnvironment(env){
  assert.equal(env.GITHUB_ACTIONS,"true");assert.equal(env.RUNNER_ENVIRONMENT,"github-hosted");assert.equal(env.CERTOPS_LINUX_SYSTEMD_DISPOSABLE_HOST,"1");assert.ok(env.RUNNER_TEMP&&path.isAbsolute(env.RUNNER_TEMP));
}
function assertNoSymlinkTargets(targets){for(const target of targets){const stat=fs.lstatSync(target,{throwIfNoEntry:false});assert.equal(stat?.isSymbolicLink()||false,false,"Refuse symlink ownership target before installer/uninstaller execution");}}
function claimOwnershipReceipt(file,receipt){fs.writeFileSync(file,JSON.stringify(receipt),{flag:"wx",mode:0o600});}
module.exports={validateWriteFixture,validateHostedEnvironment,claimOwnershipReceipt,assertNoSymlinkTargets};
