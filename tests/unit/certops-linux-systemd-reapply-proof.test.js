"use strict";
// Portable refusal coverage for independently measured native reapplication facts.
// Synthetic records exercise the verifier only; the real installer stays opt-in.
const {test}=require("node:test"),assert=require("node:assert/strict");
const {verifyProof}=require("../e2e/helpers/linux-systemd-reapply");
function proof(){return {installation:"same-candidate-reapplication",operatorConfigBytesPreserved:true,credentialBytesPreserved:true,candidatePackageInstalled:true,dropinPreserved:true,privatePermissionsPreserved:true,sameRegistration:true,spareBootstrapUnconsumed:true,bootstrapFileAbsent:true,bootstrapAbsentAfterFreshRestart:true,freshAuthenticatedHeartbeat:true,originalConfigRestored:true,beforePid:101,reappliedPid:202,freshRestartPid:303,nativeUid:1001};}
test("reapply proof rejects missing preserved authority bootstrap consumption or reused PID",()=>{assert.equal(verifyProof(proof()),true);for(const key of Object.keys(proof()).filter(key=>proof()[key]===true)){assert.throws(()=>verifyProof({...proof(),[key]:false}));assert.throws(()=>verifyProof({...proof(),[key]:undefined}));}for(const change of [{installation:"cross-version-upgrade"},{freshRestartPid:202},{beforePid:0},{nativeUid:0}])assert.throws(()=>verifyProof({...proof(),...change}));});
