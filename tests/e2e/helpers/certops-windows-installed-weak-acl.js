"use strict";
/** Actual installed startup admission slice. Public proofs contain no credential,
 * path or descriptor. Native qualification requires the disposable parent run. */
const assert=require("node:assert/strict");
const SCENARIO="windows-installed-weak-credential-acl-startup-refusal";
const SCOPE="installed-system-weak-credential-dacl-refusal-and-exact-recovery";
const FLAGS=Object.freeze(["actualNativeWeakReadableCredential","exactProductionAclRefusal","failedStartupProcessesDrained","noAuthenticatedHeartbeatDuringRefusal","noAgentOrJobMutation","exactOriginalCredentialBytesAndDaclRestored","nativeCngIisAndTrustedTlsPreserved","freshRepairedSystemHeartbeat","ownedGuardCleared"]);
const REQUIRED_SOURCES=Object.freeze(["tests/e2e/helpers/certops-windows-installed-weak-acl.js","packages/agent/scripts/host/credential-weak-acl-fixture.js","packages/agent/scripts/host/credential-weak-acl-hold.ps1",...require("./certops-windows-config-encoding").REQUIRED_SOURCES]);
function verifyProof(p){assert.deepEqual(Object.keys(p).sort(),["scope","untrustedSid","readMask","startupFailureCount","inFlightMutationQualified",...FLAGS].sort());assert.equal(p.scope,SCOPE);assert.equal(p.untrustedSid,"S-1-1-0");assert.equal(p.readMask,1);assert.equal(p.startupFailureCount,1);assert.equal(p.inFlightMutationQualified,false);for(const field of FLAGS)assert.equal(p[field],true);return true;}
module.exports={SCENARIO,SCOPE,FLAGS,REQUIRED_SOURCES,verifyProof,qualify:c=>require("./certops-windows-config-encoding").qualifyWeakCredentialAcl(c)};
