"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const {issuanceDiagnosticLabels}=require("../tests/e2e/acme-real-journey");
test("issuance diagnostic emits only bounded categories and actual proxy-stage progress",()=>{
 const before={perStage:{"new-order":{forwarded:2},finalize:{forwarded:1}}};
 const after={perStage:{"new-order":{forwarded:3},finalize:{forwarded:1}}};
 assert.deepEqual(issuanceDiagnosticLabels({status:"failed",error_message:"acme step failed with secret private output"},{exitCode:null,signalCode:null},before,after),["real-acme-diagnostic-issue-status-failed","real-acme-diagnostic-agent-running","real-acme-diagnostic-error-acme-step","real-acme-diagnostic-proxy-new-order-forwarded"]);
 const untrusted=issuanceDiagnosticLabels({status:"secret-status",error_message:"secret private output"},{exitCode:1,signalCode:null},before,after);
 assert.deepEqual(untrusted,["real-acme-diagnostic-issue-status-other","real-acme-diagnostic-agent-not-running","real-acme-diagnostic-error-other","real-acme-diagnostic-proxy-new-order-forwarded"]);
 assert.ok(untrusted.every(value=>!value.includes("secret")));
 assert.deepEqual(issuanceDiagnosticLabels(undefined,undefined,undefined,undefined),["real-acme-diagnostic-issue-status-other","real-acme-diagnostic-agent-not-running","real-acme-diagnostic-error-none"]);
});

test("post-finalize categories expose only source-defined failure and validation labels",()=>{
 const run=error_message=>issuanceDiagnosticLabels({status:"failed",error_message},{exitCode:null,signalCode:null},undefined,undefined);
 assert.deepEqual(run("preflight validation failed (CHAIN_INVALID): secret"),["real-acme-diagnostic-issue-status-failed","real-acme-diagnostic-agent-running","real-acme-diagnostic-validation-chain-invalid","real-acme-diagnostic-error-preflight-validation"]);
 assert.ok(run("pre-deploy validation failed (SAN_MISMATCH): secret").includes("real-acme-diagnostic-validation-san-mismatch"));
 assert.ok(run("deploy step failed at stage write: secret").includes("real-acme-diagnostic-error-deployment"));
 assert.ok(run("acme step reported success but produced no certificate file: secret").includes("real-acme-diagnostic-error-acme-staging"));
 assert.ok(run("preflight validation failed (SECRET_TOKEN): private").every(value=>!value.includes("secret")&&!value.includes("private")));
});

test("CA milestones expose only bounded response deltas",()=>{
 const before={acceptedOrders:1,validAuthorizations:2,invalidAuthorizations:0,readyOrders:1,badNonceResponses:0,dnsProblemResponses:0,unauthorizedResponses:0,rateLimitedResponses:0};
 const after={...before,acceptedOrders:2,badNonceResponses:1,privateValue:"do-not-report"};
 const labels=issuanceDiagnosticLabels({status:"failed",error_message:"private-value"},{exitCode:null,signalCode:null},before,after);
 assert.ok(labels.includes("real-acme-diagnostic-ca-observed-order-accepted"));
 assert.ok(labels.includes("real-acme-diagnostic-ca-observed-bad-nonce"));
 assert.ok(!labels.some(value=>value.includes("private")));
 assert.ok(!labels.includes("real-acme-diagnostic-ca-observed-authorization-invalid"));
});

test("second-renewal failure labels remain scoped and reject untrusted phase names",()=>{
 const labels=issuanceDiagnosticLabels({status:"blocked",error_message:"job execution failed: private-data"},{exitCode:null,signalCode:null},{},{},"second-renewal");
 assert.ok(labels.includes("real-acme-diagnostic-second-renewal-status-blocked"));
 assert.ok(labels.includes("real-acme-diagnostic-error-execution-exception"));
 assert.ok(labels.every(value=>!value.includes("private")));
 assert.throws(()=>issuanceDiagnosticLabels({},null,{},{},"private-data"));
});

test("blocked second renewals fail promptly with only an allowlisted reason",()=>{
 const {failedRenewalTerminalStatus}=require("../tests/e2e/acme-real-journey");
 for(const status of ["failed","rejected","cancelled","blocked","orphaned_unknown_effect"])assert.equal(failedRenewalTerminalStatus(status),true);
 for(const status of ["pending","claimed","running","succeeded",undefined,"private-status"])assert.equal(failedRenewalTerminalStatus(status),false);
 const labels=issuanceDiagnosticLabels({status:"blocked",error_message:"lease renew aborted: claim ownership lost or lease conflict (HTTP 409) (private-data)"},{exitCode:null,signalCode:null},{},{},"second-renewal");
 assert.ok(labels.includes("real-acme-diagnostic-second-renewal-block-lease-conflict"));
 assert.ok(labels.every(value=>!value.includes("private")));
 assert.ok(issuanceDiagnosticLabels({status:"blocked",error_message:"private-data"},null,{},{},"second-renewal").includes("real-acme-diagnostic-second-renewal-block-other"));
});


test("native agent cadence leaves discovery and request-budget headroom",()=>{
 const t=require("../tests/e2e/acme-real-journey").QUALIFICATION_AGENT_TIMING;
 // Poll loops jitter by up to 20%; allow five seconds for scan and evidence processing.
 assert.ok(2*t.discoveryIntervalMs*1.2+5000<=t.discoveryObservationTimeoutMs);
 // Conservatively count an extra initial tick per loop in any one-minute window.
 const idleRequests=[t.pollIntervalMs,t.heartbeatIntervalMs,t.discoveryIntervalMs].reduce((sum,ms)=>sum+Math.ceil(60000/(ms*0.8))+1,0);
 assert.ok(idleRequests<=60,`idle request budget ${idleRequests} leaves insufficient room for job traffic`);
});
