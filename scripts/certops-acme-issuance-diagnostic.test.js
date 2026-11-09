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
