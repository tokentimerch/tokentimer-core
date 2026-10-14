/**
 * Verify periodic execution-lease loss reaches the active command cancellation signal.
 * Controlled timers/lease callbacks test propagation; native command-tree teardown and
 * actual public cancellation are qualified separately by the command and ACME journeys. */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const {startExecutionLeaseRenewal}=require("./index");
test("execution lease renewal aborts its command signal on actual ownership-refusal response",{timeout:5000},async()=>{
 const heartbeat=startExecutionLeaseRenewal({leaseClient:{renewLease:async()=>({ok:false,status:409,code:"CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH"})},jobId:"owned-unit-job",claimId:"owned-unit-claim",leaseState:{},log:()=>{}},{intervalMs:5});
 try{await new Promise(resolve=>heartbeat.signal.addEventListener("abort",resolve,{once:true}));assert.equal(heartbeat.signal.aborted,true);assert.equal(heartbeat.signal.reason.status,"blocked");assert.match(heartbeat.signal.reason.errorMessage,/HTTP 409/);}finally{heartbeat.stop();}
});
