"use strict";
const {test}=require("node:test"), assert=require("node:assert/strict"), {crossExchange}=require("./cross-role-probes.cjs");
test("requires two own-role successes and specific denial for both cross exchanges", async () => {
  const issuer={tenantId:"11111111-1111-4111-8111-111111111111",clientId:"22222222-2222-4222-8222-222222222222",assertionFile:"/issuer"};
  const consumer={tenantId:issuer.tenantId,clientId:"33333333-3333-4333-8333-333333333333",assertionFile:"/consumer"};
  const readAssertion=async path=>path==="/issuer"?"issuer_assertion_123456789":"consumer_assertion_123456789";
  let crossStatus=400;
  const requestJson=async (_url,options)=>{const body=new URLSearchParams(options.body), own=body.get("client_id")===(body.get("client_assertion").startsWith("issuer")?issuer.clientId:consumer.clientId);
    return own?{status:200,json:{access_token:"synthetic_access_token_12345"}}:{status:crossStatus,json:{error:"invalid_client",error_codes:[70021]}};};
  const input={issuer,consumer,federationMismatchCodes:[70021],readAssertion,requestJson};
  const report=await crossExchange(input); assert.equal(report.crossRoleRejected,2); assert.doesNotMatch(JSON.stringify(report),/assertion|access_token/);
  crossStatus=403; await assert.rejects(crossExchange(input),/federation mismatch/);
  await assert.rejects(crossExchange({...input,requestJson:async()=>{throw new Error("network");}}),/network/);
});
