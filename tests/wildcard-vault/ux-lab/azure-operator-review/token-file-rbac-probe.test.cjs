"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),{consumerReadWriteProbe}=require("./token-file-rbac-probe.cjs");
test("only an authenticated read and explicit 403 count as denial; intent precedes write",async()=>{
  const events=[], input={vaultOrigin:"https://owned-vault.vault.azure.net",secretName:"tt-probe-"+"a".repeat(32),version:"b".repeat(32),
    getToken:async()=>"synthetic-token",recordOwnedIntent:async()=>events.push("intent"),
    requestJson:async (_url,o)=>(events.push(o.method),o.method==="GET"?{status:200,json:{id:`${input.vaultOrigin}/secrets/${input.secretName}/${input.version}`}}:{status:403})};
  const result=await consumerReadWriteProbe(input); assert.equal(result.consumerWriteDenied,true);
  assert.deepEqual(events,["GET","intent","PUT"]); assert.doesNotMatch(JSON.stringify(result),/synthetic-token/);
  const read={status:200,json:{id:`${input.vaultOrigin}/secrets/${input.secretName}/${input.version}`}};
  await assert.rejects(consumerReadWriteProbe({...input,requestJson:async (_url,o)=>o.method==="GET"?read:{status:401}}),/denial not established/);
  await assert.rejects(consumerReadWriteProbe({...input,requestJson:async()=>{throw new Error("network");}}),/network/);
  await assert.rejects(consumerReadWriteProbe({...input,requestJson:async (_url,o)=>o.method==="GET"?read:{status:200}}),/cleanup/);
});
