"use strict";
const {test}=require("node:test"), assert=require("node:assert/strict"), {createBridge}=require("./role-control-bridge.cjs");
test("loopback control forwards a supported action to the selected role only", async t=>{
  const calls=[], token="a".repeat(64),server=createBridge({token,send:async (role,body)=>(calls.push({role,action:body.action}),{ok:true})});
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve)); t.after(()=>new Promise(resolve=>server.close(resolve)));
  const url=`http://127.0.0.1:${server.address().port}/`;
  const blocked=await fetch(url,{method:"POST",body:JSON.stringify({name:"nginx",action:"tls-proof"})});
  assert.equal(blocked.status,403);assert.equal(calls.length,0);
  const headers={"Content-Type":"application/json",Authorization:`Bearer ${token}`};
  const response=await fetch(url,{method:"POST",headers,body:JSON.stringify({name:"nginx",action:"tls-proof"})});
  assert.equal(response.status,200); assert.deepEqual(calls,[{role:"consumer",action:"tls-proof"}]);
  const denied=await fetch(url,{method:"POST",headers,body:JSON.stringify({name:"issuer",action:"tls-proof"})});
  assert.equal(denied.status,400); assert.equal(calls.length,1);
});
