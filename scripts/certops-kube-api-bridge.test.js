"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),http=require("node:http");
const {fixtureApiPort,createBridgeRequestHandler}=require("./certops-kube-api-bridge");
const listen=server=>new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
const close=server=>new Promise((resolve,reject)=>{server.closeAllConnections();server.close(error=>error?reject(error):resolve());});
function request(port,path,headers={},method="POST"){return new Promise((resolve,reject)=>{const outgoing=http.request({hostname:"127.0.0.1",port,path,method,headers:{authorization:"Bearer qualification-machine-token","content-type":"application/json",...headers}},response=>{response.resume();response.on("end",()=>resolve({status:response.statusCode,headers:response.headers}));});outgoing.on("error",error=>{error.message+=" fixture path="+path;reject(error);});outgoing.end(method==="GET"?undefined:"{}");});}
test("bridge startup accepts only loopback HTTP root without credentials query or fragment",()=>{
 assert.equal(fixtureApiPort("http://localhost:4000/"),4000);assert.equal(fixtureApiPort("http://127.0.0.1:4000"),4000);
 for(const url of ["https://localhost:4000","http://localhost.attacker.test:4000","http://127.0.0.2:4000","http://169.254.169.254/","http://user:password@localhost:4000","http://localhost:4000/path","http://localhost:4000/?next=evil","http://localhost:4000/#evil"])assert.throws(()=>fixtureApiPort(url));
});
test("real HTTP bridge forwards only committed controller POST routes and bounded machine headers",async()=>{
 const calls=[];const upstream=http.createServer((req,res)=>{calls.push({path:req.url,headers:req.headers});req.resume();res.writeHead(200,{"content-type":"application/json","set-cookie":"must-not-forward=1"});res.end("{}");});let bridge;
 await listen(upstream);
 try{
  bridge=http.createServer(createBridgeRequestHandler(upstream.address().port));await listen(bridge);const port=bridge.address().port,id="12345678-abcd-4000-8000-123456789abc";
  const valid=["/api/v1/certops/executor/observations","/api/v1/certops/executor/provisioning-commands/next",`/api/v1/certops/executor/provisioning-commands/${id}/authorize-mutation`,`/api/v1/certops/jobs/${id}/events`];
  for(const path of valid){const actual=await request(port,path,{host:"attacker.invalid",cookie:"browser-session=secret","x-forwarded-host":"attacker.invalid","x-forwarded-for":"169.254.169.254"});assert.equal(actual.status,200);assert.equal(actual.headers["set-cookie"],undefined);}
  assert.deepEqual(calls.map(value=>value.path),valid);
  for(const call of calls){assert.equal(call.headers.authorization,"Bearer qualification-machine-token");assert.equal(call.headers.cookie,undefined);assert.equal(call.headers["x-forwarded-host"],undefined);assert.equal(call.headers["x-forwarded-for"],undefined);assert.equal(call.headers.host,`127.0.0.1:${upstream.address().port}`);}
  for(const path of ["http://169.254.169.254/latest/meta-data","//attacker.invalid/api/v1/certops/executor/observations","/api/v1/certops/executor/../admin","/api/v1/certops/executor/%2e%2e/admin","/api/v1/certops/executor/observations?next=http://attacker.invalid","/api/v1/certops/executor/observations/extra",`/api/v1/certops/jobs/${id}/events#fragment`,`/api/v1/certops/jobs/not-a-uuid/events`])assert.equal((await request(port,path)).status,404);
  assert.equal((await request(port,valid[0],{},"GET")).status,404);assert.equal((await request(port,valid[0],{authorization:"Basic secret"})).status,401);assert.equal((await request(port,valid[0],{"content-type":"text/plain"})).status,415);assert.equal(calls.length,4,"Refused targets and credentials never reach any upstream");
 }finally{if(bridge)await close(bridge);await close(upstream);}
});
