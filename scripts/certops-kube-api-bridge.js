"use strict";
// Private fixture transport runs separately so blocking kubectl waits cannot
// block real controller HTTP delivery. No request/response bodies are logged.
const fs=require("node:fs");
const http=require("node:http");
const https=require("node:https");
const assert=require("node:assert/strict");
const api=new URL(process.argv[2]);
assert.equal(process.platform,"linux");assert.equal(process.env.GITHUB_ACTIONS,"true");
assert.equal(api.protocol,"http:");assert.ok(["127.0.0.1","localhost"].includes(api.hostname));
const server=https.createServer({cert:fs.readFileSync(process.argv[3]),key:fs.readFileSync(process.argv[4])},(request,response)=>{
  if(!/^\/api\/v1\/certops\/(executor\/|jobs\/)/.test(request.url||"")){response.writeHead(404);response.end();return;}
  const forwarded=http.request(new URL(request.url,api),{method:request.method,headers:{...request.headers,host:api.host},timeout:30000},upstream=>{response.writeHead(upstream.statusCode,upstream.headers);upstream.pipe(response);});
  forwarded.on("error",()=>{if(!response.headersSent)response.writeHead(502);response.end();});
  forwarded.on("timeout",()=>forwarded.destroy());request.pipe(forwarded);
});
server.on("error",()=>{console.error("Private qualification bridge failed");process.exitCode=1;});
server.listen(0,"0.0.0.0",()=>console.log(JSON.stringify({port:server.address().port})));
function close(){server.closeAllConnections();server.close(()=>process.exit(0));}
process.once("SIGTERM",close);process.once("SIGINT",close);
