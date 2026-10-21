"use strict";
// Private fixture transport runs separately so blocking kubectl waits cannot
// block controller delivery. It never logs request bodies or bearer tokens.
const fs=require("node:fs"),http=require("node:http"),https=require("node:https"),assert=require("node:assert/strict");
const UUID="[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}";
const ROUTE=new RegExp(`^/api/v1/certops/(?:executor/(?:observations|provisioning-commands/next|provisioning-commands/${UUID}/authorize-mutation)|jobs/${UUID}/events)$`,"i");
function fixtureApiPort(value){
 const api=new URL(value);assert.equal(api.protocol,"http:");assert.ok(["127.0.0.1","localhost"].includes(api.hostname));assert.equal(api.username,"");assert.equal(api.password,"");assert.equal(api.pathname,"/");assert.equal(api.search,"");assert.equal(api.hash,"");const port=Number(api.port||80);assert.ok(Number.isInteger(port)&&port>0&&port<65536);return port;
}
function createBridgeRequestHandler(port){
 assert.ok(Number.isInteger(port)&&port>0&&port<65536);
 return(request,response)=>{
  if(request.method!=="POST"||!ROUTE.test(request.url||"")){response.writeHead(404);response.end();return;}
  const authorization=request.headers.authorization;
  if(typeof authorization!=="string"||authorization.length>8192||!/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)){response.writeHead(401);response.end();return;}
  if(!/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers["content-type"]||"")){response.writeHead(415);response.end();return;}
  // The incoming target supplies only an exact allowlisted relative path.
  // Neither its URL nor its Host/forwarding/cookie headers can select a peer.
  const forwarded=http.request({hostname:"127.0.0.1",port,path:request.url,method:"POST",headers:{authorization,"content-type":"application/json"},timeout:30000},upstream=>{
   response.writeHead(upstream.statusCode,{"content-type":"application/json"});upstream.pipe(response);
  });
  forwarded.on("error",()=>{if(!response.headersSent)response.writeHead(502);response.end();});forwarded.on("timeout",()=>forwarded.destroy());
  request.on("aborted",()=>forwarded.destroy());response.on("close",()=>{if(!response.writableFinished)forwarded.destroy();});
  let bytes=0;request.on("data",chunk=>{bytes+=chunk.length;if(bytes>1024*1024){forwarded.destroy();request.destroy();}});request.pipe(forwarded);
 };
}
function main(){
 assert.equal(process.platform,"linux");assert.equal(process.env.GITHUB_ACTIONS,"true");assert.equal(process.env.RUNNER_ENVIRONMENT,"github-hosted");
 const server=https.createServer({cert:fs.readFileSync(process.argv[3]),key:fs.readFileSync(process.argv[4])},createBridgeRequestHandler(fixtureApiPort(process.argv[2])));
 server.on("error",()=>{console.error("Private qualification bridge failed");process.exitCode=1;});
 server.listen(0,"0.0.0.0",()=>console.log(JSON.stringify({port:server.address().port})));
 function close(){server.closeAllConnections();server.close(()=>process.exit(0));}
 process.once("SIGTERM",close);process.once("SIGINT",close);
}
if(require.main===module)main();
module.exports={fixtureApiPort,createBridgeRequestHandler};
