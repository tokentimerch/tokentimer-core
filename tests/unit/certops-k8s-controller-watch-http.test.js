"use strict";
// Deterministic Kubernetes wire-protocol integration; this is not proof of
// actual etcd compaction or cert-manager issuance on a native cluster.
const {test}=require("node:test");
const assert=require("node:assert/strict");
const http=require("node:http");
const {createRequire}=require("node:module");
const path=require("node:path");
const {pathToFileURL}=require("node:url");
const controllerRequire=createRequire(path.resolve(__dirname,"../../apps/k8s-controller/package.json"));
const {createInClusterCertManagerClient}=require("../../apps/k8s-controller/src/cert-manager-client");
const {createCertManagerObserver}=require("../../apps/k8s-controller/src/cert-manager-observer");
async function until(check){const deadline=Date.now()+5000;while(Date.now()<deadline){if(check())return;await new Promise(resolve=>setTimeout(resolve,10));}throw new Error("Expected wire-protocol recovery missing");}
test("real Kubernetes HTTP watch ERROR410 relists and resumes from the fresh list cursor",{timeout:15000},async()=>{
 const sockets=new Set(),requests=[],observations=[],warnings=[];let lists=0;
 const certificate=version=>({apiVersion:"cert-manager.io/v1",kind:"Certificate",metadata:{name:"wire-leaf",namespace:"wire",uid:"owned-wire-certificate",resourceVersion:version},spec:{secretName:"wire-tls",dnsNames:["wire.example.test"],issuerRef:{kind:"Issuer",name:"wire"}},status:{conditions:[{type:"Ready",status:"True"}],revision:Number(version)}});
 const server=http.createServer((request,response)=>{
  const url=new URL(request.url,"http://127.0.0.1");requests.push(url);
  const certificates=url.pathname.endsWith("/certificates");
  response.setHeader("Content-Type","application/json");
  if(url.searchParams.get("watch")==="true"){
   response.writeHead(200);response.flushHeaders();
   if(certificates&&url.searchParams.get("resourceVersion")==="10")response.end(JSON.stringify({type:"ERROR",object:{apiVersion:"v1",kind:"Status",status:"Failure",reason:"Expired",code:410,message:"Fixture resource version expired"}})+"\n");
   else if(certificates)response.write(JSON.stringify({type:"MODIFIED",object:certificate("21")})+"\n");
  }else{if(certificates)lists++;response.end(JSON.stringify({apiVersion:"cert-manager.io/v1",kind:certificates?"CertificateList":"CertificateRequestList",metadata:{resourceVersion:certificates&&lists>1?"20":"10"},items:certificates?[certificate(lists>1?"20":"10")]:[]}));}
 });
 server.on("connection",socket=>{sockets.add(socket);socket.on("close",()=>sockets.delete(socket));});
 await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
 let observer;
 try{
  const kube=await import(pathToFileURL(controllerRequire.resolve("@kubernetes/client-node")).href);
  class FixtureKubeConfig extends kube.KubeConfig{loadFromCluster(){this.loadFromOptions({clusters:[{name:"wire",skipTLSVerify:true,server:`http://127.0.0.1:${server.address().port}`}],users:[{name:"wire"}],contexts:[{name:"wire",cluster:"wire",user:"wire"}],currentContext:"wire"});}}
  const client=createInClusterCertManagerClient({loadClient:async()=>({...kube,KubeConfig:FixtureKubeConfig})});
  await client.start();await client.list({resource:"CertificateRequest",namespace:"wire"});observer=createCertManagerObserver({client,clusterId:"wire-cluster",workspaceId:"wire-workspace",watchNamespaces:["wire"],restartBaseDelayMs:10,restartMaxDelayMs:20,random:()=>0,observationHandler:async value=>{observations.push(value);},logger:{warn:(message,fields)=>warnings.push({message,...fields}),info(){},error(){},debug(){}}});
  await observer.start();
  await until(()=>observations.some(value=>value.resourceVersion==="21")&&observer.isReady());
  assert.equal(lists,2,"An actual streamed ERROR must trigger exactly one fresh certificate list");
  assert.deepEqual(requests.filter(url=>url.pathname.endsWith("/certificates")&&url.searchParams.get("watch")==="true").map(url=>url.searchParams.get("resourceVersion")),["10","20"]);
  assert.ok(warnings.some(value=>value.code==="CERT_MANAGER_RESOURCE_VERSION_EXPIRED"),JSON.stringify(warnings));
  assert.ok(observations.some(value=>value.resourceVersion==="20"),"The relisted certificate must be observed before new watch events");
 }finally{
  if(observer)await observer.close();
  for(const socket of sockets)socket.destroy();
  await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));
 }
});
