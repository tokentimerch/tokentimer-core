"use strict";
// Executed inside the production controller image, with its actual scoped
// ServiceAccount. The host must compact the real owned etcd and restart its
// API server before releasing this fixture; no synthetic watch events exist.
const assert=require("node:assert/strict"),fs=require("node:fs");
const namespace=process.env.CERTOPS_TEST_NAMESPACE;
async function until(check,timeout=90000){const end=Date.now()+timeout;while(Date.now()<end){const value=await check();if(value)return value;await new Promise(resolve=>setTimeout(resolve,250));}throw new Error("Native compaction handshake deadline exceeded");}
function publish(file,value){assert.equal(fs.existsSync(file),false);const temporary=`${file}.tmp`;fs.writeFileSync(temporary,JSON.stringify(value),{flag:"wx"});fs.renameSync(temporary,file);}
function command(file){try{return JSON.parse(fs.readFileSync(file,"utf8"));}catch(error){if(error.code==="ENOENT")return null;throw error;}}
async function main(){
 const {createInClusterCertManagerClient}=require("/app/apps/k8s-controller/src/cert-manager-client");
 const {createCertManagerObserver}=require("/app/apps/k8s-controller/src/cert-manager-observer");
 const client=createInClusterCertManagerClient();let observer,watcher;
 try{
  await client.start();const snapshot=await client.list({resource:"Certificate",namespace});assert.match(snapshot.resourceVersion,/^[1-9][0-9]*$/);const original=snapshot.items.find(item=>item.metadata.name==="owned");assert.ok(original);
  publish("/tmp/checkpoint.json",{resourceVersion:snapshot.resourceVersion,certificateUid:original.metadata.uid});
  const compacted=await until(()=>command("/tmp/compacted.json"),180000);assert.ok(BigInt(compacted.revision)>BigInt(snapshot.resourceVersion));
  let status;const expired=new Promise((resolve,reject)=>{
   const timer=setTimeout(()=>reject(new Error("Actual expired native watch was not rejected")),20000);
   const accept=error=>{const code=[error?.statusCode,error?.status,error?.code,error?.body?.code].map(Number).find(value=>value===410);if(code===410){status=code;clearTimeout(timer);resolve();}else{clearTimeout(timer);reject(new Error("Native stale watch failed without410"));}};
   client.watch({resource:"Certificate",namespace,resourceVersion:snapshot.resourceVersion,onEvent:(phase,object)=>{if(phase==="ERROR")accept(object);},onError:accept}).then(value=>{watcher=value;},error=>accept(error));
  });
  await expired;watcher?.close();watcher=null;assert.equal(status,410);
  const observations=[];observer=createCertManagerObserver({client,workspaceId:"native-compaction-workspace",clusterId:"native-compaction-cluster",watchNamespaces:[namespace],observationHandler:async value=>{observations.push(value);}});
  await observer.start();assert.equal(observer.isReady(),true);
  publish("/tmp/relisted.json",{expiredStatus:status,ready:true});
  const changed=await until(()=>command("/tmp/changed.json"));
  await until(()=>observations.some(value=>value.certificateUid===original.metadata.uid&&value.resourceVersion===changed.resourceVersion));
  const result={expiredStatus:410,originalResourceVersion:snapshot.resourceVersion,compactedRevision:String(compacted.revision),observedResourceVersion:changed.resourceVersion,certificateUid:original.metadata.uid,productionClient:true,productionObserver:true};
  console.log(JSON.stringify(result));
 }finally{watcher?.close();if(observer)await observer.close();else await client.close();}
}
if(require.main===module)main().catch(()=>{console.error("Native compaction fixture failed; no qualification result was emitted");process.exitCode=1;});

module.exports={publish};
