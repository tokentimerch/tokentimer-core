"use strict";
// Opt-in Linux qualification: real Certbot/Pebble DNS-01, real Vault, two
// independent TLS processes. Everything writes under this Compose volume.
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const crypto=require("node:crypto");
const http=require("node:http");
const https=require("node:https");
const dns=require("node:dns/promises");
const { spawn,spawnSync }=require("node:child_process");
const {executeJob}=require("../../packages/agent/src");
const { publicationSession,executePinnedDeployment,reconcilePinnedDeployment,probeListener }=require("../../packages/agent/src/material-store/lifecycle");
const { createVaultStore,readProtectedFile,writeProtectedJson,protectDirectory }=require("../../packages/agent/src/material-store");
const { computeCertificateFingerprint }=require("../../packages/agent/src/verify");
const { createPolicyEngine,loadPolicyConfig }=require("../../packages/agent/src/policy");
const root=path.join("/fixture",crypto.randomUUID());
protectDirectory(root);
const sans=["*.wildcard.test","wildcard.test"];
const workspaceId=crypto.randomUUID(),groupId=crypto.randomUUID(),issuerId="fixture-issuer";
const proxies=[],children=[];
let orders=0;
const sleep=(ms)=>new Promise((r)=>setTimeout(r,ms));
async function proxy(port,host,upstreamPort,tlsOptions) {
  const handler=(req,res)=>{
    const up=http.request({host,port:upstreamPort,path:req.url,method:req.method,headers:req.headers},(r)=>{res.writeHead(r.statusCode,r.headers);r.pipe(res);});
    up.on("error",()=>res.writeHead(502).end()); req.pipe(up);
  };
  const server=tlsOptions?https.createServer(tlsOptions,handler):http.createServer(handler);
  await new Promise((r)=>server.listen(port,"127.0.0.1",r));proxies.push(server);
}
async function main() {
  const tlsKey=path.join(root,"vault-proxy.key"),tlsCert=path.join(root,"vault-proxy.crt");
  const openssl=spawnSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",tlsKey,"-out",tlsCert,"-days","1","-subj","/CN=127.0.0.1","-addext","subjectAltName=IP:127.0.0.1"],{stdio:"ignore"});assert.equal(openssl.status,0);
  await proxy(18200,"vault",8200,{key:fs.readFileSync(tlsKey),cert:fs.readFileSync(tlsCert)});await proxy(18055,"challtestsrv",8055);
  const dnsIp=(await dns.lookup("challtestsrv")).address;
  process.env.TOKENTIMER_AGENT_CONFIG_DIR=root;
  process.env.REQUESTS_CA_BUNDLE="/repo/.scratch/wildcard/pebble-ca.pem";
  const dnsFile=path.join(root,"dns.json");
  writeProtectedJson(dnsFile,{baseUrl:"http://127.0.0.1:18055",allowInsecureLocalHttp:true});
  writeProtectedJson(path.join(root,"config.json"),{serverUrl:"https://fixture.invalid",agentId:issuerId,
    policy:{allowedTargetSelectors:["*.wildcard.test"],allowedCommands:{certbot:{argv:["certbot","--no-verify-ssl","--agree-tos","--register-unsafely-without-email"]}},
      allowedPaths:[root],allowedCaEndpoints:["https://pebble:14000/dir"],allowedDnsZones:["wildcard.test"],allowedDnsProviders:["pebble-challtestsrv"]},
    dnsProviders:{"pebble-challtestsrv":{credentialsFile:dnsFile},zoneProviderMap:{"wildcard.test":"pebble-challtestsrv"}},
    dnsPropagation:{checkAuthoritative:false,resolvers:[`${dnsIp}:8053`],timeoutMs:20000,intervalMs:200}});
  const tokenFile=path.join(root,"vault-token");fs.writeFileSync(tokenFile,"isolated-vault-fixture-only",{mode:0o600});
  const stores={customer:{address:"https://127.0.0.1:18200",caFile:tlsCert,mount:"secret",tokenFile,timeoutMs:5000,
    groups:{[groupId]:{workspaceId,prefix:`${workspaceId}/${groupId}`,sans,keyAlgorithm:"ec",issuerAgentId:issuerId,
      issuanceProfileRef:"fixture",profileRevision:1,caEndpoint:"https://pebble:14000/dir",dnsProvider:"pebble-challtestsrv",dnsZone:"wildcard.test"}}}};
  const policyEngine=createPolicyEngine(loadPolicyConfig({...JSON.parse(fs.readFileSync(path.join(root,"config.json"))).policy,allowedTargetSelectors:["*"]}));
  async function issue() {
    const materialVersionId=crypto.randomUUID(),jobId=crypto.randomUUID();
    const publication={type:"vault-kv2",groupId,managementPeriodId:crypto.randomUUID(),materialVersionId,materialStoreRef:"customer",issuanceProfileRef:"fixture",profileRevision:1};
    const job={workspaceId,jobId,agentId:issuerId,publication,caEndpoint:"https://pebble:14000/dir",dnsProvider:"pebble-challtestsrv",dnsZone:"wildcard.test",sans,keyAlgorithm:"ecdsa",keySize:256};
    Object.assign(job,{certificateId:groupId,action:"renew",target:{type:"domain",reference:sans[0]},commandRef:"certbot",keyRotation:true,mode:"real"});
    const evidence=[];
    const recovered=await executeJob({job,jobId,claimId:crypto.randomUUID(),policyEngine,client:{reportEvidence:async body=>{assert.equal(JSON.stringify(body).includes("PRIVATE KEY"),false);evidence.push(body);}},leaseClient:{renewLease:async()=>({ok:true,leaseExpiresAt:new Date(Date.now()+60000).toISOString()})},executionContext:{execution:{enabled:true,dryRun:false,keysDir:path.join(root,"keys")},materialStores:stores},log:()=>{}});orders++;
    assert.equal(recovered.status,"succeeded",JSON.stringify(recovered));
    const session=publicationSession({job,stores,stateDir:root});
    const pem=recovered.publicationCertificatePem;
    const duplicate=await session.recover(async()=>{});assert.deepEqual(duplicate.publicationReceipt,recovered.publicationReceipt);
    assert.equal(duplicate.publicationReceipt.providerVersion,1);
    return {publication,receipt:recovered.publicationReceipt,pem};
  }
  const first=await issue();
  const ca=await fetch("https://pebble:15000/roots/0").then(r=>r.text());
  const caFile=path.join(root,"root-ca.pem");fs.writeFileSync(caFile,ca);
  const bindings={};
  function consumer(kind,port) {
    const bindingId=crypto.randomUUID(),dir=path.join(root,kind);protectDirectory(dir);
    bindings[bindingId]={workspaceId,groupId,agentId:`fixture-${kind}`,materialStoreRef:"customer",deploymentProfileRef:kind,
      profileRevision:1,authorizationRevision:1,verificationPolicy:"trust",reloadService:kind,
      target:{type:"endpoint",reference:kind,certPath:path.join(dir,"cert.pem"),keyPath:path.join(dir,"cert.pem.key")},
      probes:[{dialAddress:"127.0.0.1",port,sni:`${kind}.wildcard.test`,trustCaFile:caFile}]};
    let process;
    let failReload=false;
    const rolloutIds=new Map();
    if(kind==="nginx")fs.writeFileSync(path.join(dir,"service.conf"),`daemon off; master_process on; pid ${dir}/pid; error_log ${dir}/error.log; events {} http { access_log off; server { listen ${port} ssl; ssl_certificate ${dir}/cert.pem; ssl_certificate_key ${dir}/cert.pem.key; return 200 'fixture'; } }`);
    else fs.writeFileSync(path.join(dir,"service.conf"),`global\n  maxconn 32\ndefaults\n  mode tcp\n  timeout connect 2s\n  timeout client 2s\n  timeout server 2s\nfrontend fixture\n  bind 0.0.0.0:${port} ssl crt ${dir}/cert.pem\n`);
    const start=()=>{process=spawn(kind,kind==="nginx"?["-p",dir,"-c",path.join(dir,"service.conf")]:["-db","-f",path.join(dir,"service.conf")],{stdio:"ignore"});children.push(process);};
    const reload=async()=>{if(failReload){failReload=false;return false;}if(process){process.kill("SIGTERM");await new Promise((r)=>process.once("exit",r));}start();for(let i=0;i<50;i++){const ready=await new Promise(resolve=>{const socket=require("node:net").connect(port,"127.0.0.1",()=>{socket.destroy();resolve(true);});socket.on("error",()=>resolve(false));});if(ready)return process.exitCode===null;await sleep(100);}return false;};
    const deploy=(material,generation,checkLease=async()=>{},verificationOnly=false)=>executePinnedDeployment({job:{workspaceId,agentId:`fixture-${kind}`,materialDeployment:{bindingId,rolloutId:rolloutIds.get(generation)||rolloutIds.set(generation,crypto.randomUUID()).get(generation),groupId,
      materialVersionId:material.publication.materialVersionId,materialStoreRef:"customer",providerVersion:1,
      fingerprintSha256:material.receipt.fingerprintSha256,generation,deploymentProfileRef:kind,profileRevision:1,authorizationRevision:1,verificationPolicy:"trust",...(verificationOnly?{verificationOnly:true}:{})}},
      stores,bindings,stateDir:root,policyEngine,checkLease,reload,fixtureLoopbackHttp:true});
    return {bindingId,deploy,reload,failReload:()=>{failReload=true;},stop:async()=>{process?.kill("SIGTERM");if(process)await new Promise((r)=>process.once("exit",r));process=null;},probe:()=>probeListener(bindings[bindingId].probes[0],first.receipt.fingerprintSha256,"trust")};
  }
  const nginx=consumer("nginx",8443),haproxy=consumer("haproxy",9443);
  const n1=await nginx.deploy(first,1);assert.equal(n1.status,"succeeded",JSON.stringify(n1));
  const h1=await haproxy.deploy(first,1);assert.equal(h1.status,"succeeded",JSON.stringify(h1));
  const renewed=await issue();assert.notEqual(renewed.receipt.fingerprintSha256,first.receipt.fingerprintSha256);
  await haproxy.stop();
  assert.equal((await nginx.deploy(renewed,2)).status,"succeeded");
  assert.equal((await haproxy.probe()).servedVerified,false); // offline remains stale
  await assert.rejects(nginx.deploy(first,1),{code:"material_stale_generation"});
  assert.equal((await haproxy.deploy(renewed,2)).status,"succeeded");
  // Explicit rollback is a new generation referencing the old pinned object.
  assert.equal((await nginx.deploy(first,3)).status,"succeeded");
  assert.equal((await nginx.probe()).trustValidated,true);
  const wrong={...renewed.publication,workspaceId:crypto.randomUUID()};
  assert.throws(()=>createVaultStore(stores,wrong,{fixtureLoopbackHttp:true}),{code:"material_scope_denied"});
  await assert.rejects(nginx.deploy(renewed,4,async()=>{const e=new Error("material_lease_unavailable");e.code="material_lease_unavailable";throw e;}),{code:"material_lease_unavailable"});
  // Concrete drift and wrong-SNI trust checks.
  assert.equal((await nginx.probe()).servedVerified,true);
  const badSni=await probeListener({...bindings[nginx.bindingId].probes[0],sni:"unapproved.invalid"},first.receipt.fingerprintSha256,"trust");assert.equal(badSni.trustValidated,false);
  nginx.failReload();const uncertain=await nginx.deploy(renewed,4);assert.equal(uncertain.status,"orphaned_unknown_effect");
  const record=JSON.parse(readProtectedFile(path.join(root,"material-bindings",nginx.bindingId+".json")));
  const reconcile=()=>reconcilePinnedDeployment({job:{workspaceId,agentId:"fixture-nginx",materialDeployment:record.intent},bindings,stateDir:root,policyEngine});
  await assert.rejects(reconcile(),{code:"material_reconciliation_mismatch"});
  await nginx.reload();assert.equal((await reconcile()).reconciled,true);
  assert.equal((await nginx.deploy(renewed,4)).status,"succeeded");
  assert.equal((await nginx.probe()).servedVerified,false,"old fingerprint must expose drift");
  const installedPath=bindings[nginx.bindingId].target.certPath;
  const before=fs.readFileSync(installedPath);
  nginx.failReload(); // A read-only check must never consume this injected failure.
  assert.equal((await nginx.deploy(first,5,async()=>{},true)).status,"failed");
  assert.deepEqual(fs.readFileSync(installedPath),before);
  assert.equal((await nginx.deploy(renewed,6,async()=>{},true)).status,"succeeded");
  assert.deepEqual(fs.readFileSync(installedPath),before);
  assert.equal(orders,2);
  console.log(JSON.stringify({passed:true,acmeOrders:orders,consumers:["nginx","haproxy"],checks:["dns01","publication_recovery","pinned_versions","offline_consumer","renewal","stale_generation","rollback","cross_workspace","expired_lease","native_execute_job","wrong_sni","uncertain_reload","read_only_reconciliation","drift","verification_only_no_install_or_reload"]}));
}
main().catch((e)=>{console.error(e);process.exitCode=1;}).finally(()=>{for(const p of children)p.kill("SIGTERM");for(const p of proxies)p.close();});
