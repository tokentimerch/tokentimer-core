/**
 * Use real local HTTPS sockets to test Pebble fixture readiness trust and host validation.
 * Generated temporary certificates cover the owned CA, unrelated CA and wrong SAN.
 * These are readiness regressions, not ACME issuance or public-CA qualification. */
"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),https=require("node:https"),{spawnSync}=require("node:child_process");
const {probeHttpsReady}=require("../../scripts/certops-real-acme");

test("owned HTTPS readiness requires the actual certificate and matching server identity",{timeout:30000},async()=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-readiness-tls-"));
  const servers=[];
  const certificate=(name,san)=>{
    const cert=path.join(directory,`${name}.crt`),key=path.join(directory,`${name}.key`);
    const result=spawnSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",key,"-out",cert,"-days","1","-subj",`/CN=${name}`,"-addext",`subjectAltName=${san}`],{stdio:"ignore",timeout:10000});
    assert.equal(result.status,0,"OpenSSL must generate the owned public test authority");
    return {cert:fs.readFileSync(cert),key:fs.readFileSync(key)};
  };
  const listen=async material=>{
    const server=https.createServer(material,(_request,response)=>response.writeHead(200).end("ready"));servers.push(server);
    await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve);});
    return `https://127.0.0.1:${server.address().port}/dir`;
  };
  try{
    const owned=certificate("owned","DNS:localhost,IP:127.0.0.1"),other=certificate("other","DNS:localhost,IP:127.0.0.1"),wrongHost=certificate("wrong-host","DNS:other.invalid");
    const endpoint=await listen(owned);
    assert.equal(await probeHttpsReady(endpoint,owned.cert),true);
    assert.equal(await probeHttpsReady(endpoint,other.cert),false,"An unrelated trust anchor must not qualify readiness");
    assert.equal(await probeHttpsReady(await listen(wrongHost),wrongHost.cert),false,"Even an explicitly trusted certificate must match the actual peer identity");
    assert.throws(()=>probeHttpsReady("https://example.invalid/dir",owned.cert),/loopback-only/);
  }finally{
    for(const server of servers){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
    fs.rmSync(directory,{recursive:true,force:true});
  }
});
