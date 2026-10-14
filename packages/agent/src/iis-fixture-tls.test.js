"use strict";
const {test}=require("node:test");
const assert=require("node:assert/strict");
const fs=require("node:fs"),path=require("node:path"),tls=require("node:tls"),crypto=require("node:crypto");
const {servedThumbprint}=require("../scripts/host/iis-fixture");
const fixture=name=>fs.readFileSync(path.join(__dirname,"verify/fixtures",name),"utf8");
async function withServer(certificate,key,check){
  const server=tls.createServer({cert:fixture(certificate),key:fixture(key)},socket=>socket.end());
  server.on("tlsClientError",()=>{});
  await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve);});
  try{await check(server.address().port);}finally{await new Promise(resolve=>server.close(resolve));}
}
test("IIS fixture TLS probe authenticates a trusted certificate and its requested DNS name",async()=>{
  await withServer("leaf.crt.pem","leaf.key.pem",async port=>{
    const observed=await servedThumbprint(port,"valid.example.com",fixture("ca.crt.pem"));
    assert.equal(observed,new crypto.X509Certificate(fixture("leaf.crt.pem")).fingerprint.replace(/:/g,""));
  });
});
test("IIS fixture TLS probe trusts only the explicitly supplied self-signed fixture leaf",async()=>{
  await withServer("selfsigned.crt.pem","leaf.key.pem",async port=>{
    const observed=await servedThumbprint(port,"valid.example.com",fixture("selfsigned.crt.pem"));
    assert.equal(observed,new crypto.X509Certificate(fixture("selfsigned.crt.pem")).fingerprint.replace(/:/g,""));
  });
});
test("IIS fixture TLS probe rejects a trusted signer with the wrong SAN",async()=>{
  await withServer("wrong-san.crt.pem","wrong-san.key.pem",async port=>{
    await assert.rejects(servedThumbprint(port,"valid.example.com",fixture("ca.crt.pem")),error=>error.code==="ERR_TLS_CERT_ALTNAME_INVALID");
  });
});
test("IIS fixture TLS probe rejects a matching name signed by an untrusted issuer",async()=>{
  await withServer("leaf.crt.pem","leaf.key.pem",async port=>{
    await assert.rejects(servedThumbprint(port,"valid.example.com",fixture("selfsigned.crt.pem")),error=>["UNABLE_TO_VERIFY_LEAF_SIGNATURE","UNABLE_TO_GET_ISSUER_CERT_LOCALLY"].includes(error.code));
  });
});
test("IIS fixture TLS probe refuses an omitted trust anchor before opening a connection",async()=>{
  await assert.rejects(servedThumbprint(1,"valid.example.com"),/Expected values to be strictly equal/);
});
