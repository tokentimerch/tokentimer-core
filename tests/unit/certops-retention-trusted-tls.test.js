"use strict";
/* Real loopback TLS regression for the retention fixture's shared probe adapter.
 * OpenSSL creates only owned temporary test CA/leaf files; no OS trust, IIS,
 * SCM or CNG state is changed. Positive authentication and wrong-name/root
 * refusals catch argument drift without weakening certificate verification. */
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),crypto=require("node:crypto"),tls=require("node:tls"),{spawnSync}=require("node:child_process");
const {createRetentionTlsProbe}=require("../../packages/agent/scripts/host/retention-fixture"),{servedThumbprint}=require("../../packages/agent/scripts/host/iis-fixture");
test("retention probe authenticates owned CA and SAN and rejects foreign trust/name",async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),"certops-retention-tls-"));let server;const sockets=new Set();
 const openssl=process.platform==="win32"&&fs.existsSync("C:/Program Files/Git/usr/bin/openssl.exe")?"C:/Program Files/Git/usr/bin/openssl.exe":"openssl";
 const run=args=>{const result=spawnSync(openssl,args,{cwd:directory,encoding:"utf8",timeout:30000});assert.ifError(result.error);assert.equal(result.status,0,"Owned TLS certificate generation failed");};
 try{
 for(const name of ["owned","foreign"])run(["req","-x509","-newkey","rsa:2048","-nodes","-keyout",`${name}.key`,"-out",`${name}.pem`,"-days","1","-subj",`/CN=CertOps ${name} fixture CA`,"-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign"]);
 run(["req","-new","-newkey","rsa:2048","-nodes","-keyout","leaf.key","-out","leaf.csr","-subj","/CN=certops-host.invalid"]);fs.writeFileSync(path.join(directory,"leaf.ext"),"subjectAltName=DNS:certops-host.invalid\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n");run(["x509","-req","-in","leaf.csr","-CA","owned.pem","-CAkey","owned.key","-set_serial","1","-days","1","-extfile","leaf.ext","-out","leaf.pem"]);
 const caPem=fs.readFileSync(path.join(directory,"owned.pem"),"utf8"),leaf=fs.readFileSync(path.join(directory,"leaf.pem")),thumbprint=new crypto.X509Certificate(leaf).fingerprint.replace(/:/g,"");
 server=tls.createServer({key:fs.readFileSync(path.join(directory,"leaf.key")),cert:leaf},socket=>socket.end());server.on("tlsClientError",()=>{});server.on("connection",socket=>{sockets.add(socket);socket.once("close",()=>sockets.delete(socket));});await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve);});const port=server.address().port;
 await createRetentionTlsProbe({caPem})(port,thumbprint);assert.equal(await servedThumbprint(port,"certops-host.invalid",caPem),thumbprint);
 await assert.rejects(servedThumbprint(port,"wrong-name.invalid",caPem),error=>error.code==="ERR_TLS_CERT_ALTNAME_INVALID");await assert.rejects(servedThumbprint(port,"certops-host.invalid",fs.readFileSync(path.join(directory,"foreign.pem"),"utf8")));assert.throws(()=>createRetentionTlsProbe({}));assert.throws(()=>createRetentionTlsProbe({caPem:leaf.toString()}));
 }finally{for(const socket of sockets)socket.destroy();if(server?.listening)await new Promise(resolve=>server.close(resolve));fs.rmSync(directory,{recursive:true,force:true});}
});
