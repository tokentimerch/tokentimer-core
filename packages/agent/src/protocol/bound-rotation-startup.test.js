"use strict";

const test=require("node:test"), assert=require("node:assert/strict"), crypto=require("node:crypto"), fs=require("node:fs"), https=require("node:https"), net=require("node:net"), path=require("node:path");
const {Readable}=require("node:stream");
const {receiveCredentialPipeBootstrap}=require("./credential-pipe");
const {recoverBoundRotationCredential}=require("./bound-rotation-startup");
const domain=Buffer.from("TokenTimer-Credential-Pipe-Server-v1\0");
const token="ttagent_"+"1".repeat(16)+"_"+"2".repeat(64);
const identity={id:"11111111-1111-4111-8111-111111111111",agentId:"agent-a",workspaceId:"22222222-2222-4222-8222-222222222222"};

test("bound startup refuses an already-cancelled operation before contacting the pipe", async()=>{
  const controller=new AbortController();controller.abort();
  await assert.rejects(recoverBoundRotationCredential({session:null,enrolledIdentity:identity,origin:"https://example.test",caBundlePem:"test",signal:controller.signal}),/bound rotation identity unavailable/);
});

test("bound startup refuses a live IPv6 endpoint before opening the credential pipe", async t=>{
  if(process.platform!=="win32") return t.skip("requires Windows named pipes");
  let networkConnections=0, pipeConnections=0;
  const ipv6=net.createServer(socket=>{networkConnections++;socket.destroy();});
  try { await new Promise((resolve,reject)=>ipv6.listen(0,"::1",resolve).once("error",reject)); }
  catch (_error) { return t.skip("IPv6 loopback unavailable"); }
  const name=`\\\\.\\pipe\\TokenTimerCredential-${crypto.randomBytes(32).toString("hex")}`,key=crypto.randomBytes(32),prefix=Buffer.alloc(2);
  prefix.writeUInt16BE(Buffer.byteLength(name));
  const session=await receiveCredentialPipeBootstrap(Readable.from([Buffer.concat([prefix,Buffer.from(name),key])]));
  const pipe=net.createServer(socket=>{pipeConnections++;socket.destroy();});
  await new Promise((resolve,reject)=>pipe.listen(name,resolve).once("error",reject));
  try {
    await assert.rejects(recoverBoundRotationCredential({session,enrolledIdentity:identity,origin:`https://[::1]:${ipv6.address().port}`,caBundlePem:"not used"}),/bound rotation identity unavailable/);
    assert.equal(pipeConnections,0);assert.equal(networkConnections,0);
  } finally {session.dispose();key.fill(0);await Promise.all([new Promise(resolve=>pipe.close(resolve)),new Promise(resolve=>ipv6.close(resolve))]);}
});

test("bound startup requires matching protected context, TLS CA and remote workspace", async t=>{
  const dir=process.env.TT_TEST_TLS_DIR;
  if(process.platform!=="win32" || !dir) return t.skip("requires Windows and disposable TLS fixture");
  const read=name=>fs.readFileSync(path.join(dir,name),"utf8"), ca=read("ca.pem"), wrong=read("wrong.pem");
  let httpCalls=0, remoteIdentity=identity;
  const api=https.createServer({key:read("leaf.key"),cert:read("leaf.pem")},(req,res)=>{
    httpCalls++; if(req.headers.authorization!==`Bearer ${token}`){res.writeHead(401).end();return;}
    req.resume();req.on("end",()=>{res.setHeader("content-type","application/json");res.end(JSON.stringify(remoteIdentity));});
  });
  await new Promise((resolve,reject)=>api.listen(0,"127.0.0.1",resolve).once("error",reject));
  const origin=`https://127.0.0.1:${api.address().port}`;
  async function run(enrolledIdentity, expectedCA, suppliedCA, remote) {
    remoteIdentity=remote;
    const name=`\\\\.\\pipe\\TokenTimerCredential-${crypto.randomBytes(32).toString("hex")}`, key=crypto.randomBytes(32);
    const prefix=Buffer.alloc(2);prefix.writeUInt16BE(Buffer.byteLength(name));
    const session=await receiveCredentialPipeBootstrap(Readable.from([Buffer.concat([prefix,Buffer.from(name),key])]));
    const binding={...identity,origin,caHash:crypto.createHash("sha256").update(expectedCA).digest("hex")};
    let data=Buffer.alloc(0),stage=0;
    const pipe=net.createServer(socket=>{socket.on("error",()=>{});socket.on("data",chunk=>{
      data=Buffer.concat([data,chunk]);
      if(stage===0 && data.length>=32){const challenge=data.subarray(0,32);data=data.subarray(32);stage=1;socket.write(crypto.createHmac("sha256",key).update(domain).update(challenge).digest());}
      if(stage===1 && data.length>=4 && data.length>=4+data.readUInt32BE(0)){
        stage=2; const request=JSON.parse(data.subarray(4,4+data.readUInt32BE(0)).toString());
        if(JSON.stringify(request.binding)!==JSON.stringify(binding)){socket.destroy();return;}
        const reply=Buffer.from(JSON.stringify({credential:token})),header=Buffer.alloc(4);header.writeUInt32BE(reply.length);socket.end(Buffer.concat([header,reply]));
      }
    });});
    await new Promise((resolve,reject)=>pipe.listen(name,resolve).once("error",reject));
    try{return await recoverBoundRotationCredential({session,enrolledIdentity,origin,caBundlePem:suppliedCA});}
    finally{session.dispose();key.fill(0);await new Promise(resolve=>pipe.close(resolve));}
  }
  try {
    assert.equal(await run(identity,ca,ca,identity),token);
    await assert.rejects(run({...identity,workspaceId:"33333333-3333-4333-8333-333333333333"},ca,ca,identity));
    await assert.rejects(run(identity,ca,wrong,identity));
    await assert.rejects(run(identity,wrong,wrong,identity)); // CA pin matches store; TLS rejects server before HTTP.
    assert.equal(httpCalls,1);
    await assert.rejects(run(identity,ca,ca,{...identity,workspaceId:"33333333-3333-4333-8333-333333333333"}));
    assert.equal(httpCalls,2);
  } finally { await new Promise(resolve=>api.close(resolve)); }
});
