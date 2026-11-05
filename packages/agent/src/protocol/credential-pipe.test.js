"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const net = require("node:net");
const { spawn } = require("node:child_process");
const { Readable } = require("node:stream");
const { receiveCredentialPipeBootstrap, sendCredentialPipeRequest } = require("./credential-pipe");

const pipeName = () => `\\\\.\\pipe\\TokenTimerCredential-${crypto.randomBytes(32).toString("hex")}`;
const domain = Buffer.from("TokenTimer-Credential-Pipe-Server-v1\0");

async function makeSession(name, key) {
  const prefix = Buffer.alloc(2); prefix.writeUInt16BE(Buffer.byteLength(name));
  return receiveCredentialPipeBootstrap(Readable.from([Buffer.concat([prefix, Buffer.from(name), key])]));
}

test("bootstrap uses bounded dedicated stdin and keeps capability non-enumerable", async () => {
  const key = crypto.randomBytes(32), name = pipeName();
  const session = await makeSession(name,key);
  assert.equal(session.name,name);
  assert.equal(session.key,undefined);
  assert.equal(Object.keys(session).includes("dispose"),false);
  await assert.rejects(receiveCredentialPipeBootstrap(Readable.from([Buffer.alloc(547)])), /credential pipe unavailable/);
  session.dispose();
  await assert.rejects(sendCredentialPipeRequest(session,{command:"read"}), /credential pipe unavailable/);
  key.fill(0);
});

test("pipe sends a credential only after authenticating the server", async t => {
  if (process.platform !== "win32") return t.skip("Windows named pipe test");
  const name = pipeName(), key = crypto.randomBytes(32), session = await makeSession(name,key);
  const secret = "ttagent_"+"1".repeat(16)+"_"+"2".repeat(64);
  let received = Buffer.alloc(0);
  const server = net.createServer(socket => {
    let phase = 0;
    socket.on("data", data => {
      received = Buffer.concat([received,data]);
      if (phase === 0 && received.length >= 32) {
        const challenge = received.subarray(0,32); received = received.subarray(32); phase = 1;
        socket.write(crypto.createHmac("sha256",key).update(domain).update(challenge).digest());
      }
      if (phase === 1 && received.length >= 4 && received.length >= 4 + received.readUInt32BE(0)) {
        const body = JSON.parse(received.subarray(4,4+received.readUInt32BE(0)).toString("utf8"));
        assert.equal(body.record.credential,secret);
        phase = 2;
        const reply=Buffer.from('{"state":"prepared"}'); const hdr=Buffer.alloc(4); hdr.writeUInt32BE(reply.length); socket.end(Buffer.concat([hdr,reply]));
      }
    });
  });
  await new Promise((resolve,reject)=>server.listen(name,resolve).once("error",reject));
  try { assert.deepEqual(await sendCredentialPipeRequest(session,{command:"prepare",record:{version:1,operation:"a".repeat(32),credential:secret}}),{state:"prepared"}); }
  finally { session.dispose(); key.fill(0); await new Promise(resolve=>server.close(resolve)); }
});

test("a fake server cannot receive a credential without a valid proof", async t => {
  if (process.platform !== "win32") return t.skip("Windows named pipe test");
  const name=pipeName(), key=crypto.randomBytes(32), session=await makeSession(name,key);
  const secret="ttagent_"+"3".repeat(16)+"_"+"4".repeat(64);
  let received=Buffer.alloc(0);
  const server=net.createServer(socket=>socket.on("data",data=>{
    received=Buffer.concat([received,data]);
    if (received.length === 32) socket.write(Buffer.alloc(32));
  }));
  await new Promise((resolve,reject)=>server.listen(name,resolve).once("error",reject));
  try {
    await assert.rejects(sendCredentialPipeRequest(session,{command:"prepare",record:{version:1,operation:"a".repeat(32),credential:secret}}), error => {
      assert.equal(error.message,"credential pipe unavailable");
      assert.equal(String(error).includes(secret),false);
      return true;
    });
    assert.equal(received.length,32);
    assert.equal(received.includes(Buffer.from(secret)),false);
  } finally { session.dispose(); key.fill(0); await new Promise(resolve=>server.close(resolve)); }
});

test("a pipe impersonator after host process death receives no credential", async t => {
  if (process.platform !== "win32") return t.skip("Windows named pipe test");
  const name=pipeName(), key=crypto.randomBytes(32), session=await makeSession(name,key);
  const secret="ttagent_"+"5".repeat(16)+"_"+"6".repeat(64);
  const host=spawn(process.execPath,["-e", "require('node:net').createServer(()=>{}).listen(process.argv[1],()=>process.stdout.write('ready'))",name],{stdio:["ignore","pipe","pipe"],windowsHide:true});
  await new Promise((resolve,reject)=>{ host.stdout.once("data",resolve); host.once("error",reject); host.once("exit",()=>reject(new Error("host stopped before ready"))); });
  const exited=new Promise(resolve=>host.once("exit",resolve));
  host.kill(); await exited;
  let received=Buffer.alloc(0);
  const impostor=net.createServer(socket=>socket.on("data",data=>{ received=Buffer.concat([received,data]); if(received.length===32) socket.write(Buffer.alloc(32)); }));
  await new Promise((resolve,reject)=>impostor.listen(name,resolve).once("error",reject));
  try {
    await assert.rejects(sendCredentialPipeRequest(session,{command:"prepare",record:{version:1,operation:"a".repeat(32),credential:secret}}),/credential pipe unavailable/);
    assert.equal(received.length,32);
    assert.equal(received.includes(Buffer.from(secret)),false);
  } finally { session.dispose(); key.fill(0); await new Promise(resolve=>impostor.close(resolve)); }
});

test("authenticated responses must match the operation, credential hash and phase", async t => {
  if (process.platform !== "win32") return t.skip("Windows named pipe test");
  const secret="ttagent_"+"7".repeat(16)+"_"+"8".repeat(64), operation="b".repeat(32);
  const hash=crypto.createHash("sha256").update(secret).digest("hex");
  const scenarios=[
    { reply:{version:1,operation,credential:secret}, expected:true },
    { reply:{version:1,operation:"c".repeat(32),credential:secret}, expected:false },
    { reply:{version:1,operation,credential:"ttagent_"+"7".repeat(16)+"_"+"9".repeat(64)}, expected:false },
    { reply:{version:1,operation,credential:secret,extra:1}, expected:false },
    { reply:{state:"prepared"}, expected:false },
  ];
  for (const scenario of scenarios) {
    const name=pipeName(), key=crypto.randomBytes(32), session=await makeSession(name,key);
    let received=Buffer.alloc(0), phase=0;
    const server=net.createServer(socket=>socket.on("data",data=>{
      received=Buffer.concat([received,data]);
      if (phase===0 && received.length>=32) { const challenge=received.subarray(0,32); received=received.subarray(32); phase=1; socket.write(crypto.createHmac("sha256",key).update(domain).update(challenge).digest()); }
      if (phase===1 && received.length>=4 && received.length>=4+received.readUInt32BE(0)) {
        phase=2; const reply=Buffer.from(JSON.stringify(scenario.reply)); const header=Buffer.alloc(4); header.writeUInt32BE(reply.length); socket.end(Buffer.concat([header,reply]));
      }
    }));
    await new Promise((resolve,reject)=>server.listen(name,resolve).once("error",reject));
    try {
      const result=sendCredentialPipeRequest(session,{command:"read"},{expectedOperationId:operation,expectedCandidateHash:hash});
      if (scenario.expected) assert.deepEqual(await result,scenario.reply);
      else await assert.rejects(result,/credential pipe unavailable/);
    } finally { session.dispose(); key.fill(0); await new Promise(resolve=>server.close(resolve)); }
  }
});

test("socket failure after proof is sanitized and does not escape as an unhandled error", async t => {
  if (process.platform !== "win32") return t.skip("Windows named pipe test");
  const name=pipeName(), key=crypto.randomBytes(32), session=await makeSession(name,key);
  const secret="ttagent_"+"a".repeat(16)+"_"+"b".repeat(64);
  const server=net.createServer(socket=>socket.once("data",challenge=>{
    socket.write(crypto.createHmac("sha256",key).update(domain).update(challenge).digest(),()=>socket.destroy());
  }));
  await new Promise((resolve,reject)=>server.listen(name,resolve).once("error",reject));
  try {
    await assert.rejects(sendCredentialPipeRequest(session,{command:"prepare",record:{version:1,operation:"c".repeat(32),credential:secret}}),error=>{
      assert.equal(error.message,"credential pipe unavailable"); assert.equal(String(error).includes(secret),false); return true;
    });
  } finally { session.dispose(); key.fill(0); await new Promise(resolve=>server.close(resolve)); }
});

test("disposing an in-flight session refuses a proof made with the cleared key and sends no credential", async t => {
  if (process.platform !== "win32") return t.skip("Windows named pipe test");
  const name=pipeName(), key=crypto.randomBytes(32), session=await makeSession(name,key);
  const secret="ttagent_"+"a".repeat(16)+"_"+"b".repeat(64);
  let received=Buffer.alloc(0), releaseProof, observed;
  const seenChallenge=new Promise(resolve=>{observed=resolve;});
  const proofGate=new Promise(resolve=>{releaseProof=resolve;});
  const server=net.createServer(socket=>{ socket.on("error", () => {}); socket.on("data",data=>{
    received=Buffer.concat([received,data]);
    if (received.length===32) {
      const challenge=Buffer.from(received); observed();
      proofGate.then(()=>{
        if (!socket.destroyed) socket.write(crypto.createHmac("sha256",Buffer.alloc(32)).update(domain).update(challenge).digest());
      });
    } else if (received.length>32) {
      const reply=Buffer.from('{"state":"prepared"}'), header=Buffer.alloc(4); header.writeUInt32BE(reply.length); socket.end(Buffer.concat([header,reply]));
    }
  }); });
  await new Promise((resolve,reject)=>server.listen(name,resolve).once("error",reject));
  try {
    const request=sendCredentialPipeRequest(session,{command:"prepare",record:{version:1,operation:"a".repeat(32),credential:secret}});
    await seenChallenge;
    session.dispose(); releaseProof();
    await assert.rejects(request,/credential pipe unavailable/);
    assert.equal(received.length,32);
    assert.equal(received.includes(Buffer.from(secret)),false);
  } finally { releaseProof(); session.dispose(); key.fill(0); await new Promise(resolve=>server.close(resolve)); }
});
