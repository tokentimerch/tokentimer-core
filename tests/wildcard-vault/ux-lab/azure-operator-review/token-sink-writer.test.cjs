"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {createTokenSink}=require("./token-sink-writer.cjs");
test("refresh atomically replaces a role-local sink without returning credentials",async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"tt-token-sink-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 let token="first"; const sink=createTokenSink({directory:dir,acquire:async()=>({accessToken:token,expiresOn:10000}),prepareOwner:()=>{},now:()=>100});
 assert.deepEqual(await sink.refresh(),{expiresOn:10000});
 assert.equal(JSON.parse(fs.readFileSync(path.join(dir,"token.json"))).accessToken,"first");
 token="second";await sink.refresh();assert.equal(JSON.parse(fs.readFileSync(path.join(dir,"token.json"))).accessToken,"second");
 assert.deepEqual(fs.readdirSync(dir),["token.json"]);
});
test("expired credentials never replace a valid sink",async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),"tt-token-expired-"));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 fs.writeFileSync(path.join(dir,"token.json"),"prior");
 const sink=createTokenSink({directory:dir,acquire:async()=>({accessToken:"secret",expiresOn:10}),prepareOwner:()=>{},now:()=>100});
 await assert.rejects(sink.refresh(),/unexpired/);assert.equal(fs.readFileSync(path.join(dir,"token.json"),"utf8"),"prior");
});
