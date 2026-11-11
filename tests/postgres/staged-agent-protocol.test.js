"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const net = require("node:net");
const crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const { runStagedAgentProtocol } = require("../../scripts/staged-agent-protocol.cjs");
const { createApiFixture } = require("../e2e/helpers/certops-api-fixture");

test("real Core API signs and persists the complete staged protocol journey", {timeout:150000}, async () => {
  assert.equal(process.env.TT_RELEASE_UPGRADE_DISPOSABLE,"1","Explicit disposable PostgreSQL required");
  assert.match(process.env.DB_NAME || "",/^core_published_upgrade.*_test$/,"Owned acceptance server required");
  const { Client } = require("pg");
  const admin = new Client();
  const root=path.resolve(__dirname,"../..");
  const database=`core_staged_protocol_${crypto.randomUUID().replaceAll('-','')}_test`;
  const previousDbName=process.env.DB_NAME;
  const previousDisposable=process.env.CERTOPS_CSR_DISPOSABLE_STACK;
  let api,fixture,created=false;
  try {
    await admin.connect();
    await admin.query(`CREATE DATABASE "${database}"`);created=true;
    process.env.DB_NAME=database;
    process.env.CERTOPS_CSR_DISPOSABLE_STACK="1";
    const port=await new Promise(resolve=>{const server=net.createServer();server.listen(0,"127.0.0.1",()=>{const value=server.address().port;server.close(()=>resolve(value));});});
    const baseUrl=`http://127.0.0.1:${port}`;
    const env={...process.env,NODE_ENV:"test",CERTOPS_ENABLED:"true",PORT:String(port),HOST:"127.0.0.1",SESSION_SECRET:crypto.randomBytes(32).toString("hex"),CERTOPS_SIGNING_ENCRYPTION_KEY:crypto.randomBytes(32).toString("hex"),CERTOPS_REGISTRATION_ENCRYPTION_KEY:crypto.randomBytes(32).toString("hex"),CREDENTIAL_PEPPER:crypto.randomBytes(32).toString("hex"),PUBLIC_APP_URL:baseUrl,ADMIN_EMAIL:"disposable-protocol@example.test",ADMIN_PASSWORD:"SyntheticFixture-LongPassphrase-16!",ADMIN_NAME:"Disposable protocol fixture"};
    const migrations=spawnSync(process.execPath,[path.join(root,"apps/api/migrations/migrate.js")],{cwd:root,env,encoding:"utf8",timeout:90000,maxBuffer:8*1024*1024});
    assert.equal(migrations.status,0,"Fresh protocol database migrations failed");
    api=spawn(process.execPath,["--max-old-space-size=384",path.join(root,"apps/api/index.js")],{cwd:root,env,stdio:["ignore","ignore","ignore"]});
    let startupError;api.once("error",error=>{startupError=error;});
    let ready=false;
    for(let i=0;i<100;i++){
      assert.equal(Boolean(startupError),false,"Owned API failed to launch");
      assert.equal(api.exitCode,null,"Owned API exited before readiness");
      try{if((await fetch(`${baseUrl}/health`,{signal:AbortSignal.timeout(2000)})).ok){ready=true;break;}}catch{}
      await new Promise(resolve=>setTimeout(resolve,250));
    }
    assert.equal(ready,true,"Owned API health deadline exceeded");
    fixture=await createApiFixture(baseUrl);
    const cookies=new Map();
    const session=async(route,method="GET",body,csrf)=>{
      const response=await fetch(new URL(route,baseUrl),{method,redirect:"error",signal:AbortSignal.timeout(15000),headers:{"content-type":"application/json",cookie:[...cookies].map(([key,value])=>`${key}=${value}`).join("; "),...(csrf?{"x-csrf-token":csrf}:{})},...(body?{body:JSON.stringify(body)}:{})});
      for(const value of response.headers.getSetCookie()){const first=value.split(";",1)[0],i=first.indexOf("=");cookies.set(first.slice(0,i),first.slice(i+1));}
      return{status:response.status,body:await response.json()};
    };
    let csrf=(await session("/api/csrf-token")).body.csrfToken;
    assert.equal((await session("/auth/login","POST",{email:fixture.email,password:fixture.password},csrf)).status,200,"Fixture login failed");
    csrf=(await session("/api/csrf-token")).body.csrfToken;
    const result=await runStagedAgentProtocol({baseUrl,workspaceId:fixture.workspaceId,sessionCookie:[...cookies].map(([key,value])=>`${key}=${value}`).join("; "),csrfToken:csrf,disposable:true,edition:"core"});
    assert.equal(result.passed,8);
    assert.equal(result.cleanup,"owned-agent-retired-and-bootstrap-revoked");
    console.log(JSON.stringify(result));
  } finally {
    try{if(fixture)await fixture.cleanup();}
    finally{
      if(api&&api.exitCode===null){api.kill("SIGTERM");await new Promise(resolve=>{api.once("exit",resolve);setTimeout(()=>{api.kill("SIGKILL");resolve();},5000).unref();});}
      if(created){await admin.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()",[database]);await admin.query(`DROP DATABASE "${database}"`);}
      await admin.end();
      process.env.DB_NAME=previousDbName;
      if(previousDisposable===undefined)delete process.env.CERTOPS_CSR_DISPOSABLE_STACK;else process.env.CERTOPS_CSR_DISPOSABLE_STACK=previousDisposable;
    }
  }
});
