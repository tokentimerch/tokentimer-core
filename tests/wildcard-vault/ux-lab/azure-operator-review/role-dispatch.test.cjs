"use strict";
const {test}=require("node:test"), assert=require("node:assert/strict"), {dispatch,authorizeRole}=require("./role-dispatch.cjs");
const { readFileSync } = require("node:fs");
const { createRequire } = require("node:module");
const path = require("node:path");
const { runInNewContext } = require("node:vm");

test("the Azure role supervisor enrolls an issuer only on its own isolated role", async () => {
  const hostFile = path.join(__dirname, "customer-host.cjs");
  const source = readFileSync(hostFile, "utf8");
  // Load the control handler without starting the role supervisor or an agent.
  const handler = source.match(/^async function control\(body\) \{[\s\S]*?^\}/m);
  assert.ok(handler, "customer-host control handler missing");
  const calls = [];
  const env = { TT_UX_MATERIAL_PROVIDER: "azure-key-vault", TT_UX_ISOLATED_ROLE: "issuer" };
  const control = runInNewContext(`${handler[0]}\ncontrol`, {
    assert,
    process: { env },
    require: createRequire(hostFile),
    config: name => calls.push(["config", name]),
    startAgent: (name, token) => calls.push(["enroll", name, token]),
  }, { filename: hostFile });

  const enrollment = { action: "enroll", name: "issuer", token: "fixture-enrollment" };
  await control(enrollment);
  assert.deepEqual(calls, [["config", "issuer"], ["enroll", "issuer", "fixture-enrollment"]]);
  env.TT_UX_ISOLATED_ROLE = "consumer";
  await assert.rejects(control(enrollment), /wrong isolated role/);
  assert.equal(calls.length, 2);
});

test("routes issuer and consumer actions separately and refuses cross-role actions", async () => {
  const calls=[], send=async (role,body)=>(calls.push({role,action:body.action}),{ok:true});
  await dispatch({action:"enroll",name:"issuer"},send);
  await dispatch({action:"tls-proof",name:"nginx"},send);
  assert.deepEqual(calls,[{role:"issuer",action:"enroll"},{role:"consumer",action:"tls-proof"}]);
  await assert.rejects(dispatch({action:"tls-proof",name:"issuer"},send),/unsupported action/);
  await assert.rejects(dispatch({action:"enroll",name:"cancel-issuer"},send),/unsupported role/);
  assert.throws(()=>authorizeRole({action:"enroll",name:"issuer"},"consumer"),/wrong isolated role/);
});
test("package proof requires both role inventories and the same archive",async()=>{
 const send=async role=>({role,candidateSha:"a".repeat(40),packageSha256:"b".repeat(64),packageFilesUnmodified:true});
 const proof=await dispatch({action:"package-proof",name:"issuer"},send);
 assert.equal(proof.roleProofs.length,2);
 await assert.rejects(dispatch({action:"package-proof",name:"issuer"},async role=>({...await send(role),packageSha256:role==="issuer"?"b".repeat(64):"c".repeat(64)})));
});
