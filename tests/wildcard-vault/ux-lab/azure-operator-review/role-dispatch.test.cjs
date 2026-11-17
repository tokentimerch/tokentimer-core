"use strict";
const {test}=require("node:test"), assert=require("node:assert/strict"), {dispatch,authorizeRole}=require("./role-dispatch.cjs");
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
