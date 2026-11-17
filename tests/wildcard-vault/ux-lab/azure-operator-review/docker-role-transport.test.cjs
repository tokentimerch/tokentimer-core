"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict"),{createDockerSender}=require("./docker-role-transport.cjs");
test("Docker role transport pins immutable IDs and matching ownership labels",async()=>{
  const project="tt-wildcard-ux-qual-test", issuer="a".repeat(64), consumer="b".repeat(64),calls=[];
  const execute=(args,options={})=>{calls.push(args); if(args[0]==="inspect")return JSON.stringify([{Id:args[1],Config:{Labels:{"com.docker.compose.project":project,"com.docker.compose.service":args[1]===issuer?"issuer":"consumer"}}}]); return JSON.stringify({status:200,body:'{"ok":true}'});};
  const send=createDockerSender({project,issuerContainerId:issuer,consumerContainerId:consumer,execute});
  assert.deepEqual(await send("consumer",{name:"nginx",action:"tls-proof"}),{ok:true});
  assert.equal(calls[1][2],consumer);
  const bad=createDockerSender({project,issuerContainerId:issuer,consumerContainerId:consumer,execute:()=>JSON.stringify([{Id:consumer,Config:{Labels:{"com.docker.compose.project":"foreign","com.docker.compose.service":"consumer"}}}])});
  await assert.rejects(bad("consumer",{}));
});
