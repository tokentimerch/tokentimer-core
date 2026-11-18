"use strict";
// Docker daemon access is a privileged host boundary. Exact immutable container
// IDs and Compose labels are rechecked before each role-local control request.
const assert = require("node:assert/strict"), { execFileSync } = require("node:child_process");
const { assertRoleMounts } = require("./azure-isolated-role.cjs");
const CLIENT = `const http=require('node:http');let s='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>{const r=http.request({host:'127.0.0.1',port:8085,path:'/',method:'POST',headers:{'Content-Type':'application/json'}},v=>{let b='';v.on('data',c=>{b+=c;if(b.length>65536)r.destroy()});v.on('end',()=>{process.stdout.write(JSON.stringify({status:v.statusCode,body:b}))})});r.on('error',()=>process.exit(1));r.end(s)});`;
function createDockerSender({ project, issuerContainerId, consumerContainerId, roleMounts, execute = (args,options={}) => execFileSync("docker",args,{encoding:"utf8",timeout:30000,maxBuffer:131072,...options}) }) {
  assert.match(project || "", /^tt-wildcard-ux-qual-[a-z0-9-]+$/);
  for (const id of [issuerContainerId, consumerContainerId]) assert.match(id || "", /^[a-f0-9]{64}$/);
  assert.notEqual(issuerContainerId, consumerContainerId);
  return async (role, body) => {
    assert.ok(["issuer", "consumer"].includes(role));
    const id = role === "issuer" ? issuerContainerId : consumerContainerId;
    const records = JSON.parse(execute(["inspect",id])); assert.ok(Array.isArray(records) && records.length === 1);
    const labels = records[0].Config?.Labels;
    assert.equal(records[0].Id,id); assert.equal(labels?.["com.docker.compose.project"],project);
    assert.equal(labels?.["com.docker.compose.service"],role);
    if (roleMounts) assertRoleMounts({ ...roleMounts, record: records[0], project, role });
    const payload = JSON.stringify(body); assert.ok(Buffer.byteLength(payload) <= 65536);
    const reply = JSON.parse(execute(["exec","--interactive",id,"node","-e",CLIENT], {input:payload}));
    assert.equal(reply.status,200,"role control refused");
    return JSON.parse(reply.body);
  };
}
module.exports = { createDockerSender };
