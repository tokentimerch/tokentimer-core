"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { normalizeIisAbsenceProof, persistIisAbsenceProofBatch } = require("../../apps/api/services/certops/iisAbsenceProof");

const now = Date.now();
const valid = { evidenceId:"proof-1", targetHost:"pilot.example.test", site:"Default Web Site", port:443, address:"192.0.2.10", fingerprintSha256:"a".repeat(64), thumbprint:"b".repeat(40), observedAt:new Date(now).toISOString() };
test("IIS proofs reject expired, future, ambiguous and malformed targets", () => {
  assert.equal(normalizeIisAbsenceProof(valid,now).address,"192.0.2.10");
  for (const patch of [{address:"0.0.0.0"},{address:"::"},{address:"0:0:0:0:0:0:0:0"},{address:"::ffff:0.0.0.0"},{address:"fe80::1%2"},{port:0},{site:""},{fingerprintSha256:"a"},{thumbprint:"b"},{observedAt:new Date(now-120001).toISOString()},{observedAt:new Date(now+1).toISOString()},{extra:true}]) {
    assert.throws(() => normalizeIisAbsenceProof({...valid,...patch},now),{code:"CERTOPS_AGENT_OBSERVATION_INVALID"});
  }
});
test("proof batches require an explicit sequence and unique client identifiers", async () => {
  const input={agent:{id:"a",workspaceId:"w",agentId:"a"},envelope:{sequence:0},proofs:[valid]};
  await assert.rejects(persistIisAbsenceProofBatch(input),{code:"CERTOPS_AGENT_OBSERVATION_INVALID"});
  await assert.rejects(persistIisAbsenceProofBatch({...input,envelope:{sequence:1},proofs:[valid,valid]}),{code:"CERTOPS_AGENT_OBSERVATION_INVALID"});
});
test("proof inserts and duplicates remain inside the sequenced credential transaction", async () => {
  const queries=[]; let released=false;
  const client={query:async(sql) => {queries.push(sql); if(sql.startsWith("SELECT status")) return {rows:[{status:"active",platform:"win32",declared_capabilities:["iis-explicit-ip-v1"],capabilities_updated_at:new Date().toISOString()}]}; if(sql.startsWith("SELECT count")) return {rows:[{count:0}]}; if(sql.startsWith("INSERT")) return {rowCount:0}; return {rows:[],rowCount:0};},release:()=>{released=true;}};
  const result=await persistIisAbsenceProofBatch({dbPool:{connect:async()=>client},agent:{id:"a",workspaceId:"w",agentId:"a"},envelope:{sequence:1},proofs:[valid],deps:{assertCurrentAgentCredential:async()=>queries.push("credential"),enforceAgentSequence:async()=>queries.push("sequence")}});
  assert.equal(result.proofCount,0); assert.equal(result.duplicateCount,1);
  assert.deepEqual(queries.slice(0,3),["BEGIN","credential","sequence"]);
  assert.ok(queries.some(sql=>sql.includes("DO NOTHING"))); assert.equal(queries.at(-1),"COMMIT"); assert.equal(released,true);
});
test("storage cap refuses a batch without deleting fresh proof identifiers", async () => {
  const queries=[];
  const client={query:async(sql) => { queries.push(sql); if(sql.startsWith("SELECT status")) return {rows:[{status:"active",platform:"win32",declared_capabilities:["iis-explicit-ip-v1"],capabilities_updated_at:new Date().toISOString()}]}; if(sql.startsWith("SELECT count")) return {rows:[{count:512}]}; return {rows:[],rowCount:0}; },release:()=>{}};
  await assert.rejects(persistIisAbsenceProofBatch({dbPool:{connect:async()=>client},agent:{id:"a",workspaceId:"w",agentId:"a"},envelope:{sequence:1},proofs:[valid],deps:{assertCurrentAgentCredential:async()=>{},enforceAgentSequence:async()=>{}}}),{code:"CERTOPS_AGENT_OBSERVATION_INVALID"});
  assert.equal(queries.some(sql=>sql.startsWith("INSERT")),false);
  assert.equal(queries.at(-1),"ROLLBACK");
});
