"use strict";
const {test}=require("node:test"), assert=require("node:assert/strict"), {requireFresh}=require("./project-freshness.cjs");
test("a retained volume blocks reuse even when no container exists", async()=>{
  const project="tt-wildcard-ux-qual-run";
  await assert.rejects(requireFresh(project,{inventory:async()=>[{kind:"volume",id:"retained",project}]}),/containers, volumes or networks/);
  assert.equal(await requireFresh(project,{inventory:async()=>[]}),true);
  await assert.rejects(requireFresh(project,{inventory:async()=>{throw new Error("Docker unavailable");}}),/Docker unavailable/);
});
