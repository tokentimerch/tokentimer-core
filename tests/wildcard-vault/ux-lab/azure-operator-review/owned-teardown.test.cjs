"use strict";
const { test } = require("node:test"), assert = require("node:assert/strict");
const { cleanup } = require("./owned-teardown.cjs");
test("teardown removes only owned containers and volumes and verifies absence", async () => {
  const project = "tt-wildcard-ux-qual-run123", rows = [
    {kind:"container",id:"one",project},{kind:"volume",id:"two",project},{kind:"volume",id:"foreign",project:"other"}];
  const transport = { inventory:async p=>rows.filter(x=>x.project===p), inspect:async (kind,id)=>rows.find(x=>x.kind===kind&&x.id===id)||null,
    remove:async (kind,id)=>{const i=rows.findIndex(x=>x.kind===kind&&x.id===id); rows.splice(i,1);} };
  const result = await cleanup({project,transport});
  assert.equal(result.removedContainers,1); assert.equal(result.removedVolumes,1); assert.deepEqual(rows.map(x=>x.id),["foreign"]);
});
test("changed ownership and remaining volumes fail closed", async () => {
  const project="tt-wildcard-ux-qual-run123", item={kind:"volume",id:"one",project}; let removed=false;
  const transport={inventory:async()=>[item],inspect:async()=>({project:"foreign"}),remove:async()=>{removed=true;}};
  await assert.rejects(cleanup({project,transport}),/ownership changed/); assert.equal(removed,false);
  transport.inspect=async()=>item; transport.remove=async()=>{};
  await assert.rejects(cleanup({project,transport}),/remains/);
});
