"use strict";
const assert = require("node:assert/strict");
const { createDockerTransport } = require("./docker-transport.cjs");
async function requireFresh(project, transport = createDockerTransport({project})) {
  assert.match(project || "", /^tt-wildcard-ux-(?:qual|ci)-[a-z0-9-]+$/);
  const inventory = await transport.inventory(project);
  assert.ok(Array.isArray(inventory), "project inventory unavailable");
  assert.equal(inventory.length, 0, "project contains existing containers, volumes or networks");
  return true;
}
if (require.main === module) requireFresh(process.argv[2]).then(()=>console.log("Project inventory empty"))
  .catch(()=>{console.error("Project freshness refused");process.exitCode=1;});
module.exports = { requireFresh };
