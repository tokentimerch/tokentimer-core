"use strict";
// Scoped cleanup engine. Caller supplies a reviewed Docker transport; no CLI,
// global prune or implicit connection is performed by this module.
const assert = require("node:assert/strict");
const resourceOrder = ["container", "volume", "network"];
async function cleanup({ project, transport }) {
  assert.match(project || "", /^tt-wildcard-ux-qual-[a-z0-9-]+$/);
  for (const method of ["inventory", "inspect", "remove"]) assert.equal(typeof transport?.[method], "function");
  const resources = await transport.inventory(project);
  assert.ok(Array.isArray(resources) && resources.length <= 128, "bounded owned inventory required");
  const seen = new Set();
  for (const item of resources) {
    assert.ok(resourceOrder.includes(item.kind) && typeof item.id === "string" && item.id.length > 0);
    assert.equal(item.project, project, "foreign resource refused");
    const key = item.kind + ":" + item.id; assert.equal(seen.has(key), false, "duplicate resource"); seen.add(key);
  }
  // Remove consumers before their storage and network, rechecking each resource.
  for (const item of [...resources].sort((a, b) => resourceOrder.indexOf(a.kind) - resourceOrder.indexOf(b.kind))) {
    const current = await transport.inspect(item.kind, item.id);
    assert.equal(current?.project, project, "resource ownership changed; refusing removal");
    await transport.remove(item.kind, item.id);
    assert.equal(await transport.inspect(item.kind, item.id), null, "resource remains after removal");
  }
  const remaining = await transport.inventory(project);
  assert.ok(Array.isArray(remaining) && remaining.length === 0, "owned project resources remain");
  return { status: "passed-supporting-only", releaseQualification: "not-established", project, removedContainers: resources.filter(x => x.kind === "container").length,
    removedVolumes: resources.filter(x => x.kind === "volume").length, removedNetworks: resources.filter(x => x.kind === "network").length, ownedContainersAbsent: true, ownedVolumesAbsent: true, ownedNetworksAbsent: true };
}
module.exports = { cleanup };
