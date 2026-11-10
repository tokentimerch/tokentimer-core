"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { cleanupApiFixture } = require("../e2e/helpers/certops-api-fixture");
const operations = ["workspace-discovery", "audit-delete", "workspace-delete", "user-delete", "pool-close"];
function fakePool(failed) {
  const calls = [];
  const marker = new Error("fixture failure");
  return { calls, marker, async query(sql) {
    const kind = sql.startsWith("SELECT") ? "workspace-discovery" : sql.includes("audit_events") ? "audit-delete" : sql.includes("workspaces") ? "workspace-delete" : "user-delete";
    calls.push(kind); if (kind === failed) throw marker;
    return { rows: kind === "workspace-discovery" ? [{id: "workspace"}, {id: "personal"}] : [] };
  }, async end() { calls.push("pool-close"); if (failed === "pool-close") throw marker; } };
}
for (const failed of operations) test(`cleanup classifies ${failed} without suppressing failure or remaining work`, async () => {
  const pool = fakePool(failed), labels = [];
  await assert.rejects(cleanupApiFixture({pool,workspaceId:"workspace",userId:1,onCleanupFailure:kind => { labels.push(kind); throw new Error("ignored diagnostic failure"); }}), error => {
    if (failed === "pool-close") assert.equal(error, pool.marker);
    else { assert.ok(error instanceof AggregateError); assert.ok(error.errors.includes(pool.marker)); }
    return true;
  });
  assert.ok(labels.length >= 1); assert.ok(labels.every(label => label === failed));
  for (const operation of operations) assert.ok(pool.calls.includes(operation));
  assert.equal(pool.calls.at(-1), "pool-close");
});
test("successful cleanup deduplicates owned workspaces and emits no labels", async () => {
  const pool=fakePool(), labels=[];
  await cleanupApiFixture({pool,workspaceId:"workspace",userId:1,onCleanupFailure:kind=>labels.push(kind)});
  assert.deepEqual(labels,[]); assert.equal(pool.calls.filter(x=>x==="workspace-delete").length,2);
});
