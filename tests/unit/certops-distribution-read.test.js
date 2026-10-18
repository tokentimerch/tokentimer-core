"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { parseIds, consumerStatus, summarizeConsumers, listDistributionGroups } = require("../../apps/api/services/certops/distributionRead");
const { consumerMatrix } = require("../../apps/api/services/certops/materialDistribution");

const consumer = (extra = {}) => ({ binding_state: "active", desired_material_version_id: randomUUID(), ...extra });

test("deployment states require current backend convergence, not a historical successful stage", () => {
  for (const [extra, expected] of [
    [{ converged: true }, "verified"],
    [{ latest_deployment: { stage: "served_verified" } }, "pending"],
    [{ latest_deployment: { stage: "trust_validated" }, stale: true }, "stale"],
    [{ latest_deployment: { stage: "failed" } }, "failed"],
    [{ converged: true, latest_deployment: { stage: "failed" } }, "failed"],
    [{ converged: true, latest_deployment: { stage: "orphaned_unknown_effect" } }, "uncertain"],
    [{ latest_deployment: { stage: "orphaned_unknown_effect" } }, "uncertain"],
    [{ desired_material_version_id: null }, "not_deployed"],
    [{ binding_state: "removed", converged: true }, "inactive"],
  ]) assert.equal(consumerStatus(consumer(extra)), expected);
});

test("summary counts active bindings, partial convergence, and stale/failed/uncertain evidence", () => {
  const verified = consumer({ converged: true });
  assert.equal(summarizeConsumers([]).status, "not_deployed");
  assert.equal(summarizeConsumers([verified]).status, "verified");
  assert.deepEqual(summarizeConsumers([verified, consumer(), consumer({ binding_state: "removed", converged: true })]), {
    total: 2, verified: 1, failed: 0, uncertain: 0, stale: 0, pending: 1, not_deployed: 0, status: "partial",
  });
  for (const [extra, status] of [[{ stale: true }, "stale"], [{ latest_deployment: { stage: "failed" } }, "failed"], [{ latest_deployment: { stage: "orphaned_unknown_effect" } }, "uncertain"]]) {
    assert.equal(summarizeConsumers([verified, consumer(extra)]).status, status);
  }
  assert.equal(summarizeConsumers([verified], false).verified, 0);
});

test("batch input is bounded, deduplicated and rejects invalid IDs", async () => {
  const id = randomUUID();
  assert.deepEqual(parseIds(`${id},${id}`), [id]);
  for (const value of ["", [], "not-a-uuid", Array(201).fill(id).join(",")]) {
    assert.throws(() => parseIds(value), error => error.statusCode === 422);
  }
  await assert.rejects(listDistributionGroups({ client: {}, workspaceId: id, query: { summaries: "true" } }), error => error.statusCode === 422);
});

test("50 shared certificates and 500 consumers use two workspace-scoped reads", async () => {
  const workspaceId = randomUUID();
  const groups = Array.from({ length: 50 }, () => ({ id: randomUUID(), managed_certificate_id: randomUUID(), current_identity_id: randomUUID() }));
  const queries = [];
  const client = { async query(sql, params) {
    queries.push({ sql, params });
    assert.equal(params[0], workspaceId);
    if (queries.length === 1) return { rows: groups };
    return { rows: groups.flatMap(group => Array.from({ length: 10 }, () => consumer({ group_id: group.id, converged: true }))) };
  } };
  const result = await listDistributionGroups({ client, workspaceId, query: { summaries: "true", identityIds: groups.map(g => g.current_identity_id).join(",") } });
  assert.equal(queries.length, 2);
  assert.equal(result.groups.length, 50);
  assert.ok(result.groups.every(g => g.summary.total === 10 && g.summary.verified === 10));
  assert.ok(result.groups.every(g => !g.consumers && !g.material_store_ref));
  assert.match(queries[0].sql, /p\.managed_certificate_id=g\.managed_certificate_id/);
  assert.match(queries[0].sql, /p\.current_identity_id=ANY\(\$3::uuid\[\]\)/);
  assert.match(queries[0].sql, /g\.state='active' AND p\.ended_at IS NULL/);
  assert.match(queries[0].sql, /g\.workspace_id=\$1/);
  assert.match(queries[1].sql, /b\.workspace_id=\$1 AND b\.group_id=ANY/);
  assert.match(queries[1].sql, /proof\.authorization_revision=b\.authorization_revision/);
  assert.match(queries[1].sql, /identity\.lifecycle_status='active'/);
  assert.match(queries[1].sql, /s\.observed_at>clock_timestamp\(\)-b\.freshness_seconds/);
});

test("historical identity detail can read publication history without marking ended periods active", async () => {
  let params, sql;
  const identity = randomUUID();
  await listDistributionGroups({ workspaceId: randomUUID(), query: { identityIds: identity }, client: { async query(text, values) { sql = text; params = values; return { rows: [] }; } } });
  assert.equal(params[4], false);
  assert.deepEqual(params[2], [identity]);
  assert.match(sql, /history\.workspace_id=g\.workspace_id/);
  assert.match(sql, /history\.certificate_identity_id=ANY/);
  assert.match(sql, /p\.ended_at IS NULL\) AS active/);
});

test("single-group consumer read still uses the same convergence query and scoped agent labels", async () => {
  const groupId = randomUUID(), workspaceId = randomUUID();
  await consumerMatrix({ groupId, workspaceId, client: { async query(sql, params) {
    assert.deepEqual(params, [workspaceId, [groupId]]);
    assert.match(sql, /a\.workspace_id=b\.workspace_id AND a\.id=b\.assigned_agent_id/);
    assert.match(sql, /desired\.workspace_id=s\.workspace_id/);
    return { rows: [] };
  } } });
});
