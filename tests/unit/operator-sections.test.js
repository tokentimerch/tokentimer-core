"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { listSections } = require("../../apps/api/services/operator/tokenInventory");

test("sections are workspace scoped and projected as untrusted text", async () => {
  const calls = [];
  const client = { query: async (sql, params) => {
    calls.push({ sql, params });
    return calls.length === 1 ? { rows: [{ total: 2 }] } : { rows: [{ label: "Production" }, { label: "Staging" }] };
  } };
  const result = await listSections({ workspaceId: "workspace-a", query: { limit: "2" }, client });
  assert.deepEqual(calls.map((call) => call.params), [["workspace-a"], ["workspace-a", 2, 0]]);
  assert.ok(calls.every((call) => call.sql.includes("workspace_id=$1")));
  assert.deepEqual(result.items.map((item) => [item.value, item.untrusted]), [["Production", true], ["Staging", true]]);
  assert.equal(result.completeness.returned, 2);
});

test("sections reject unsupported filters and unsafe outbound data", async () => {
  const client = { query: async () => ({ rows: [{ total: 1, label: "Bearer abcdefghijklmnopqrstuvwxyz0123456789" }] }) };
  await assert.rejects(listSections({ workspaceId: "workspace-a", query: { provider: "gitlab" }, client }), { code: "OPERATOR_VALIDATION_ERROR" });
  await assert.rejects(listSections({ workspaceId: "workspace-a", client }), { code: "OPERATOR_UNSAFE_METADATA" });
});
