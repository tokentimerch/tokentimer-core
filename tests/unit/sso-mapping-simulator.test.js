"use strict";

const { it } = require("node:test");
const assert = require("node:assert/strict");
const { runMappingSimulation } = require("../../apps/api/sso/mapping-simulator.js");
const { validateMappingPayload } = require("../../apps/api/sso/mapping-validation.js");

it("simulates legacy bootstrap admin groups without reading membership history", async () => {
  const workspaceId = "e4e045ef-b74b-4205-af63-19f8ca9d9805";
  const pool = {
    async query(sql, values) {
      if (sql.includes("FROM sso_providers")) {
        assert.deepEqual(values, ["oidc"]);
        return { rows: [{ config: { admin_groups: "legacy-admins" } }] };
      }
      if (sql.includes("FROM sso_group_role_mappings")) {
        assert.deepEqual(values, ["oidc", ["legacy-admins", "readers"]]);
        return { rows: [{ idp_group: "readers", role: "viewer", workspace_id: workspaceId }] };
      }
      if (sql === "SELECT id FROM workspaces") {
        return { rows: [{ id: workspaceId }] };
      }
      assert.match(sql, /^SELECT id, name FROM workspaces/);
      assert.deepEqual(values, [[workspaceId]]);
      return { rows: [{ id: workspaceId, name: "Platform" }] };
    },
  };

  const preview = await runMappingSimulation(pool, {
    providerSlug: "OIDC",
    groups: [" Legacy-Admins ", "Readers", "READERS"],
    strictSyncPreview: true,
  });

  assert.deepEqual(preview.matched_groups, ["legacy-admins", "readers"]);
  assert.deepEqual(preview.grants, [
    { role: "admin", workspace: "system-wide" },
    { role: "workspace_manager", workspace_id: workspaceId, workspace: "Platform" },
  ]);
  assert.deepEqual(preview.revoked_preview, []);
  assert.match(preview.strict_sync_note, /no membership history/);
});

it("validates workspace scope without treating malformed IDs as a global grant", () => {
  const mapping = { provider_slug: "OIDC", idp_group: " Readers ", role: "viewer" };
  assert.match(validateMappingPayload({ ...mapping, workspace_id: "invalid" }).error, /UUID/);
  assert.match(validateMappingPayload({ ...mapping, workspace_id: false }).error, /UUID/);
  assert.deepEqual(validateMappingPayload({ ...mapping, workspace_id: null }).value, {
    provider_slug: "oidc",
    idp_group: "readers",
    role: "viewer",
    workspace_id: null,
    priority: 100,
  });
});
