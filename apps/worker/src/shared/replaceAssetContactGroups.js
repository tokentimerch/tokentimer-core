import {
  canonicalLegacyContactGroupId,
  normalizeAssignedGroupIds,
} from "./contactGroups.js";

const KIND_TABLES = {
  token: {
    joinTable: "token_contact_groups",
    assetCol: "token_id",
    parentTable: "tokens",
  },
  agent: {
    joinTable: "certops_agent_contact_groups",
    assetCol: "agent_id",
    parentTable: "certops_agents",
  },
};

function resolveKind(kind) {
  const spec = KIND_TABLES[kind];
  if (!spec) {
    throw new Error(`Unsupported contact-group asset kind: ${kind}`);
  }
  return spec;
}

async function replaceAssetContactGroups({
  client,
  kind,
  assetId,
  workspaceId,
  ids,
}) {
  const spec = resolveKind(kind);
  const normalized = normalizeAssignedGroupIds(ids);
  const canonical = canonicalLegacyContactGroupId(normalized);

  await client.query(
    `DELETE FROM ${spec.joinTable} WHERE ${spec.assetCol} = $1 AND workspace_id = $2`,
    [assetId, workspaceId],
  );

  if (normalized.length > 0) {
    await client.query(
      `INSERT INTO ${spec.joinTable} (${spec.assetCol}, workspace_id, contact_group_id)
       SELECT $1, $2, unnest($3::text[])`,
      [assetId, workspaceId, normalized],
    );
  }

  await client.query(
    `UPDATE ${spec.parentTable}
        SET contact_group_id = $1
      WHERE id = $2 AND workspace_id = $3`,
    [canonical, assetId, workspaceId],
  );
}

async function loadAssignedGroupIds({ client, kind, assetId, workspaceId }) {
  const spec = resolveKind(kind);
  const res = await client.query(
    `SELECT contact_group_id
       FROM ${spec.joinTable}
      WHERE ${spec.assetCol} = $1 AND workspace_id = $2`,
    [assetId, workspaceId],
  );
  return normalizeAssignedGroupIds(
    (res.rows || []).map((row) => row.contact_group_id),
  );
}

async function loadAssignedGroupIdsForAssets({
  client,
  kind,
  assetIds,
  workspaceId,
}) {
  const spec = resolveKind(kind);
  const ids = [];
  const seen = new Set();
  for (const raw of Array.isArray(assetIds) ? assetIds : []) {
    if (raw == null) continue;
    const key = String(raw);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    ids.push(raw);
  }
  const assigned = new Map();
  for (const id of ids) assigned.set(String(id), []);
  if (ids.length === 0) return assigned;

  const arrayType = kind === "token" ? "int[]" : "uuid[]";
  const res = await client.query(
    `SELECT ${spec.assetCol} AS asset_id, contact_group_id
       FROM ${spec.joinTable}
      WHERE workspace_id = $1 AND ${spec.assetCol} = ANY($2::${arrayType})`,
    [workspaceId, ids],
  );
  for (const row of res.rows || []) {
    const key = String(row.asset_id);
    const list = assigned.get(key) || [];
    list.push(row.contact_group_id);
    assigned.set(key, list);
  }
  for (const [key, list] of assigned) {
    assigned.set(key, normalizeAssignedGroupIds(list));
  }
  return assigned;
}

export {
  replaceAssetContactGroups,
  loadAssignedGroupIds,
  loadAssignedGroupIdsForAssets,
};
