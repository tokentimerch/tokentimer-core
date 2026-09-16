"use strict";

const {
  canonicalLegacyContactGroupId,
  normalizeAssignedGroupIds,
} = require("../src/shared/contactGroups");

class TransferAssociationConflictError extends Error {
  constructor(message, details = []) {
    super(message);
    this.name = "TransferAssociationConflictError";
    this.code = "TRANSFER_CONFLICT";
    this.status = 409;
    this.details = details;
  }
}

const RELOCATABLE_TABLES = new Set([
  "certificate_instances",
  "certificate_job_log",
  "certificate_evidence",
  "certificate_executor_events",
  "certificate_controller_observations",
]);

function parseContactGroups(raw) {
  if (!Array.isArray(raw)) return [];
  return raw.filter((group) => group && typeof group.id === "string" && group.id);
}

function buildContactGroupTransferMap(sourceGroups, destGroups) {
  const destById = new Set(destGroups.map((group) => String(group.id)));
  const destByName = new Map();
  for (const group of destGroups) {
    const name = String(group.name || "")
      .trim()
      .toLowerCase();
    if (!name || destByName.has(name)) continue;
    destByName.set(name, String(group.id));
  }

  const map = new Map();
  const unmatched = [];
  for (const group of sourceGroups) {
    const id = String(group.id);
    if (destById.has(id)) {
      map.set(id, id);
      continue;
    }
    const name = String(group.name || "")
      .trim()
      .toLowerCase();
    const destId = name ? destByName.get(name) : null;
    if (destId) {
      map.set(id, destId);
    } else {
      unmatched.push({ id, name: group.name || null });
    }
  }
  return { map, unmatched };
}

function remapJoinRows(rows, idMap) {
  const remapped = [];
  const dropped = [];
  for (const row of rows) {
    const fromId = String(row.contact_group_id);
    const toId = idMap.get(fromId);
    if (!toId) {
      dropped.push({
        token_id: Number(row.token_id),
        contact_group_id: fromId,
      });
      continue;
    }
    remapped.push({
      token_id: Number(row.token_id),
      contact_group_id: toId,
    });
  }
  return { remapped, dropped };
}

async function loadWorkspaceGroups(client, workspaceId) {
  const res = await client.query(
    `SELECT contact_groups FROM workspace_settings WHERE workspace_id = $1`,
    [workspaceId],
  );
  return parseContactGroups(res.rows?.[0]?.contact_groups);
}

async function takeTokenContactGroupRows(client, tokenIds, fromWorkspaceId) {
  if (tokenIds.length === 0) return [];
  const res = await client.query(
    `DELETE FROM token_contact_groups
      WHERE token_id = ANY($1::int[]) AND workspace_id = $2
      RETURNING token_id, contact_group_id`,
    [tokenIds, fromWorkspaceId],
  );
  return res.rows || [];
}

async function putTokenContactGroupRows(client, rows, toWorkspaceId) {
  if (rows.length === 0) return;
  await client.query(
    `INSERT INTO token_contact_groups (token_id, workspace_id, contact_group_id)
     SELECT x.token_id, $1::uuid, x.contact_group_id
       FROM jsonb_to_recordset($2::jsonb)
         AS x(token_id int, contact_group_id text)
     ON CONFLICT DO NOTHING`,
    [
      toWorkspaceId,
      JSON.stringify(
        rows.map((row) => ({
          token_id: Number(row.token_id),
          contact_group_id: String(row.contact_group_id),
        })),
      ),
    ],
  );
}

async function takeWorkspaceScopedRows(
  client,
  { table, fromWorkspaceId, whereSql, whereParams },
) {
  if (!RELOCATABLE_TABLES.has(table)) {
    throw new Error(`refusing to relocate unknown table ${table}`);
  }
  const taken = await client.query(
    `DELETE FROM ${table} WHERE workspace_id = $1 AND (${whereSql}) RETURNING *`,
    [fromWorkspaceId, ...whereParams],
  );
  return taken.rows || [];
}

async function putWorkspaceScopedRows(
  client,
  { table, toWorkspaceId, rows, nullColumns = [] },
) {
  if (!RELOCATABLE_TABLES.has(table)) {
    throw new Error(`refusing to relocate unknown table ${table}`);
  }
  if (!rows || rows.length === 0) return 0;

  const columns = Object.keys(rows[0]);
  const values = [];
  const tuples = [];
  let i = 1;
  for (const row of rows) {
    const placeholders = [];
    for (const col of columns) {
      let value = row[col];
      if (col === "workspace_id") value = toWorkspaceId;
      if (nullColumns.includes(col)) value = null;
      placeholders.push(`$${i++}`);
      values.push(value);
    }
    tuples.push(`(${placeholders.join(", ")})`);
  }
  const quotedCols = columns.map((col) => `"${col}"`).join(", ");
  await client.query(
    `INSERT INTO ${table} (${quotedCols}) VALUES ${tuples.join(", ")}`,
    values,
  );
  return rows.length;
}

async function assertNoManagedCertificateCollision(
  client,
  { tokenIds, fromWorkspaceId, toWorkspaceId },
) {
  const res = await client.query(
    `SELECT mc.token_id, mc.id
       FROM managed_certificates mc
      WHERE mc.workspace_id = $1
        AND mc.token_id = ANY($2::int[])
        AND EXISTS (
          SELECT 1
            FROM managed_certificates dest
           WHERE dest.workspace_id = $3
             AND (
               (
                 mc.fingerprint_sha256 IS NOT NULL
                 AND dest.fingerprint_sha256 = mc.fingerprint_sha256
                 AND mc.source NOT IN ('endpoint_monitor', 'domain_checker')
                 AND dest.source NOT IN ('endpoint_monitor', 'domain_checker')
               )
               OR (
                 mc.source_ref IS NOT NULL
                 AND dest.source = mc.source
                 AND dest.source_ref = mc.source_ref
                 AND mc.source IN ('endpoint_monitor', 'domain_checker')
               )
             )
        )`,
    [fromWorkspaceId, tokenIds, toWorkspaceId],
  );
  if ((res.rowCount || 0) > 0) {
    throw new TransferAssociationConflictError(
      "A managed certificate in the destination workspace already uses the same fingerprint or monitor source",
      res.rows.map((row) => ({
        token_id: Number(row.token_id),
        managed_certificate_id: row.id,
      })),
    );
  }
}

async function assertNoJobIdempotencyCollision(
  client,
  { jobIds, fromWorkspaceId, toWorkspaceId },
) {
  if (jobIds.length === 0) return;
  const res = await client.query(
    `SELECT cj.id
       FROM certificate_jobs cj
      WHERE cj.workspace_id = $1
        AND cj.id = ANY($2::uuid[])
        AND cj.idempotency_key IS NOT NULL
        AND EXISTS (
          SELECT 1
            FROM certificate_jobs dest
           WHERE dest.workspace_id = $3
             AND dest.idempotency_key = cj.idempotency_key
        )`,
    [fromWorkspaceId, jobIds, toWorkspaceId],
  );
  if ((res.rowCount || 0) > 0) {
    throw new TransferAssociationConflictError(
      "A certificate job in the destination workspace already uses the same idempotency key",
      res.rows.map((row) => ({ job_id: row.id })),
    );
  }
}

async function listIds(client, sql, params) {
  const res = await client.query(sql, params);
  return (res.rows || []).map((row) => row.id);
}

/**
 * Move tokens and the workspace-scoped records operators treat as part of
 * the token. Call inside an open transaction.
 */
async function transferTokenAssociations(
  client,
  { tokenIds, fromWorkspaceId, toWorkspaceId, targetOwnerId },
) {
  if (!Array.isArray(tokenIds) || tokenIds.length === 0) {
    return {
      movedIds: [],
      droppedContactGroups: [],
      movedMonitors: 0,
      movedCertificates: 0,
    };
  }

  const sourceGroups = await loadWorkspaceGroups(client, fromWorkspaceId);
  const destGroups = await loadWorkspaceGroups(client, toWorkspaceId);
  const { map: groupIdMap } = buildContactGroupTransferMap(
    sourceGroups,
    destGroups,
  );

  await assertNoManagedCertificateCollision(client, {
    tokenIds,
    fromWorkspaceId,
    toWorkspaceId,
  });

  const certIds = await listIds(
    client,
    `SELECT id FROM managed_certificates
      WHERE workspace_id = $1 AND token_id = ANY($2::int[])`,
    [fromWorkspaceId, tokenIds],
  );
  const monitorIds = await listIds(
    client,
    `SELECT id FROM domain_monitors
      WHERE workspace_id = $1 AND token_id = ANY($2::int[])`,
    [fromWorkspaceId, tokenIds],
  );
  const instanceIds =
    certIds.length === 0
      ? []
      : await listIds(
          client,
          `SELECT id FROM certificate_instances
            WHERE workspace_id = $1 AND managed_certificate_id = ANY($2::uuid[])`,
          [fromWorkspaceId, certIds],
        );
  const instanceTargetIds =
    certIds.length === 0
      ? []
      : await listIds(
          client,
          `SELECT DISTINCT target_id AS id FROM certificate_instances
            WHERE workspace_id = $1
              AND managed_certificate_id = ANY($2::uuid[])
              AND target_id IS NOT NULL`,
          [fromWorkspaceId, certIds],
        );
  const linkedTargetIds = await listIds(
    client,
    `SELECT id FROM certificate_targets
      WHERE workspace_id = $1
        AND (
          token_id = ANY($2::int[])
          OR ($3::uuid[] <> '{}'::uuid[] AND domain_monitor_id = ANY($3::uuid[]))
        )`,
    [fromWorkspaceId, tokenIds, monitorIds],
  );
  const targetIds = [
    ...new Set([...linkedTargetIds, ...instanceTargetIds].map(String)),
  ];

  const certIdTexts = certIds.map(String);
  const tokenIdTexts = tokenIds.map(String);
  const targetIdTexts = targetIds;
  const instanceIdTexts = instanceIds.map(String);
  const jobIds = await listIds(
    client,
    `SELECT id FROM certificate_jobs
      WHERE workspace_id = $1
        AND (
          (subject_type = 'managed_certificate' AND subject_id = ANY($2::text[]))
          OR (subject_type = 'token' AND subject_id = ANY($3::text[]))
          OR (subject_type = 'certificate_target' AND subject_id = ANY($4::text[]))
          OR (subject_type = 'certificate_instance' AND subject_id = ANY($5::text[]))
        )`,
    [fromWorkspaceId, certIdTexts, tokenIdTexts, targetIdTexts, instanceIdTexts],
  );
  await assertNoJobIdempotencyCollision(client, {
    jobIds,
    fromWorkspaceId,
    toWorkspaceId,
  });
  if (certIds.length > 0) {
    const observationClash = await client.query(
      `SELECT src.id
         FROM certificate_controller_observations src
        WHERE src.workspace_id = $1
          AND src.managed_certificate_id = ANY($2::uuid[])
          AND EXISTS (
            SELECT 1
              FROM certificate_controller_observations dest
             WHERE dest.workspace_id = $3
               AND dest.controller_cluster_id = src.controller_cluster_id
               AND dest.idempotency_key = src.idempotency_key
          )`,
      [fromWorkspaceId, certIds, toWorkspaceId],
    );
    if ((observationClash.rowCount || 0) > 0) {
      throw new TransferAssociationConflictError(
        "A controller observation in the destination workspace already uses the same cluster idempotency key",
        observationClash.rows.map((row) => ({ observation_id: row.id })),
      );
    }
  }

  const membership = await takeTokenContactGroupRows(
    client,
    tokenIds,
    fromWorkspaceId,
  );

  const heldInstances =
    certIds.length === 0
      ? []
      : await takeWorkspaceScopedRows(client, {
          table: "certificate_instances",
          fromWorkspaceId,
          whereSql: "managed_certificate_id = ANY($2::uuid[])",
          whereParams: [certIds],
        });
  const heldObservations =
    certIds.length === 0
      ? []
      : await takeWorkspaceScopedRows(client, {
          table: "certificate_controller_observations",
          fromWorkspaceId,
          whereSql: "managed_certificate_id = ANY($2::uuid[])",
          whereParams: [certIds],
        });
  const heldJobLogs =
    jobIds.length === 0
      ? []
      : await takeWorkspaceScopedRows(client, {
          table: "certificate_job_log",
          fromWorkspaceId,
          whereSql: "job_id = ANY($2::uuid[])",
          whereParams: [jobIds],
        });
  const heldEvidence =
    jobIds.length === 0
      ? []
      : await takeWorkspaceScopedRows(client, {
          table: "certificate_evidence",
          fromWorkspaceId,
          whereSql: "job_id = ANY($2::uuid[])",
          whereParams: [jobIds],
        });
  const heldExecutorEvents =
    jobIds.length === 0
      ? []
      : await takeWorkspaceScopedRows(client, {
          table: "certificate_executor_events",
          fromWorkspaceId,
          whereSql: "job_id = ANY($2::uuid[])",
          whereParams: [jobIds],
        });

  const updateRes = await client.query(
    `UPDATE tokens
        SET workspace_id = $1, updated_at = NOW()
      WHERE id = ANY($2::int[]) AND workspace_id = $3
      RETURNING id`,
    [toWorkspaceId, tokenIds, fromWorkspaceId],
  );
  const movedIds = (updateRes.rows || []).map((row) => Number(row.id));
  const movedIdSet = new Set(movedIds);

  const monitorRes = await client.query(
    `UPDATE domain_monitors
        SET workspace_id = $1, updated_at = NOW()
      WHERE workspace_id = $2 AND token_id = ANY($3::int[])`,
    [toWorkspaceId, fromWorkspaceId, movedIds],
  );

  if (targetIds.length > 0) {
    await client.query(
      `UPDATE certificate_targets
          SET workspace_id = $1, profile_id = NULL, updated_at = NOW()
        WHERE workspace_id = $2 AND id = ANY($3::uuid[])`,
      [toWorkspaceId, fromWorkspaceId, targetIds],
    );
  }

  let movedCertificates = 0;
  if (certIds.length > 0) {
    const certRes = await client.query(
      `UPDATE managed_certificates
          SET workspace_id = $1, profile_id = NULL, updated_at = NOW()
        WHERE workspace_id = $2 AND id = ANY($3::uuid[])`,
      [toWorkspaceId, fromWorkspaceId, certIds],
    );
    movedCertificates = certRes.rowCount || 0;
  }

  if (jobIds.length > 0) {
    await client.query(
      `UPDATE certificate_jobs
          SET workspace_id = $1,
              requested_by_api_token_id = NULL,
              updated_at = NOW()
        WHERE workspace_id = $2 AND id = ANY($3::uuid[])`,
      [toWorkspaceId, fromWorkspaceId, jobIds],
    );
  }

  await putWorkspaceScopedRows(client, {
    table: "certificate_instances",
    toWorkspaceId,
    rows: heldInstances,
  });
  await putWorkspaceScopedRows(client, {
    table: "certificate_controller_observations",
    toWorkspaceId,
    rows: heldObservations,
    nullColumns: ["created_by_api_token_id"],
  });
  await putWorkspaceScopedRows(client, {
    table: "certificate_job_log",
    toWorkspaceId,
    rows: heldJobLogs,
    nullColumns: ["created_by_api_token_id"],
  });
  await putWorkspaceScopedRows(client, {
    table: "certificate_evidence",
    toWorkspaceId,
    rows: heldEvidence,
    nullColumns: ["created_by_api_token_id"],
  });
  await putWorkspaceScopedRows(client, {
    table: "certificate_executor_events",
    toWorkspaceId,
    rows: heldExecutorEvents,
    nullColumns: ["created_by_api_token_id"],
  });

  const { remapped, dropped } = remapJoinRows(
    membership.filter((row) => movedIdSet.has(Number(row.token_id))),
    groupIdMap,
  );
  await putTokenContactGroupRows(client, remapped, toWorkspaceId);

  const assignedByToken = new Map();
  for (const id of movedIds) assignedByToken.set(id, []);
  for (const row of remapped) {
    const list = assignedByToken.get(row.token_id) || [];
    list.push(row.contact_group_id);
    assignedByToken.set(row.token_id, list);
  }
  for (const [tokenId, ids] of assignedByToken) {
    const canonical = canonicalLegacyContactGroupId(
      normalizeAssignedGroupIds(ids),
    );
    await client.query(
      `UPDATE tokens
          SET contact_group_id = $1
        WHERE id = $2 AND workspace_id = $3`,
      [canonical, tokenId, toWorkspaceId],
    );
  }

  if (movedIds.length > 0 && targetOwnerId) {
    await client.query(
      `UPDATE alert_delivery_log
          SET user_id = $1
        WHERE token_id = ANY($2::int[])
          AND date_trunc('month', (sent_at AT TIME ZONE 'UTC')) =
              date_trunc('month', (NOW() AT TIME ZONE 'UTC'))`,
      [targetOwnerId, movedIds],
    );
  }

  return {
    movedIds,
    droppedContactGroups: dropped,
    movedMonitors: monitorRes.rowCount || 0,
    movedCertificates,
  };
}

module.exports = {
  TransferAssociationConflictError,
  buildContactGroupTransferMap,
  remapJoinRows,
  transferTokenAssociations,
};
