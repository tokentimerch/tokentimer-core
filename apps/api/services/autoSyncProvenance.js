"use strict";

const { pool } = require("../db/database");
const { claimScanForCleanup, getScan } = require("./integrationScans");
const { buildDimensionFilterSql } = require("./importCleanup");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function multiConfigEnabled(db = pool) {
  const { rows } = await db.query(
    "SELECT multi_config_enabled FROM auto_sync_feature_state WHERE id = TRUE",
  );
  return rows[0]?.multi_config_enabled === true;
}

function normalizeConnectionName(value) {
  if (typeof value !== "string") return null;
  const name = value.trim().replace(/\s+/gu, " ");
  return name.length >= 1 && name.length <= 100 ? name : null;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort()
      .map((key) => [key, canonicalJson(value[key])]));
  }
  return value;
}

function scanSettingsEqual(left, right) {
  return JSON.stringify(canonicalJson(left || {})) ===
    JSON.stringify(canonicalJson(right || {}));
}

function sanitizePublicAutoSyncError(value) {
  if (value == null) return null;
  return String(value)
    .replace(/Bearer\s+[^\s,;]+/gi, "Bearer [redacted]")
    .replace(/https?:\/\/[^\s,;]+/gi, "[URL]")
    .replace(/\b(token|secret|password|authorization|api[_-]?key|client[_-]?secret)\s*[:=]\s*[^\s,;]+/gi,
      "$1=[redacted]")
    .substring(0, 1000);
}

async function assertRunFence(db, context) {
  const { rows } = await db.query(
    `SELECT c.id, c.workspace_id, c.provider, c.connection_key, c.run_generation,
            c.scan_version, c.active_run_id, c.lease_owner, c.lease_until,
            r.run_id, r.status
       FROM auto_sync_configs c
       JOIN auto_sync_runs r ON r.run_id = c.active_run_id
      WHERE c.id = $1 AND c.workspace_id = $2 AND c.provider = $3
        AND c.active_run_id = $4 AND c.run_generation = $5
        AND c.scan_version = $6 AND c.lease_owner = $7
        AND c.lease_until > NOW() AND c.enabled = TRUE
        AND r.status = 'running'
      FOR UPDATE OF c`,
    [
      context.configId,
      context.workspaceId,
      context.provider,
      context.runId,
      context.generation,
      context.scanVersion,
      context.leaseOwner,
    ],
  );
  if (!rows[0]) {
    const error = new Error("Auto-sync run is no longer current");
    error.code = "AUTO_SYNC_RUN_STALE";
    throw error;
  }
  return rows[0];
}

async function resolveAutoSyncImportContext(req, workspaceId, provider, scanId) {
  const enabled = await multiConfigEnabled();
  const body = req.body?.auto_sync_run;
  if (!body) {
    if (enabled && req.isWorkerCall) {
      const error = new Error("Fenced auto-sync run is required");
      error.code = "AUTO_SYNC_RUN_REQUIRED";
      throw error;
    }
    return null;
  }
  if (!req.isWorkerCall || !scanId || !UUID.test(String(scanId))) {
    const error = new Error("Invalid auto-sync run context");
    error.code = "AUTO_SYNC_RUN_INVALID";
    throw error;
  }
  const context = {
    configId: body.config_id,
    runId: body.run_id,
    generation: body.generation,
    scanVersion: body.scan_version,
    leaseOwner: body.lease_owner,
    workspaceId,
    provider,
    scanId,
  };
  if (
    !UUID.test(String(context.configId)) ||
    !UUID.test(String(context.runId)) ||
    !UUID.test(String(context.leaseOwner)) ||
    !Number.isSafeInteger(Number(context.generation)) ||
    !Number.isSafeInteger(Number(context.scanVersion))
  ) {
    const error = new Error("Invalid auto-sync run context");
    error.code = "AUTO_SYNC_RUN_INVALID";
    throw error;
  }
  const scan = await getScan({ scanId, workspaceId, provider });
  if (!scan || !scan.completed_at) {
    const error = new Error("Auto-sync scan is incomplete or unavailable");
    error.code = "AUTO_SYNC_SCAN_INVALID";
    throw error;
  }
  await assertRunFence(pool, context);
  return context;
}

async function withFencedImport(context, work) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await assertRunFence(client, context);
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function attachObservedToken(context, tokenId, created, { client } = {}) {
  if (!client) {
    return withFencedImport(context, (db) =>
      attachObservedToken(context, tokenId, created, { client: db }));
  }
    const config = await assertRunFence(client, context);
    const { rows } = await client.query(
      "SELECT id FROM tokens WHERE id = $1 AND workspace_id = $2 FOR UPDATE",
      [tokenId, context.workspaceId],
    );
    if (!rows[0]) throw new Error("Imported token is unavailable");
    if (created) {
      await client.query(
        "UPDATE tokens SET auto_sync_managed = TRUE WHERE id = $1",
        [tokenId],
      );
    }
    const linked = await client.query(
      `INSERT INTO auto_sync_token_links(config_id, token_id, last_seen_generation)
       VALUES ($1, $2, $3)
       ON CONFLICT (config_id, token_id)
       DO UPDATE SET last_seen_generation = GREATEST(
         auto_sync_token_links.last_seen_generation, EXCLUDED.last_seen_generation)
       RETURNING (xmax = 0) AS attached`,
      [context.configId, tokenId, context.generation],
    );
    if (linked.rows[0]?.attached) {
      await client.query(
        `INSERT INTO auto_sync_token_link_events
          (token_id, token_id_snapshot, workspace_id, config_id, config_name, run_id, event, reason)
         VALUES ($1, $1, $2, $3, $4, $5, 'attached', 'scan_discovery')`,
        [tokenId, context.workspaceId, context.configId, config.connection_key, context.runId],
      );
    }
}

async function reconcileAutoSyncRun(context, scanIds = [context.scanId]) {
  const client = await pool.connect();
  const result = { detached: 0, deleted: 0, complete: false };
  try {
    await client.query("BEGIN");
    const config = await assertRunFence(client, context);
    if (!Array.isArray(scanIds) || scanIds.length === 0 ||
        scanIds.length > 100 || new Set(scanIds).size !== scanIds.length ||
        !scanIds.every((id) => UUID.test(String(id))) ||
        !scanIds.includes(context.scanId)) {
      throw new Error("Invalid auto-sync scan set");
    }
    const scans = [];
    for (const scanId of scanIds) {
      const scan = await getScan({
        scanId, workspaceId: context.workspaceId,
        provider: context.provider, client,
      });
      const scopes = scan?.cleanup_scope?.subScopes;
      if (!scan?.completed_at || !Array.isArray(scopes) || scopes.length === 0 ||
          scopes.some((scope) => scope?.complete !== true)) {
        await client.query("COMMIT");
        return result;
      }
      scans.push({ scan, scopes });
    }
    for (const { scan } of scans) {
      const claimed = await claimScanForCleanup({
        scanId: scan.id, workspaceId: context.workspaceId,
        provider: context.provider, client,
      });
      if (!claimed) throw new Error("Auto-sync scan was already consumed");
    }
    result.complete = true;
    for (const { scan, scopes } of scans) {
    for (const scope of scopes) {
      const { sql, params } = buildDimensionFilterSql(scope.dimensions, 10);
      const candidates = await client.query(
        `SELECT t.id, t.auto_sync_managed, t.name, t.location
           FROM auto_sync_token_links l
           JOIN tokens t ON t.id = l.token_id
          WHERE l.config_id = $1 AND l.last_seen_generation < $2
            AND t.workspace_id = $3 AND t.source_provider = $4
            AND t.source_instance = $5 AND t.source_owner_key = $6
            AND t.source_kind = $7
            AND (t.source_observed_at IS NULL OR t.source_observed_at <= $8)
            ${sql}
            AND NOT EXISTS (
              SELECT 1 FROM integration_scan_items si
               WHERE si.scan_id = $9 AND si.source_kind = t.source_kind
                 AND si.source_object_id = t.source_object_id)
          ORDER BY t.id FOR UPDATE OF t`,
        [context.configId, context.generation, context.workspaceId,
          context.provider, scan.source_instance, scan.source_owner_key,
          String(scope.sourceKind), scan.started_at, scan.id, ...params],
      );
      for (const token of candidates.rows) {
        const detached = await client.query(
          "DELETE FROM auto_sync_token_links WHERE config_id = $1 AND token_id = $2 RETURNING token_id",
          [context.configId, token.id],
        );
        if (!detached.rowCount) continue;
        result.detached++;
        await client.query(
          `INSERT INTO auto_sync_token_link_events
            (token_id, token_id_snapshot, workspace_id, config_id, config_name, run_id, event, reason)
           VALUES ($1, $1, $2, $3, $4, $5, 'detached', 'complete_scan_absence')`,
          [token.id, context.workspaceId, context.configId, config.connection_key, context.runId],
        );
        if (token.auto_sync_managed) {
          const stillTracked = await client.query(
            "SELECT 1 FROM auto_sync_token_links WHERE token_id = $1 LIMIT 1",
            [token.id],
          );
          if (stillTracked.rowCount) continue;
          await client.query("DELETE FROM alert_queue WHERE token_id = $1", [token.id]);
          await client.query("DELETE FROM domain_monitors WHERE token_id = $1", [token.id]);
          const deleted = await client.query(
            `DELETE FROM tokens t WHERE t.id = $1 AND t.auto_sync_managed = TRUE
               AND NOT EXISTS (SELECT 1 FROM auto_sync_token_links l WHERE l.token_id = t.id)
             RETURNING t.id`,
            [token.id],
          );
          result.deleted += deleted.rowCount;
        }
      }
    }
    }
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

module.exports = {
  multiConfigEnabled,
  normalizeConnectionName,
  scanSettingsEqual,
  sanitizePublicAutoSyncError,
  assertRunFence,
  resolveAutoSyncImportContext,
  attachObservedToken,
  withFencedImport,
  reconcileAutoSyncRun,
};
