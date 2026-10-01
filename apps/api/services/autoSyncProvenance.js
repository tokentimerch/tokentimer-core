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

function validateAutoSyncSettings(body) {
  if (body.frequency !== undefined && !["daily", "weekly", "monthly"].includes(body.frequency)) return "Invalid frequency";
  if (body.schedule_time !== undefined && (typeof body.schedule_time !== "string" || !/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(body.schedule_time))) return "Invalid schedule time";
  if (body.schedule_tz !== undefined) {
    if (typeof body.schedule_tz !== "string" || body.schedule_tz.length > 100) return "Invalid schedule timezone";
    try { new Intl.DateTimeFormat("en", { timeZone: body.schedule_tz }).format(); }
    catch (_) { return "Invalid schedule timezone"; }
  }
  for (const key of ["enabled", "cleanup_obsolete"]) if (body[key] !== undefined && typeof body[key] !== "boolean") return `Invalid ${key}`;
  if (body.scan_params !== undefined && (!body.scan_params || typeof body.scan_params !== "object" || Array.isArray(body.scan_params))) return "Invalid scan parameters";
  return null;
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

// Public errors are controlled messages, never provider response bodies or item names.
function sanitizePublicAutoSyncError(value) {
  if (value == null) return null;
  const text = String(value);
  const safe = /^(?:Provider request failed \(HTTP \d{3}\)\.|Provider request timed out\.|Auto-sync failed; review provider access and scan settings\.|Scan or import was incomplete; associations were retained\.|Scan found \d+ item\(s\) but none were imported \(all failed validation or were rejected\)\.|\d+ of \d+ scanned item\(s\) failed to import\.)$/;
  return safe.test(text) ? text : "Auto-sync failed; review provider access and scan settings.";
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

function parseAutoSyncContext(req, workspaceId, provider) {
  const body = req.body?.auto_sync_run;
  if (!body) return null;
  const context = { configId: body.config_id, runId: body.run_id,
    generation: Number(body.generation), scanVersion: Number(body.scan_version),
    leaseOwner: body.lease_owner, workspaceId, provider };
  if (!req.isWorkerCall || !UUID.test(String(context.configId)) ||
      !UUID.test(String(context.runId)) || !UUID.test(String(context.leaseOwner)) ||
      !Number.isSafeInteger(context.generation) || context.generation < 1 ||
      !Number.isSafeInteger(context.scanVersion) || context.scanVersion < 1) {
    const error = new Error("Invalid auto-sync run context");
    error.code = "AUTO_SYNC_RUN_INVALID";
    throw error;
  }
  return context;
}

async function resolveAutoSyncImportContext(req, workspaceId, provider, scanId) {
  const context = parseAutoSyncContext(req, workspaceId, provider);
  if (!context) {
    if (req.isWorkerCall && await multiConfigEnabled()) {
      const error = new Error("Fenced auto-sync run is required");
      error.code = "AUTO_SYNC_RUN_REQUIRED";
      throw error;
    }
    return null;
  }
  if (!UUID.test(String(scanId))) {
    const error = new Error("Invalid auto-sync scan");
    error.code = "AUTO_SYNC_SCAN_INVALID";
    throw error;
  }
  context.scanId = scanId;
  await withFencedImport(context, async (client) => {
    const scan = await getScan({ scanId, workspaceId, provider, client });
    const bound = await client.query(
      "SELECT 1 FROM auto_sync_run_scans WHERE run_id = $1 AND scan_id = $2",
      [context.runId, scanId]);
    if (!scan?.completed_at || !bound.rowCount) {
      const error = new Error("Auto-sync scan is incomplete or does not belong to this run");
      error.code = "AUTO_SYNC_SCAN_INVALID";
      throw error;
    }
    const scopes = scan.cleanup_scope?.subScopes;
    context.scanComplete = Array.isArray(scopes) && scopes.length > 0 && scopes.every(scope => scope.complete === true);
  });
  return context;
}

async function withFencedImport(context, work) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    if (context) await assertRunFence(client, context);
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

async function upsertImportedToken({ context, payload, workspaceId, userId, manual, assignMembership }) {
  const Token = require("../db/models/Token");
  return withFencedImport(context, async (client) => {
    if (context && !payload.source_object_id) throw new Error("Auto-sync item is not part of its persisted scan");
    const keys = [JSON.stringify([workspaceId, "name", payload.name, payload.location])];
    if (payload.source_object_id) keys.push(JSON.stringify([workspaceId, "source",
      payload.source_provider, payload.source_instance, payload.source_owner_key,
      payload.source_kind, payload.source_object_id]));
    for (const key of keys.sort()) {
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [key]);
    }
    let existing = payload.source_object_id ? await Token.findBySourceIdentity({
      workspaceId, sourceProvider: payload.source_provider, sourceInstance: payload.source_instance,
      sourceOwnerKey: payload.source_owner_key, sourceKind: payload.source_kind,
      sourceObjectId: payload.source_object_id,
    }, { client }) : await Token.findByNameLocationAndWorkspace(payload.name, payload.location, workspaceId, { client });
    if (!existing && payload.source_object_id) {
      existing = await Token.findUnattributedByNameLocation(payload.name, payload.location, workspaceId, { client });
    }
    assignMembership(payload, { isCreate: !existing });
    const token = existing ? await Token.update(existing.id, {
      ...payload, ...(manual ? { auto_sync_managed: false } : {}),
    }, { client }) : await Token.create({ ...payload, userId, workspaceId,
      created_by: userId, imported_at: new Date() }, { client });
    if (context) await attachObservedToken(context, token.id, !existing, { client });
    return { token, created: !existing };
  });
}

async function recordAutoSyncImportErrors(context, count) {
  if (!context || count === 0) return;
  await withFencedImport(context, (client) => client.query(
    "UPDATE auto_sync_runs SET import_error_count = import_error_count + $2 WHERE run_id = $1",
    [context.runId, count]));
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
    const bound = await client.query("SELECT scan_id FROM auto_sync_run_scans WHERE run_id = $1", [context.runId]);
    if (bound.rows.length !== scanIds.length || bound.rows.some((row) => !scanIds.includes(row.scan_id))) {
      throw new Error("Cleanup must include every scan belonging to this run");
    }
    const importState = await client.query("SELECT import_error_count FROM auto_sync_runs WHERE run_id = $1", [context.runId]);
    if (Number(importState.rows[0]?.import_error_count) > 0) {
      await client.query("COMMIT");
      return result;
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
      // Completeness includes importing every observed item, across every request/batch.
      const missing = await client.query(`SELECT 1 FROM integration_scan_items si
        WHERE si.scan_id = $1 AND NOT EXISTS (
          SELECT 1 FROM tokens t JOIN auto_sync_token_links l ON l.token_id = t.id
          WHERE l.config_id = $2 AND l.last_seen_generation = $3 AND t.workspace_id = $4
            AND t.source_provider = $5 AND t.source_instance = $6 AND t.source_owner_key = $7
            AND t.source_kind = si.source_kind AND t.source_object_id = si.source_object_id) LIMIT 1`,
        [scan.id, context.configId, context.generation, context.workspaceId,
          context.provider, scan.source_instance, scan.source_owner_key]);
      if (missing.rowCount) {
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
  parseAutoSyncContext,
  normalizeConnectionName,
  validateAutoSyncSettings,
  scanSettingsEqual,
  sanitizePublicAutoSyncError,
  assertRunFence,
  resolveAutoSyncImportContext,
  attachObservedToken,
  withFencedImport,
  upsertImportedToken,
  recordAutoSyncImportErrors,
  reconcileAutoSyncRun,
};
