import crypto from "crypto";
import { computeNextSync } from "./autoSyncSchedule.js";
import { pool } from "../db.js";

export function settingsSnapshot(config) {
  const params = config.scan_params || {};
  const snapshot = { cleanup_obsolete: config.cleanup_obsolete === true };
  // Values are scope/filter metadata, never the credential object or arbitrary scan_params keys.
  for (const key of ["scanMode", "region", "projectId", "subscriptionId", "tenantId", "pathPrefix", "namespace", "authMount", "authMethod"])
    if (typeof params[key] === "string") snapshot[key] = params[key].slice(0, 500);
  for (const key of ["maxItems", "maxItemsPerMount"])
    if (Number.isSafeInteger(params[key])) snapshot[key] = params[key];
  for (const key of ["mounts", "categories", "detectedRegions"])
    if (Array.isArray(params[key])) snapshot[key] = params[key].filter((v) => typeof v === "string").map((v) => v.slice(0, 500));
  snapshot.include = Object.fromEntries(Object.entries(params.include || {}).filter(([, v]) => typeof v === "boolean"));
  snapshot.filters = Object.fromEntries(Object.entries(params.filters || {}).filter(([k, v]) =>
    (typeof v === "boolean" || (["search", "projectIds", "groupIds"].includes(k) &&
    (typeof v === "string" || (Array.isArray(v) && v.every((item) => typeof item === "string" || Number.isSafeInteger(item))))))));
  snapshot.filterRules = (Array.isArray(params.filterRules) ? params.filterRules : []).map((rule) =>
    Object.fromEntries(Object.entries(rule || {}).filter(([k, v]) => ["field", "matchType", "value", "action"].includes(k) && typeof v === "string").map(([k, v]) => [k, v.slice(0, 500)])));
  return snapshot;
}

export async function claimDueAutoSyncRuns(limit = 10) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query(
      `SELECT * FROM auto_sync_configs
        WHERE enabled = TRUE
          AND (lease_until IS NULL OR lease_until <= NOW())
          AND (next_sync_at <= NOW()
            OR (active_run_id IS NOT NULL AND lease_until <= NOW()))
        ORDER BY next_sync_at, id LIMIT $1 FOR UPDATE SKIP LOCKED`,
      [limit],
    );
    const claimed = [];
    for (const config of rows) {
      const runId = crypto.randomUUID();
      const leaseOwner = crypto.randomUUID();
      const generation = Number(config.run_generation) + 1;
      const trigger = config.pending_manual_run ? "manual" :
        config.pending_replacement_run ? "replacement" : "schedule";
      await client.query(
        `UPDATE auto_sync_runs SET status = 'superseded', finished_at = NOW()
          WHERE run_id = $1 AND status = 'running'`,
        [config.active_run_id],
      );
      await client.query(
        `UPDATE auto_sync_configs SET run_generation = $2, active_run_id = $3,
           lease_owner = $4, lease_until = NOW() + INTERVAL '300 seconds',
           pending_manual_run = FALSE, pending_replacement_run = FALSE,
           next_sync_at = NOW() + INTERVAL '1 day', updated_at = NOW()
         WHERE id = $1`,
        [config.id, generation, runId, leaseOwner],
      );
      await client.query(
        `INSERT INTO auto_sync_runs
          (run_id, config_id, config_id_snapshot, workspace_id, provider,
           name_snapshot, trigger, generation, scan_version, settings_snapshot, status)
         VALUES ($1,$2,$2,$3,$4,$5,$6,$7,$8,$9,'running')`,
        [runId, config.id, config.workspace_id, config.provider,
          config.connection_key, trigger, generation, config.scan_version,
          JSON.stringify(settingsSnapshot(config))],
      );
      claimed.push({ ...config, runId, leaseOwner, generation,
        scanVersion: config.scan_version, trigger });
    }
    await client.query("COMMIT");
    return claimed;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export function runContext(config) {
  return { config_id: config.id, run_id: config.runId,
    generation: config.generation, scan_version: config.scanVersion,
    lease_owner: config.leaseOwner, provider: config.provider };
}

export async function renewAutoSyncLease(config) {
  const result = await pool.query(
    `UPDATE auto_sync_configs SET lease_until = NOW() + INTERVAL '300 seconds'
      WHERE id = $1 AND active_run_id = $2 AND run_generation = $3
        AND scan_version = $4 AND lease_owner = $5 AND enabled = TRUE
        AND lease_until > NOW()`,
    [config.id, config.runId, config.generation, config.scanVersion,
      config.leaseOwner],
  );
  return result.rowCount === 1;
}

export async function withCurrentRun(config, callback) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const lock = await client.query(
      `SELECT id FROM auto_sync_configs WHERE id = $1 AND active_run_id = $2
        AND run_generation = $3 AND scan_version = $4 AND lease_owner = $5
        AND lease_until > NOW() AND enabled = TRUE FOR UPDATE`,
      [config.id, config.runId, config.generation, config.scanVersion, config.leaseOwner],
    );
    if (!lock.rowCount) {
      await client.query("ROLLBACK");
      return false;
    }
    await callback(client);
    await client.query("COMMIT");
    return true;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export async function finishAutoSyncRun(client, config, result) {
  await client.query(
    `UPDATE auto_sync_runs SET finished_at = NOW(), status = $2,
       discovered_count = $3, created_count = $4, updated_count = $5,
       detached_count = $6, deleted_count = $7, error_count = $8, error_text = $9
     WHERE run_id = $1 AND status = 'running'`,
    [config.runId, result.status, result.discovered || 0, result.created || 0,
      result.updated || 0, result.detached || 0, result.deleted || 0,
      result.errors || 0, result.error || null],
  );
  const current = await client.query("SELECT frequency, schedule_time, schedule_tz FROM auto_sync_configs WHERE id = $1 FOR UPDATE", [config.id]);
  const schedule = current.rows[0];
  const nextSync = computeNextSync(schedule.frequency, schedule.schedule_time, schedule.schedule_tz);
  await client.query(
    `UPDATE auto_sync_configs SET active_run_id = NULL, lease_owner = NULL,
       lease_until = NULL, next_sync_at = CASE
         WHEN pending_manual_run OR pending_replacement_run THEN NOW()
         ELSE $2 END, updated_at = NOW() WHERE id = $1`,
    [config.id, nextSync],
  );
}
