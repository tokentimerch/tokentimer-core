"use strict";

const crypto = require("crypto");

const { pool } = require("../../db/database");
const {
  CERTOPS_JOB_NOT_FOUND,
  normalizePublicObject,
  normalizeRequiredId,
  normalizeWorkspaceId,
  serviceError,
} = require("./jobs");

const CERTOPS_EXECUTOR_EVENT_CONFLICT = "CERTOPS_EXECUTOR_EVENT_CONFLICT";
const CERTOPS_EXECUTOR_EVENT_INVALID = "CERTOPS_EXECUTOR_EVENT_INVALID";

const SAFE_EXECUTOR_EVENT_SELECT_FIELDS = `
  id,
  workspace_id,
  job_id,
  executor_event_id,
  event_type,
  request_hash_sha256,
  response_metadata,
  created_by_api_token_id,
  created_at
`;

function parseJsonb(value) {
  if (value === null || value === undefined) return {};
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch (_error) {
      return {};
    }
  }
  return value;
}

function dateToIso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function executorEventFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    jobId: row.job_id,
    executorEventId: row.executor_event_id,
    eventType: row.event_type,
    requestHashSha256: row.request_hash_sha256,
    responseMetadata: parseJsonb(row.response_metadata),
    createdByApiTokenId: row.created_by_api_token_id,
    createdAt: dateToIso(row.created_at),
  };
}

function stableJson(value) {
  if (value === null || value === undefined) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item)).join(",")}]`;
  }
  if (typeof value === "object" && !Buffer.isBuffer(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys
      .filter((key) => value[key] !== undefined)
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(String(value));
}

function hashExecutorEventPayload(value) {
  return crypto.createHash("sha256").update(stableJson(value)).digest("hex");
}

function normalizeEventType(value) {
  const eventType = typeof value === "string" ? value.trim() : "";
  if (!eventType || eventType.length > 128) {
    throw serviceError("Executor event type is invalid", CERTOPS_EXECUTOR_EVENT_INVALID);
  }
  return eventType;
}

function normalizeRequestHash(value) {
  const hash = typeof value === "string" ? value.trim() : "";
  if (!/^[a-f0-9]{64}$/.test(hash)) {
    throw serviceError(
      "Executor event request hash is invalid",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }
  return hash;
}

async function ensureJobExists(client, workspaceId, jobId) {
  const result = await client.query(
    `SELECT id
       FROM certificate_jobs
      WHERE workspace_id = $1
        AND id = $2
      LIMIT 1
      FOR SHARE`,
    [workspaceId, jobId],
  );
  if (!result.rows[0]) {
    throw serviceError("Certificate job not found", CERTOPS_JOB_NOT_FOUND);
  }
}

async function runExecutorEventIdempotently(options, performSideEffects) {
  if (typeof performSideEffects !== "function") {
    throw serviceError(
      "Executor event side effect handler is required",
      CERTOPS_EXECUTOR_EVENT_INVALID,
    );
  }

  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const jobId = normalizeRequiredId(options.jobId, CERTOPS_EXECUTOR_EVENT_INVALID);
  const executorEventId = normalizeRequiredId(
    options.executorEventId,
    CERTOPS_EXECUTOR_EVENT_INVALID,
  );
  const eventType = normalizeEventType(options.eventType);
  const requestHashSha256 = normalizeRequestHash(options.requestHashSha256);
  const createdByApiTokenId = options.createdByApiTokenId || null;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureJobExists(client, workspaceId, jobId);

    const inserted = await client.query(
      `INSERT INTO certificate_executor_events (
         workspace_id,
         job_id,
         executor_event_id,
         event_type,
         request_hash_sha256,
         response_metadata,
         created_by_api_token_id
       )
       VALUES ($1, $2, $3, $4, $5, '{}'::jsonb, $6)
       ON CONFLICT (workspace_id, job_id, executor_event_id) DO NOTHING
       RETURNING ${SAFE_EXECUTOR_EVENT_SELECT_FIELDS}`,
      [
        workspaceId,
        jobId,
        executorEventId,
        eventType,
        requestHashSha256,
        createdByApiTokenId,
      ],
    );

    if (!inserted.rows[0]) {
      const existingResult = await client.query(
        `SELECT ${SAFE_EXECUTOR_EVENT_SELECT_FIELDS}
           FROM certificate_executor_events
          WHERE workspace_id = $1
            AND job_id = $2
            AND executor_event_id = $3
          LIMIT 1
          FOR UPDATE`,
        [workspaceId, jobId, executorEventId],
      );
      const existing = executorEventFromRow(existingResult.rows[0]);
      if (!existing || existing.requestHashSha256 !== requestHashSha256) {
        throw serviceError(
          "Executor event idempotency key conflicts with a different payload",
          CERTOPS_EXECUTOR_EVENT_CONFLICT,
        );
      }
      await client.query("COMMIT");
      return {
        duplicate: true,
        idempotent: true,
        record: existing,
        responseMetadata: existing.responseMetadata || {},
      };
    }

    const insertedRecord = executorEventFromRow(inserted.rows[0]);
    const sideEffectMetadata = await performSideEffects(client, insertedRecord);
    const responseMetadata = normalizePublicObject(
      {
        ...(sideEffectMetadata || {}),
        executorEventRecordId: insertedRecord.id,
      },
      "responseMetadata",
    );
    const updated = await client.query(
      `UPDATE certificate_executor_events
          SET response_metadata = $4::jsonb
        WHERE workspace_id = $1
          AND job_id = $2
          AND executor_event_id = $3
        RETURNING ${SAFE_EXECUTOR_EVENT_SELECT_FIELDS}`,
      [
        workspaceId,
        jobId,
        executorEventId,
        JSON.stringify(responseMetadata),
      ],
    );

    await client.query("COMMIT");
    const record = executorEventFromRow(updated.rows[0]);
    return {
      duplicate: false,
      idempotent: false,
      record,
      responseMetadata: record.responseMetadata || responseMetadata,
    };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackError) {
      // Prefer the original error; rollback errors are not actionable here.
    }
    throw error;
  } finally {
    client.release();
  }
}

module.exports = {
  CERTOPS_EXECUTOR_EVENT_CONFLICT,
  CERTOPS_EXECUTOR_EVENT_INVALID,
  executorEventFromRow,
  hashExecutorEventPayload,
  runExecutorEventIdempotently,
  _test: {
    stableJson,
  },
};
