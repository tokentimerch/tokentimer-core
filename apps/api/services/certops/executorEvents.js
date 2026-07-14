"use strict";

const crypto = require("crypto");

const { pool } = require("../../db/database");
const { CERTOPS_JOB_NOT_FOUND, serviceError } = require("./jobs");

const CERTOPS_EXECUTOR_EVENT_CONFLICT = "CERTOPS_EXECUTOR_EVENT_CONFLICT";

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalize(value[key])]),
  );
}

function requestHash(value) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(canonicalize(value)))
    .digest("hex");
}

function parseResponse(value) {
  if (!value) return null;
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch (_error) {
      return null;
    }
  }
  return value;
}

function idempotencyConflict() {
  return serviceError(
    "Executor event ID was already used with a different event",
    CERTOPS_EXECUTOR_EVENT_CONFLICT,
  );
}

function storedResponseForReplay(value) {
  const response = parseResponse(value);
  // A committed event always stores this complete, safe response in the same
  // transaction as its side effects. Never turn a malformed historical row
  // into a successful replay with an empty response.
  if (
    !response ||
    typeof response !== "object" ||
    Array.isArray(response) ||
    response.ok !== true ||
    typeof response.eventId !== "string" ||
    typeof response.logId !== "string" ||
    typeof response.jobId !== "string" ||
    typeof response.status !== "string" ||
    !Array.isArray(response.evidenceIds) ||
    typeof response.redactionApplied !== "boolean" ||
    !Number.isInteger(response.redactionCount) ||
    response.redactionCount < 0
  ) {
    throw idempotencyConflict();
  }
  return response;
}

async function findExecutorEvent(client, workspaceId, jobId, eventId) {
  const result = await client.query(
    `SELECT id, request_hash, response
       FROM certificate_executor_events
      WHERE workspace_id = $1
        AND job_id = $2
        AND executor_event_id = $3
      LIMIT 1`,
    [workspaceId, jobId, eventId],
  );
  return result.rows[0] || null;
}

async function lockJob(client, workspaceId, jobId) {
  const result = await client.query(
    `SELECT id
       FROM certificate_jobs
      WHERE workspace_id = $1
        AND id = $2
      FOR UPDATE`,
    [workspaceId, jobId],
  );
  if (!result.rows[0]) {
    throw serviceError("Certificate job not found", CERTOPS_JOB_NOT_FOUND);
  }
}

async function insertExecutorEvent({
  client,
  workspaceId,
  jobId,
  eventId,
  hash,
  apiTokenId,
}) {
  const result = await client.query(
    `INSERT INTO certificate_executor_events (
       workspace_id,
       job_id,
       executor_event_id,
       request_hash,
       created_by_api_token_id
     )
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (workspace_id, job_id, executor_event_id) DO NOTHING
     RETURNING id`,
    [workspaceId, jobId, eventId, hash, apiTokenId || null],
  );
  return result.rows[0] || null;
}

async function storeExecutorEventResponse(client, id, response) {
  await client.query(
    `UPDATE certificate_executor_events
        SET response = $2::jsonb,
            status = 'accepted'
      WHERE id = $1`,
    [id, JSON.stringify(response)],
  );
}

async function ingestExecutorEvent({
  workspaceId,
  jobId,
  eventId,
  request,
  apiTokenId,
  process,
}) {
  const hash = requestHash(request);
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const existing = await findExecutorEvent(client, workspaceId, jobId, eventId);
    if (existing) {
      if (existing.request_hash !== hash) throw idempotencyConflict();
      const response = storedResponseForReplay(existing.response);
      await client.query("COMMIT");
      return { response, duplicate: true };
    }

    // Serializing event processing on the job also closes the gap between a
    // replay lookup and unique-key reservation by another executor retry.
    await lockJob(client, workspaceId, jobId);
    const inserted = await insertExecutorEvent({
      client,
      workspaceId,
      jobId,
      eventId,
      hash,
      apiTokenId,
    });

    if (!inserted) {
      const replay = await findExecutorEvent(client, workspaceId, jobId, eventId);
      if (!replay || replay.request_hash !== hash) throw idempotencyConflict();
      const response = storedResponseForReplay(replay.response);
      await client.query("COMMIT");
      return { response, duplicate: true };
    }

    const response = await process(client, { id: inserted.id });
    await storeExecutorEventResponse(client, inserted.id, response);
    await client.query("COMMIT");
    return { response, duplicate: false };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackError) {
      // The original persistence error is more useful to the caller.
    }
    throw error;
  } finally {
    client.release();
  }
}

module.exports = {
  CERTOPS_EXECUTOR_EVENT_CONFLICT,
  ingestExecutorEvent,
  _test: {
    canonicalize,
    requestHash,
    storedResponseForReplay,
  },
};
