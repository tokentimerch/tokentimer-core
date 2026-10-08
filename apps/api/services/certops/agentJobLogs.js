"use strict";

/**
 * Curated agent execution-console ingest.
 *
 * Lock order, every path: job_state, then stream, then daily quota.
 * A later lock may be skipped. Taking them out of order can deadlock.
 * Log failures must not fail certificate execution; callers that run inside
 * a job transaction use a savepoint.
 */

const crypto = require("node:crypto");
const client = require("prom-client");
const { pool } = require("../../db/database");
const { writeAudit } = require("../audit");
const { logger } = require("../../utils/logger");
const {
  scrubAgentLogText,
  scrubAgentLogFields,
} = require("../../../../packages/log-scrub/agent-log-text");

const JOB_LOG_STREAM_CAPABILITY = "job-log-stream-v1";
const MAX_BATCH_BYTES = 64 * 1024;
const CLAIM_LINE_CAP = 5000;
const CLAIM_BYTE_CAP = 1024 * 1024;
const ACCEPT_GRACE_MS = 5 * 60 * 1000;
const STREAM_RETENTION_EXTRA_DAYS = 30;
const QUOTA_ROW_KEEP_DAYS = 7;

const CERTOPS_AGENT_LOG_PRIVATE_MATERIAL = "CERTOPS_AGENT_LOG_PRIVATE_MATERIAL";
const CERTOPS_AGENT_LOG_CLAIM_INVALID = "CERTOPS_AGENT_LOG_CLAIM_INVALID";
const CERTOPS_AGENT_LOG_CLOSED = "CERTOPS_AGENT_LOG_CLOSED";
const CERTOPS_AGENT_LOG_INVALID = "CERTOPS_AGENT_LOG_INVALID";

const LOCK_ORDER = Object.freeze(["job_state", "stream", "quota"]);
const OPERATION_LOCKS = Object.freeze({
  claimOpen: Object.freeze(["job_state", "stream"]),
  close: Object.freeze(["job_state", "stream"]),
  ingest: Object.freeze(["job_state", "stream", "quota"]),
  abandon: Object.freeze(["job_state", "stream"]),
  purgeStream: Object.freeze(["job_state", "stream"]),
});

const TERMINAL_JOB_STATUSES = new Set([
  "rejected",
  "succeeded",
  "failed",
  "blocked",
  "cancelled",
  "dry_run_complete",
  "orphaned_unknown_effect",
]);
const CLOSED_STREAM_STATUSES = new Set(["final", "abandoned", "disabled"]);
const ZERO_DELTA = Object.freeze({ quotaBytes: 0, quotaLines: 0, serverDropped: 0 });

function metric(factory, config) {
  return client.register.getSingleMetric(config.name) || factory(config);
}

const batchesTotal = metric((cfg) => new client.Counter(cfg), {
  name: "certops_agent_log_batches_total",
  help: "Agent execution-console batches by outcome",
  labelNames: ["outcome"],
});
const linesDroppedTotal = metric((cfg) => new client.Counter(cfg), {
  name: "certops_agent_log_lines_dropped_total",
  help: "Agent execution-console lines dropped",
  labelNames: ["side", "reason"],
});
const ingestSeconds = metric((cfg) => new client.Histogram(cfg), {
  name: "certops_agent_log_ingest_seconds",
  help: "Agent execution-console ingest latency",
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1],
});
const quotaExhaustedTotal = metric((cfg) => new client.Counter(cfg), {
  name: "certops_agent_log_quota_exhausted_total",
  help: "Agent execution-console batches that hit a storage quota",
});

function noteMetric(fn) {
  try {
    fn();
  } catch (_error) {
    // Metrics must not change ingest or job execution.
  }
}

function resolveRetentionDays(env = process.env) {
  const raw = env.CERTOPS_AGENT_LOG_RETENTION_DAYS;
  if (raw == null || String(raw).trim() === "") return 30;
  const parsed = Number.parseInt(String(raw).trim(), 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return 30;
  return parsed;
}

function storageEnabled(env = process.env) {
  return resolveRetentionDays(env) !== 0;
}

function resolveDailyByteLimit(env = process.env) {
  const raw = env.CERTOPS_AGENT_LOG_DAILY_BYTES;
  if (raw == null || String(raw).trim() === "" || String(raw).trim() === "0") return 0;
  const parsed = Number.parseInt(String(raw).trim(), 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return 0;
  return parsed;
}

function assertLockSequence(names) {
  let previous = -1;
  for (const name of names) {
    const index = LOCK_ORDER.indexOf(name);
    if (index === -1 || index <= previous) {
      throw new Error(`agent log lock order violated at ${name}`);
    }
    previous = index;
  }
}

function contentHash(line) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify({
      level: line.level,
      step: line.step,
      message: line.message,
      fields: line.fields || null,
    }))
    .digest("hex");
}

function batchKeyOf(lines, final) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify({
      final: Boolean(final),
      lines: lines.map((line) => [line.seq, line.hash]),
    }))
    .digest("hex");
}

function disabledAck(state) {
  return {
    ackThroughSeq: state.resolvedThroughSeq || 0,
    newlyStored: 0,
    duplicateCount: 0,
    serverDroppedCount: 0,
    streamDisabled: true,
    retryAfterMs: null,
  };
}

function emptyAck(resolvedThroughSeq, duplicateCount = 0) {
  return {
    ackThroughSeq: resolvedThroughSeq,
    newlyStored: 0,
    duplicateCount,
    serverDroppedCount: 0,
    streamDisabled: false,
    retryAfterMs: null,
  };
}

/**
 * newlyStored and serverDroppedCount describe this batch's first resolution.
 * A retry of the same batch returns that stored ack. Counters and quota do
 * not move again. Per-request numbers on a replay are therefore stable, not
 * a second charge and not a cumulative total.
 */
function resolveIngest(state, batch, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date();
  const maxLines = options.maxLines ?? CLAIM_LINE_CAP;
  const maxBytes = options.maxBytes ?? CLAIM_BYTE_CAP;
  const quotaLimit = options.quotaLimitBytes ?? 0;
  let quotaUsed = options.quotaUsedBytes ?? 0;

  if (state.lastBatchKey && state.lastBatchKey === batch.key) {
    return {
      kind: "replay",
      httpStatus: state.lastHttpStatus || 200,
      ack: state.lastAck,
      nextState: state,
      delta: ZERO_DELTA,
      inserts: [],
    };
  }

  if (!state.streamingEnabled || state.status === "disabled") {
    return {
      kind: "disabled",
      httpStatus: 200,
      ack: disabledAck(state),
      nextState: state,
      delta: ZERO_DELTA,
      inserts: [],
    };
  }

  if (state.status === "abandoned") {
    return { kind: "closed", httpStatus: 409, code: CERTOPS_AGENT_LOG_CLOSED };
  }

  const acceptUntil = state.acceptUntil ? new Date(state.acceptUntil) : null;
  const windowClosed = Boolean(acceptUntil && acceptUntil.getTime() <= now.getTime());
  const seqs = batch.lines.map((line) => line.seq);
  const allResolved = seqs.every((seq) => seq <= state.resolvedThroughSeq);
  if (state.status === "final" || windowClosed) {
    if ((batch.final && batch.lines.length === 0) || allResolved) {
      return {
        kind: "replay",
        httpStatus: 200,
        ack: emptyAck(state.resolvedThroughSeq, seqs.length),
        nextState: state,
        delta: ZERO_DELTA,
        inserts: [],
      };
    }
    return { kind: "closed", httpStatus: 409, code: CERTOPS_AGENT_LOG_CLOSED };
  }

  if (batch.rejected) {
    const nextState = {
      ...state,
      rejectedBatches: state.rejectedBatches + 1,
      lastBatchKey: batch.key,
      lastAck: {
        error: "Agent log batch rejected",
        code: CERTOPS_AGENT_LOG_PRIVATE_MATERIAL,
      },
      lastHttpStatus: 422,
    };
    return {
      kind: "rejected",
      httpStatus: 422,
      code: CERTOPS_AGENT_LOG_PRIVATE_MATERIAL,
      ack: nextState.lastAck,
      nextState,
      delta: ZERO_DELTA,
      inserts: [],
    };
  }

  if (batch.lines.length > 0) {
    const sorted = [...batch.lines].sort((a, b) => a.seq - b.seq);
    for (let i = 1; i < sorted.length; i += 1) {
      if (sorted[i].seq !== sorted[i - 1].seq + 1) {
        return { kind: "invalid", httpStatus: 400, code: CERTOPS_AGENT_LOG_INVALID };
      }
    }
  }

  let resolved = state.resolvedThroughSeq;
  let acceptedLines = state.acceptedLines;
  let acceptedBytes = state.acceptedBytes;
  let serverDroppedLines = state.serverDroppedLines;
  let agentGapLines = state.agentGapLines;
  let conflictCount = state.conflictCount;
  const conflicts = { ...(state.conflicts || {}) };
  const stored = { ...(state.stored || {}) };
  const inserts = [];
  let newlyStored = 0;
  let serverDroppedCount = 0;
  let duplicateCount = 0;
  let quotaBytes = 0;
  let quotaLines = 0;
  let sawNew = false;

  const ordered = [...batch.lines].sort((a, b) => a.seq - b.seq);
  for (const line of ordered) {
    if (line.seq <= resolved) {
      const previous = stored[line.seq];
      if (previous && previous !== line.hash) {
        if (conflicts[line.seq] !== line.hash) {
          conflicts[line.seq] = line.hash;
          conflictCount += 1;
        }
      } else {
        duplicateCount += 1;
      }
      continue;
    }
    if (!sawNew) {
      sawNew = true;
      if (line.seq > resolved + 1) agentGapLines += line.seq - resolved - 1;
    }
    const overClaim = acceptedLines + 1 > maxLines || acceptedBytes + line.bytes > maxBytes;
    const overQuota = quotaLimit > 0 && quotaUsed + line.bytes > quotaLimit;
    if (overClaim || overQuota) {
      serverDroppedLines += 1;
      serverDroppedCount += 1;
      resolved = line.seq;
      continue;
    }
    inserts.push(line);
    stored[line.seq] = line.hash;
    acceptedLines += 1;
    acceptedBytes += line.bytes;
    quotaUsed += line.bytes;
    quotaBytes += line.bytes;
    quotaLines += 1;
    newlyStored += 1;
    resolved = line.seq;
  }

  const ack = {
    ackThroughSeq: resolved,
    newlyStored,
    duplicateCount,
    serverDroppedCount,
    streamDisabled: false,
    retryAfterMs: null,
  };
  let status = state.status === "pending" && (inserts.length > 0 || serverDroppedCount > 0)
    ? "streaming"
    : state.status;
  if (batch.final) status = "final";
  const nextState = {
    ...state,
    status,
    resolvedThroughSeq: resolved,
    acceptedLines,
    acceptedBytes,
    serverDroppedLines,
    agentGapLines,
    conflictCount,
    conflicts,
    stored,
    lastBatchKey: batch.key,
    lastAck: ack,
    lastHttpStatus: 200,
  };
  return {
    kind: "applied",
    httpStatus: 200,
    ack,
    nextState,
    delta: { quotaBytes, quotaLines, serverDropped: serverDroppedCount },
    inserts,
  };
}

function takeIngestOrders(counter, count) {
  const start = counter + 1;
  return {
    next: counter + count,
    orders: Array.from({ length: count }, (_, index) => start + index),
  };
}

function projectRetainedBytes({
  bytesPerJob,
  jobsPerWorkspacePerDay,
  retentionDays,
  workspaces = 1,
}) {
  const days = Math.max(0, Number(retentionDays) || 0);
  return Math.round(
    Number(bytesPerJob) * Number(jobsPerWorkspacePerDay) * days * Number(workspaces),
  );
}

function logsComplete(jobStatus, streams) {
  if (!TERMINAL_JOB_STATUSES.has(jobStatus)) return false;
  return (streams || []).every((stream) => CLOSED_STREAM_STATUSES.has(stream.status));
}

function shouldAbandon(stream, now = new Date()) {
  if (!stream || !["pending", "streaming"].includes(stream.status)) return false;
  if (!stream.acceptUntil) return false;
  return new Date(stream.acceptUntil).getTime() <= now.getTime();
}

function shouldDeleteStream(stream, now, retentionDays) {
  if (!stream?.closedAt) return false;
  if (!CLOSED_STREAM_STATUSES.has(stream.status)) return false;
  const cutoff = now.getTime() - (retentionDays + STREAM_RETENTION_EXTRA_DAYS) * 86400000;
  return new Date(stream.closedAt).getTime() <= cutoff;
}

function scrubIncomingLines(lines, reservedNames) {
  let rejected = false;
  const scrubbed = [];
  for (const line of lines) {
    const message = scrubAgentLogText(line.message);
    if (message.rejected) {
      rejected = true;
      break;
    }
    const fields = scrubAgentLogFields(line.fields, reservedNames);
    if (fields.rejected) {
      rejected = true;
      break;
    }
    const lineRedactions = message.redactions + fields.redactions;
    const stored = {
      seq: line.seq,
      ts: line.ts,
      level: line.level,
      step: line.step,
      message: message.text,
      fields: fields.fields,
      redactions: lineRedactions,
    };
    stored.hash = contentHash(stored);
    stored.bytes = Buffer.byteLength(JSON.stringify({
      message: stored.message,
      fields: stored.fields,
    }), "utf8");
    scrubbed.push(stored);
  }
  return { rejected, lines: rejected ? [] : scrubbed };
}

function rowToState(row, stored) {
  if (!row) return null;
  return {
    streamingEnabled: row.streaming_enabled === true,
    status: row.status,
    acceptUntil: row.accept_until,
    resolvedThroughSeq: Number(row.resolved_through_seq) || 0,
    acceptedLines: row.accepted_lines || 0,
    acceptedBytes: Number(row.accepted_bytes) || 0,
    serverDroppedLines: row.server_dropped_lines || 0,
    agentGapLines: row.agent_gap_lines || 0,
    rejectedBatches: row.rejected_batches || 0,
    conflictCount: row.conflict_count || 0,
    conflicts: row.conflicts || {},
    lastBatchKey: row.last_batch_key,
    lastAck: row.last_ack,
    lastHttpStatus: row.last_http_status,
    stored,
  };
}

async function lockJobState(client, workspaceId, jobId) {
  await client.query(
    `INSERT INTO certops_agent_log_job_state (workspace_id, job_id)
     VALUES ($1::uuid, $2::uuid)
     ON CONFLICT (workspace_id, job_id) DO NOTHING`,
    [workspaceId, jobId],
  );
  const locked = await client.query(
    `SELECT next_ingest_order
       FROM certops_agent_log_job_state
      WHERE workspace_id = $1::uuid AND job_id = $2::uuid
      FOR UPDATE`,
    [workspaceId, jobId],
  );
  return locked.rows[0] || null;
}

async function openStreamForClaim(client, {
  workspaceId,
  jobId,
  claimId,
  agentRowId,
  attemptNumber,
  streamingEnabled,
}) {
  assertLockSequence(OPERATION_LOCKS.claimOpen);
  await lockJobState(client, workspaceId, jobId);
  await client.query(
    `INSERT INTO certops_agent_log_stream (
       workspace_id, job_id, claim_id, agent_id, attempt_number,
       streaming_enabled, status
     )
     VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6,
             CASE WHEN $6 THEN 'pending' ELSE 'disabled' END)
     ON CONFLICT (workspace_id, job_id, claim_id) DO NOTHING`,
    [workspaceId, jobId, claimId, agentRowId, attemptNumber, streamingEnabled === true],
  );
  return {
    enabled: streamingEnabled === true,
    maxBatchBytes: MAX_BATCH_BYTES,
  };
}

async function closeClaimStream(client, { workspaceId, jobId, claimId }) {
  if (!claimId) return { closed: false };
  assertLockSequence(OPERATION_LOCKS.close);
  const jobState = await lockJobState(client, workspaceId, jobId);
  if (!jobState) return { closed: false };
  const updated = await client.query(
    `UPDATE certops_agent_log_stream
        SET closed_at = NOW(),
            accept_until = CASE
              WHEN status IN ('pending', 'streaming')
                THEN COALESCE(accept_until, NOW() + ($4 || ' milliseconds')::interval)
              ELSE accept_until
            END
      WHERE workspace_id = $1::uuid
        AND job_id = $2::uuid
        AND claim_id = $3::uuid
        AND closed_at IS NULL
      RETURNING claim_id`,
    [workspaceId, jobId, claimId, String(ACCEPT_GRACE_MS)],
  );
  return { closed: updated.rows.length > 0 };
}

async function closeClaimStreamSafely(client, args) {
  if (!args?.claimId) return;
  try {
    await client.query("SAVEPOINT agent_log_close");
    await closeClaimStream(client, args);
    await client.query("RELEASE SAVEPOINT agent_log_close");
  } catch (error) {
    try {
      await client.query("ROLLBACK TO SAVEPOINT agent_log_close");
    } catch (_rollbackError) {
      // Preserve the caller's transaction.
    }
    logger.warn("agent log stream close skipped", { code: error?.code || null });
  }
}

function isUuid(value) {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

async function ingestAgentJobLogs({
  dbPool = pool,
  agent,
  jobId,
  body,
  env = process.env,
  reservedNames = new Set(),
  quotaLimitBytes,
} = {}) {
  const started = process.hrtime.bigint();
  try {
    if (!isUuid(jobId) || !isUuid(body?.claimId)) {
      return { httpStatus: 409, body: { error: "Claim is not valid", code: CERTOPS_AGENT_LOG_CLAIM_INVALID } };
    }
    const result = await withTransaction(dbPool, (client) => applyIngest(client, {
      workspaceId: agent.workspaceId,
      agentRowId: agent.id,
      jobId,
      body,
      env,
      reservedNames,
      quotaLimitBytes,
    }));
    noteMetric(() => batchesTotal.inc({ outcome: result.outcome || "ok" }));
    return result;
  } finally {
    noteMetric(() => {
      const seconds = Number(process.hrtime.bigint() - started) / 1e9;
      ingestSeconds.observe(seconds);
    });
  }
}

async function applyIngest(client, { workspaceId, agentRowId, jobId, body, env, reservedNames, quotaLimitBytes }) {
  assertLockSequence(OPERATION_LOCKS.ingest);
  const jobState = await lockJobState(client, workspaceId, jobId);
  if (!jobState) {
    return { httpStatus: 409, outcome: "unknown_claim", body: { error: "Claim is not valid", code: CERTOPS_AGENT_LOG_CLAIM_INVALID } };
  }
  const streamResult = await client.query(
    `SELECT *
       FROM certops_agent_log_stream
      WHERE workspace_id = $1::uuid AND job_id = $2::uuid AND claim_id = $3::uuid
      FOR UPDATE`,
    [workspaceId, jobId, body.claimId],
  );
  const row = streamResult.rows[0];
  if (!row || String(row.agent_id) !== String(agentRowId)) {
    return { httpStatus: 409, outcome: "unknown_claim", body: { error: "Claim is not valid", code: CERTOPS_AGENT_LOG_CLAIM_INVALID } };
  }

  const rawLines = Array.isArray(body.lines) ? body.lines : [];
  const key = batchKeyOf(rawLines.map((line) => ({
    seq: line.seq,
    hash: crypto.createHash("sha256").update(JSON.stringify({
      level: line.level,
      step: line.step,
      message: String(line.message ?? ""),
      fields: line.fields || null,
    })).digest("hex"),
  })), body.final === true);
  const scrubbed = scrubIncomingLines(rawLines, reservedNames);
  const hashedLines = scrubbed.rejected ? [] : scrubbed.lines;
  if (!storageEnabled(env)) {
    return { httpStatus: 200, outcome: "disabled", body: disabledAck(rowToState(row, {})) };
  }
  const seqList = hashedLines.map((line) => line.seq);
  let stored = {};
  if (seqList.length > 0 && !scrubbed.rejected) {
    const existing = await client.query(
      `SELECT seq, content_hash
         FROM certops_agent_job_log
        WHERE workspace_id = $1::uuid AND job_id = $2::uuid AND claim_id = $3::uuid
          AND seq = ANY($4::bigint[])`,
      [workspaceId, jobId, body.claimId, seqList],
    );
    stored = Object.fromEntries(existing.rows.map((item) => [Number(item.seq), item.content_hash]));
  }

  const quotaDay = new Date().toISOString().slice(0, 10);
  const quotaLimit = Number.isInteger(quotaLimitBytes)
    ? quotaLimitBytes
    : resolveDailyByteLimit(env);
  let quotaUsed = 0;
  if (storageEnabled(env) && quotaLimit > 0) {
    await client.query(
      `INSERT INTO certops_agent_log_daily_quota (workspace_id, quota_day)
       VALUES ($1::uuid, $2::date)
       ON CONFLICT (workspace_id, quota_day) DO NOTHING`,
      [workspaceId, quotaDay],
    );
    const quota = await client.query(
      `SELECT used_bytes
         FROM certops_agent_log_daily_quota
        WHERE workspace_id = $1::uuid AND quota_day = $2::date
        FOR UPDATE`,
      [workspaceId, quotaDay],
    );
    quotaUsed = Number(quota.rows[0]?.used_bytes) || 0;
  }

  const decision = resolveIngest(rowToState(row, stored), {
    key,
    lines: hashedLines,
    final: body.final === true,
    rejected: scrubbed.rejected,
  }, {
    quotaUsedBytes: quotaUsed,
    quotaLimitBytes: storageEnabled(env) ? quotaLimit : 0,
  });

  if (decision.kind === "invalid" || decision.kind === "closed") {
    return {
      httpStatus: decision.httpStatus,
      outcome: decision.kind,
      body: { error: "Agent log stream is not accepting lines", code: decision.code },
    };
  }

  if (decision.kind === "applied" && decision.inserts.length > 0) {
    const orders = takeIngestOrders(Number(jobState.next_ingest_order) || 0, decision.inserts.length);
    await client.query(
      `UPDATE certops_agent_log_job_state
          SET next_ingest_order = $3
        WHERE workspace_id = $1::uuid AND job_id = $2::uuid`,
      [workspaceId, jobId, orders.next],
    );
    for (let index = 0; index < decision.inserts.length; index += 1) {
      const line = decision.inserts[index];
      await client.query(
        `INSERT INTO certops_agent_job_log (
           workspace_id, job_id, claim_id, seq, ts, level, step, message,
           fields, redaction_count, content_hash, ingest_order
         )
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::timestamptz, $6, $7, $8,
                 $9::jsonb, $10, $11, $12)`,
        [
          workspaceId,
          jobId,
          body.claimId,
          line.seq,
          line.ts,
          line.level,
          line.step,
          line.message,
          line.fields ? JSON.stringify(line.fields) : null,
          line.redactions || 0,
          line.hash,
          orders.orders[index],
        ],
      );
    }
  }

  if (decision.delta.quotaBytes > 0) {
    const charged = await client.query(
      `UPDATE certops_agent_log_daily_quota
          SET used_bytes = used_bytes + $3,
              used_lines = used_lines + $4
        WHERE workspace_id = $1::uuid
          AND quota_day = $2::date
          AND ($5::bigint = 0 OR used_bytes + $3 <= $5::bigint)
        RETURNING used_bytes`,
      [workspaceId, quotaDay, decision.delta.quotaBytes, decision.delta.quotaLines, quotaLimit],
    );
    if (charged.rows.length === 0 && quotaLimit > 0) {
      noteMetric(() => quotaExhaustedTotal.inc());
    }
  }

  if (decision.kind !== "replay" && decision.kind !== "disabled") {
    const next = decision.nextState;
    await client.query(
      `UPDATE certops_agent_log_stream
          SET status = $4,
              resolved_through_seq = $5,
              accepted_lines = $6,
              accepted_bytes = $7,
              server_dropped_lines = $8,
              agent_gap_lines = $9,
              rejected_batches = $10,
              conflict_count = $11,
              conflicts = $12::jsonb,
              last_batch_key = $13,
              last_ack = $14::jsonb,
              last_http_status = $15,
              first_received_at = COALESCE(first_received_at, NOW()),
              last_received_at = NOW(),
              finalized_at = CASE WHEN $4 = 'final' THEN COALESCE(finalized_at, NOW()) ELSE finalized_at END
        WHERE workspace_id = $1::uuid AND job_id = $2::uuid AND claim_id = $3::uuid`,
      [
        workspaceId,
        jobId,
        body.claimId,
        next.status,
        next.resolvedThroughSeq,
        next.acceptedLines,
        next.acceptedBytes,
        next.serverDroppedLines,
        next.agentGapLines,
        next.rejectedBatches,
        next.conflictCount,
        JSON.stringify(next.conflicts || {}),
        next.lastBatchKey,
        JSON.stringify(next.lastAck),
        next.lastHttpStatus,
      ],
    );
  }

  if (decision.delta.serverDropped > 0) {
    noteMetric(() => linesDroppedTotal.inc({ side: "server", reason: "cap" }, decision.delta.serverDropped));
  }
  if (decision.kind === "rejected") {
    try {
      await writeAudit({
        actorUserId: null,
        subjectUserId: null,
        action: "certops.agent_log.rejected",
        targetType: "certificate_job",
        targetId: null,
        workspaceId,
        metadata: { jobId, claimId: body.claimId, code: CERTOPS_AGENT_LOG_PRIVATE_MATERIAL },
      });
    } catch (error) {
      logger.warn("agent log rejection audit failed", { code: error?.code || null });
    }
  }
  return { httpStatus: decision.httpStatus, outcome: decision.kind, body: decision.ack };
}

async function withTransaction(dbPool, fn) {
  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackError) {
      // The original error is more useful.
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * One short transaction per job. A sweep must never hold two job_state locks:
 * a multi-job claim takes them in its own order, and the two would deadlock.
 * Returns null when the job is gone.
 */
async function withJobStateLock(db, workspaceId, jobId, fn) {
  await db.query("BEGIN");
  try {
    const locked = await db.query(
      `SELECT 1
         FROM certops_agent_log_job_state
        WHERE workspace_id = $1::uuid AND job_id = $2::uuid
        FOR UPDATE`,
      [workspaceId, jobId],
    );
    const result = locked.rows.length > 0 ? await fn() : null;
    await db.query("COMMIT");
    return result;
  } catch (error) {
    try {
      await db.query("ROLLBACK");
    } catch (_rollbackError) {
      // The original error is more useful.
    }
    throw error;
  }
}

// Catches every path that ends a claim without closeClaimStream: cancels,
// controller resets, reclaims. The job row is read, never locked.
function orphanedStreamPredicate(terminalParam) {
  return `s.closed_at IS NULL
    AND (cj.claim_id IS DISTINCT FROM s.claim_id OR cj.status = ANY(${terminalParam}::text[]))`;
}

async function closeOrphanedStreams(db, limit) {
  const terminal = [...TERMINAL_JOB_STATUSES];
  const found = await db.query(
    `SELECT DISTINCT s.workspace_id, s.job_id
       FROM certops_agent_log_stream s
       JOIN certificate_jobs cj
         ON cj.workspace_id = s.workspace_id AND cj.id = s.job_id
      WHERE ${orphanedStreamPredicate("$1")}
      LIMIT $2`,
    [terminal, limit],
  );
  let closed = 0;
  for (const row of found.rows) {
    const updated = await withJobStateLock(db, row.workspace_id, row.job_id, () => db.query(
      `UPDATE certops_agent_log_stream s
          SET closed_at = NOW(),
              accept_until = CASE
                WHEN s.status IN ('pending', 'streaming')
                  THEN COALESCE(s.accept_until, NOW() + ($4 || ' milliseconds')::interval)
                ELSE s.accept_until
              END
         FROM certificate_jobs cj
        WHERE s.workspace_id = $1::uuid
          AND s.job_id = $2::uuid
          AND cj.workspace_id = s.workspace_id
          AND cj.id = s.job_id
          AND ${orphanedStreamPredicate("$3")}`,
      [row.workspace_id, row.job_id, terminal, String(ACCEPT_GRACE_MS)],
    ));
    closed += updated?.rowCount || 0;
  }
  return closed;
}

async function abandonExpiredStreams({ client: db, limit = 100 } = {}) {
  assertLockSequence(OPERATION_LOCKS.abandon);
  let closed;
  let rows;
  try {
    closed = await closeOrphanedStreams(db, limit);
    const found = await db.query(
      `SELECT workspace_id, job_id
         FROM certops_agent_log_stream
        WHERE status IN ('pending', 'streaming')
          AND accept_until IS NOT NULL
          AND accept_until < NOW()
        GROUP BY workspace_id, job_id
        LIMIT $1`,
      [limit],
    );
    rows = found.rows;
  } catch (error) {
    if (error?.code === "42P01") return { closed: 0, abandoned: 0, skipped: "schema_missing" };
    throw error;
  }
  let abandoned = 0;
  for (const row of rows) {
    const updated = await withJobStateLock(db, row.workspace_id, row.job_id, () => db.query(
      `UPDATE certops_agent_log_stream
          SET status = 'abandoned',
              closed_at = COALESCE(closed_at, NOW()),
              finalized_at = COALESCE(finalized_at, NOW())
        WHERE workspace_id = $1::uuid
          AND job_id = $2::uuid
          AND status IN ('pending', 'streaming')
          AND accept_until IS NOT NULL
          AND accept_until < NOW()`,
      [row.workspace_id, row.job_id],
    ));
    abandoned += updated?.rowCount || 0;
  }
  return { closed, abandoned };
}

async function purgeExpiredAgentLogs({ client: db, env = process.env, batchSize = 5000 } = {}) {
  // 0 means storage is off, so every stored line goes on the next run.
  const retentionDays = resolveRetentionDays(env);
  let deletedLines = 0;
  try {
    const deleted = await db.query(
      `DELETE FROM certops_agent_job_log
        WHERE id IN (
          SELECT id FROM certops_agent_job_log
           WHERE received_at < NOW() - ($1 || ' days')::interval
           LIMIT $2
        )`,
      [String(retentionDays), batchSize],
    );
    deletedLines = deleted.rowCount || 0;
    assertLockSequence(OPERATION_LOCKS.purgeStream);
    const candidates = await db.query(
      `SELECT DISTINCT workspace_id, job_id
         FROM certops_agent_log_stream
        WHERE closed_at IS NOT NULL
          AND closed_at < NOW() - (($1::int + $2::int) || ' days')::interval
          AND status IN ('final', 'abandoned', 'disabled')
        LIMIT 100`,
      [retentionDays, STREAM_RETENTION_EXTRA_DAYS],
    );
    let deletedStreams = 0;
    for (const row of candidates.rows) {
      const removed = await withJobStateLock(db, row.workspace_id, row.job_id, () => db.query(
        `DELETE FROM certops_agent_log_stream
          WHERE workspace_id = $1::uuid
            AND job_id = $2::uuid
            AND closed_at IS NOT NULL
            AND closed_at < NOW() - (($3::int + $4::int) || ' days')::interval
            AND status IN ('final', 'abandoned', 'disabled')`,
        [row.workspace_id, row.job_id, retentionDays, STREAM_RETENTION_EXTRA_DAYS],
      ));
      deletedStreams += removed?.rowCount || 0;
    }
    await db.query(
      `DELETE FROM certops_agent_log_daily_quota
        WHERE quota_day < (CURRENT_DATE - $1::int)`,
      [QUOTA_ROW_KEEP_DAYS],
    );
    return { deletedLines, deletedStreams };
  } catch (error) {
    if (error?.code === "42P01") return { deletedLines: 0, deletedStreams: 0, skipped: "schema_missing" };
    throw error;
  }
}

function encodeCursor(ingestOrder) {
  return Buffer.from(String(ingestOrder), "utf8").toString("base64url");
}

function decodeCursor(cursor) {
  if (cursor == null || cursor === "") return 0;
  try {
    const parsed = Number(Buffer.from(String(cursor), "base64url").toString("utf8"));
    return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : 0;
  } catch (_error) {
    return 0;
  }
}

function publicStream(row) {
  return {
    claimId: row.claimId,
    attempt: row.attempt,
    status: row.status,
    streamingEnabled: row.streamingEnabled === true,
    agentGapLines: row.agentGapLines || 0,
    serverDroppedLines: row.serverDroppedLines || 0,
    truncated: (row.serverDroppedLines || 0) > 0,
  };
}

/**
 * nextCursor resumes after the last line returned, or echoes the request
 * cursor on an empty page, so a poller never re-reads lines it already has.
 */
function shapeAgentLogRead({ jobStatus, streams, lines, limit, includeText, storageEnabled: enabled, cursorOrder = 0 }) {
  const pageLimit = Math.min(Math.max(limit || 100, 1), 500);
  const ordered = [...(lines || [])].sort((a, b) => a.ingestOrder - b.ingestOrder);
  const page = ordered.slice(0, pageLimit);
  const hasMore = includeText && ordered.length > pageLimit;
  const resumeAt = page.at(-1)?.ingestOrder ?? cursorOrder;
  return {
    items: includeText
      ? page.map((line) => ({
        claimId: line.claimId,
        attempt: line.attempt,
        seq: line.seq,
        ts: line.ts,
        level: line.level,
        step: line.step,
        message: line.message,
        redacted: (line.redactionCount || 0) > 0,
      }))
      : [],
    nextCursor: includeText && resumeAt > 0 ? encodeCursor(resumeAt) : null,
    hasMore,
    logsComplete: logsComplete(jobStatus, streams),
    streams: (streams || []).map(publicStream),
    storageEnabled: enabled !== false,
  };
}

function deliveryState(payload) {
  if (!payload) return "Waiting for output";
  if (payload.storageEnabled === false) return "Agent log storage is disabled";
  if (payload.linesVisible === false) return "You need manager access to view agent output";
  const streams = payload.streams || [];
  if (streams.some((stream) => stream.status === "abandoned")) return "Agent stopped reporting";
  if (streams.length > 0 && streams.every((stream) => stream.streamingEnabled === false)) {
    return "This agent did not stream logs for this attempt";
  }
  const dropped = streams.reduce(
    (sum, stream) => sum + (stream.serverDroppedLines || 0) + (stream.agentGapLines || 0),
    0,
  );
  if (dropped > 0) return `Output incomplete: ${dropped} lines dropped`;
  if (streams.some((stream) => stream.truncated)) return "Log limit reached";
  if (payload.logsComplete) return "Stream complete";
  if (streams.length > 0 && streams.every((stream) => ["final", "abandoned", "disabled"].includes(stream.status))) {
    return "Waiting for the next attempt";
  }
  return "Waiting for output";
}

async function readAgentJobLog({
  db = pool,
  workspaceId,
  jobId,
  cursor,
  limit = 100,
  includeText = false,
  env = process.env,
} = {}) {
  const job = await db.query(
    `SELECT status FROM certificate_jobs WHERE workspace_id = $1::uuid AND id = $2::uuid`,
    [workspaceId, jobId],
  );
  if (!job.rows[0]) {
    const error = new Error("Certificate job not found");
    error.code = "CERTOPS_JOB_NOT_FOUND";
    throw error;
  }
  const streamRows = await db.query(
    `SELECT claim_id, attempt_number, status, streaming_enabled,
            agent_gap_lines, server_dropped_lines
       FROM certops_agent_log_stream
      WHERE workspace_id = $1::uuid AND job_id = $2::uuid
      ORDER BY attempt_number ASC, issued_at ASC`,
    [workspaceId, jobId],
  );
  const streams = streamRows.rows.map((row) => ({
    claimId: row.claim_id,
    attempt: row.attempt_number,
    status: row.status,
    streamingEnabled: row.streaming_enabled,
    agentGapLines: row.agent_gap_lines,
    serverDroppedLines: row.server_dropped_lines,
  }));
  const pageLimit = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const cursorOrder = decodeCursor(cursor);
  let lines = [];
  if (includeText && storageEnabled(env)) {
    const found = await db.query(
      `SELECT l.claim_id, s.attempt_number, l.seq, l.ts, l.level, l.step, l.message,
              l.redaction_count, l.ingest_order
         FROM certops_agent_job_log l
         JOIN certops_agent_log_stream s
           ON s.workspace_id = l.workspace_id
          AND s.job_id = l.job_id
          AND s.claim_id = l.claim_id
        WHERE l.workspace_id = $1::uuid
          AND l.job_id = $2::uuid
          AND l.ingest_order > $3
        ORDER BY l.ingest_order ASC
        LIMIT $4`,
      [workspaceId, jobId, cursorOrder, pageLimit + 1],
    );
    lines = found.rows.map((row) => ({
      claimId: row.claim_id,
      attempt: row.attempt_number,
      seq: Number(row.seq),
      ts: row.ts,
      level: row.level,
      step: row.step,
      message: row.message,
      redactionCount: row.redaction_count,
      ingestOrder: Number(row.ingest_order),
    }));
  }
  return shapeAgentLogRead({
    jobStatus: job.rows[0].status,
    streams,
    lines,
    limit: pageLimit,
    includeText: includeText && storageEnabled(env),
    storageEnabled: storageEnabled(env),
    cursorOrder,
  });
}

async function readAgentFleetLog({ db = pool, workspaceId, agentId, limit = 20 } = {}) {
  const pageLimit = Math.min(Math.max(Number(limit) || 20, 1), 20);
  const found = await db.query(
    `SELECT s.job_id, s.claim_id, s.attempt_number, s.status, s.streaming_enabled,
            s.agent_gap_lines, s.server_dropped_lines, j.status AS job_status
       FROM certops_agent_log_stream s
       JOIN certificate_jobs j
         ON j.workspace_id = s.workspace_id AND j.id = s.job_id
      WHERE s.workspace_id = $1::uuid AND s.agent_id = $2::uuid
      ORDER BY s.issued_at DESC
      LIMIT $3`,
    [workspaceId, agentId, pageLimit],
  );
  return {
    items: found.rows.map((row) => ({
      jobId: row.job_id,
      jobStatus: row.job_status,
      ...publicStream({
        claimId: row.claim_id,
        attempt: row.attempt_number,
        status: row.status,
        streamingEnabled: row.streaming_enabled,
        agentGapLines: row.agent_gap_lines,
        serverDroppedLines: row.server_dropped_lines,
      }),
    })),
  };
}

module.exports = {
  JOB_LOG_STREAM_CAPABILITY,
  MAX_BATCH_BYTES,
  CLAIM_LINE_CAP,
  CLAIM_BYTE_CAP,
  ACCEPT_GRACE_MS,
  LOCK_ORDER,
  OPERATION_LOCKS,
  CERTOPS_AGENT_LOG_PRIVATE_MATERIAL,
  CERTOPS_AGENT_LOG_CLAIM_INVALID,
  CERTOPS_AGENT_LOG_CLOSED,
  CERTOPS_AGENT_LOG_INVALID,
  resolveRetentionDays,
  storageEnabled,
  resolveDailyByteLimit,
  assertLockSequence,
  contentHash,
  batchKeyOf,
  resolveIngest,
  takeIngestOrders,
  logsComplete,
  projectRetainedBytes,
  shouldAbandon,
  shouldDeleteStream,
  scrubIncomingLines,
  openStreamForClaim,
  closeClaimStream,
  closeClaimStreamSafely,
  ingestAgentJobLogs,
  abandonExpiredStreams,
  purgeExpiredAgentLogs,
  encodeCursor,
  decodeCursor,
  shapeAgentLogRead,
  deliveryState,
  readAgentJobLog,
  readAgentFleetLog,
};
