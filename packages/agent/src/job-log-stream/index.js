"use strict";

/**
 * Bounded, best-effort sender for one claim's execution console.
 * One batch is in flight. Sends do not use the sequenced control queue, and
 * nothing here may delay or change a job result.
 */

const { AsyncLocalStorage } = require("node:async_hooks");
const { createAgentLogger } = require("../logging");
const { jitteredDelay, AGENT_PROTOCOL_ERROR_CODES } = require("../protocol");
const {
  scrubAgentLogText,
  scrubAgentLogFields,
} = require("../../vendor/log-scrub/agent-log-text");

const MAX_LINES = 1000;
const MAX_CLAIM_BYTES = 256 * 1024;
const MAX_AGENT_BYTES = 2 * 1024 * 1024;
const MAX_BATCH_BYTES = 64 * 1024;
// Matches the schema's lines.maxItems.
const MAX_BATCH_LINES = 200;
// The server's body limit covers the whole envelope, not just the lines.
const ENVELOPE_HEADROOM_BYTES = 2048;
const FLUSH_LINES = 50;
const FLUSH_MS = 1000;
const RETRY_BUDGET_MS = 2 * 60 * 1000;
const FINAL_BUDGET_MS = 60 * 1000;
const MAX_BACKOFF_MS = 10 * 1000;
const SHUTDOWN_DRAIN_MS = 5000;

const LEVELS = new Set(["info", "warn", "error"]);
const STEPS = new Set(["claim", "acme", "dns", "deploy", "reload", "verify", "discovery", "trust", "other"]);
const STOP_STATUSES = new Set([401, 403, 404, 409, 410]);

// Mirrored agent messages start with their verb, so the prefix picks the step.
const STEP_PREFIXES = [
  [/^verif/i, "verify"],
  [/^reload/i, "reload"],
  [/^(deploy|iis binding)/i, "deploy"],
  [/^(acme|generating|completing cng|cng enrollment)/i, "acme"],
  [/\bdns\b/i, "dns"],
  [/\btrust/i, "trust"],
];

const claims = new Map();
const pendingCloses = new Set();
const jobConsole = new AsyncLocalStorage();

function agentBytes() {
  let total = 0;
  for (const buffer of claims.values()) total += buffer.bytes;
  return total;
}

function unrefSleep(ms) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref?.();
  });
}

function inferStep(message, fallback) {
  for (const [pattern, step] of STEP_PREFIXES) {
    if (pattern.test(message)) return step;
  }
  return fallback;
}

function echoLogger(prefix) {
  const echo = createAgentLogger();
  return {
    info: (message, details) => echo.info(`${prefix}${message}`, details),
    error: (message, details) => echo.error(`${prefix}${message}`, details),
  };
}

function disabledSession(jobId) {
  const echo = echoLogger(jobId ? `job ${jobId}: ` : "");
  const logger = {
    step() { return logger; },
    info: echo.info,
    warn: echo.info,
    error: echo.error,
  };
  return { logger, mirror() {}, close: async () => {}, flush: async () => true };
}

function createJobLogSession({
  post,
  jobId,
  claimId,
  maxBatchBytes = MAX_BATCH_BYTES,
  sleep = unrefSleep,
  now = () => Date.now(),
  enabled = true,
} = {}) {
  if (!enabled || typeof post !== "function") return disabledSession(jobId);

  const batchCap = Math.min(Math.max(Number(maxBatchBytes) || MAX_BATCH_BYTES, 4096), MAX_BATCH_BYTES);
  const lineBudget = batchCap - ENVELOPE_HEADROOM_BYTES;
  const prefix = `job ${jobId}: `;
  const echo = echoLogger(prefix);
  const buffer = { lines: [], bytes: 0, dropped: 0, nextSeq: 1, closed: false };
  claims.set(claimId, buffer);
  let inflight = null;
  let closing = null;
  let timer = null;
  let stopped = false;
  let closeDeadline = Infinity;
  let step = "claim";

  function stop() {
    stopped = true;
    buffer.lines = [];
    buffer.bytes = 0;
  }

  function dropOldest() {
    const removed = buffer.lines.shift();
    if (!removed) return;
    buffer.bytes -= removed.bytes;
    buffer.dropped += 1;
  }

  function schedule() {
    if (timer || buffer.closed || stopped) return;
    timer = setTimeout(() => {
      timer = null;
      void flush();
    }, FLUSH_MS);
    timer.unref?.();
  }

  function enqueue({ level, step: lineStep, message, fields }) {
    if (buffer.closed || stopped) return;
    const text = scrubAgentLogText(message);
    const safeFields = scrubAgentLogFields(fields);
    if (text.rejected || safeFields.rejected) {
      buffer.dropped += 1;
      return;
    }
    if (text.text.trim().length === 0) return;
    const payload = {
      seq: buffer.nextSeq,
      ts: new Date(now()).toISOString(),
      level: LEVELS.has(level) ? level : "info",
      step: STEPS.has(lineStep) ? lineStep : "other",
      message: text.text,
      ...(safeFields.fields ? { fields: safeFields.fields } : {}),
    };
    buffer.nextSeq += 1;
    const bytes = Buffer.byteLength(JSON.stringify(payload), "utf8") + 1;
    if (bytes > lineBudget) {
      buffer.dropped += 1;
      return;
    }
    buffer.lines.push({ payload, bytes });
    buffer.bytes += bytes;
    while (
      buffer.lines.length > 0 &&
      (buffer.lines.length > MAX_LINES || buffer.bytes > MAX_CLAIM_BYTES || agentBytes() > MAX_AGENT_BYTES)
    ) {
      dropOldest();
    }
    if (buffer.lines.length >= FLUSH_LINES || buffer.bytes >= lineBudget) void flush();
    else schedule();
  }

  function takeBatch() {
    const lines = [];
    let bytes = 2;
    const droppedBefore = buffer.dropped;
    buffer.dropped = 0;
    while (buffer.lines.length > 0 && lines.length < MAX_BATCH_LINES) {
      const next = buffer.lines[0];
      if (lines.length > 0 && bytes + next.bytes > lineBudget) break;
      buffer.lines.shift();
      buffer.bytes -= next.bytes;
      lines.push(next.payload);
      bytes += next.bytes;
    }
    return { lines, droppedBefore, firstSeq: lines[0]?.seq };
  }

  function drop(batch) {
    buffer.dropped += batch.lines.length + (batch.droppedBefore || 0);
    return false;
  }

  async function sendBatch(batch, { final = false, budgetMs = RETRY_BUDGET_MS } = {}) {
    const started = now();
    const deadline = () => Math.min(started + budgetMs, closeDeadline);
    const wait = (ms) => sleep(Math.max(0, Math.min(ms, deadline() - now())));
    const backoff = (attempt) => jitteredDelay(Math.min(500 * 2 ** (attempt - 1), MAX_BACKOFF_MS));
    let pending = batch;
    let attempt = 0;
    while (!stopped && (attempt === 0 || now() < deadline())) {
      attempt += 1;
      let response;
      try {
        response = await post({
          jobId,
          body: {
            jobId,
            claimId,
            ...(pending.firstSeq ? { firstSeq: pending.firstSeq } : {}),
            lines: pending.lines,
            droppedBefore: pending.droppedBefore || 0,
            final,
          },
        });
      } catch (error) {
        // Refused locally (malformed or unsafe): a retry sends the same bytes.
        if (error?.code !== AGENT_PROTOCOL_ERROR_CODES.NETWORK_ERROR) return drop(pending);
        await wait(backoff(attempt));
        continue;
      }
      const status = response?.status;
      if (status >= 200 && status < 300) {
        if (response?.json?.streamDisabled === true) {
          stop();
          return false;
        }
        return true;
      }
      if (status === 413 && pending.lines.length > 1) {
        const mid = Math.ceil(pending.lines.length / 2);
        const headBatch = {
          lines: pending.lines.slice(0, mid),
          droppedBefore: pending.droppedBefore,
          firstSeq: pending.lines[0].seq,
        };
        const headOk = await sendBatch(headBatch, {
          budgetMs: Math.max(0, deadline() - now()),
        });
        if (stopped) return false;
        if (!headOk) {
          // drop() already counted head lines locally. Once a later seq is
          // accepted the server records that hole as a seq gap; keep those
          // lines out of a later droppedBefore so the same loss is not counted twice.
          buffer.dropped = Math.max(0, buffer.dropped - headBatch.lines.length);
        }
        pending = {
          lines: pending.lines.slice(mid),
          droppedBefore: 0,
          firstSeq: pending.lines[mid].seq,
        };
        attempt = 0;
        continue;
      }
      if (status === 429 || status === 503) {
        await wait(Number.isFinite(response.retryAfterMs) ? response.retryAfterMs : backoff(attempt));
        continue;
      }
      if (STOP_STATUSES.has(status)) {
        stop();
        return false;
      }
      if (status === 408 || status >= 500) {
        await wait(backoff(attempt));
        continue;
      }
      // Any other 4xx: the server will never accept this batch.
      return drop(pending);
    }
    return drop(pending);
  }

  function flush() {
    if (inflight) return inflight;
    if (stopped || buffer.lines.length === 0) return Promise.resolve(true);
    inflight = sendBatch(takeBatch())
      .catch(() => false)
      .finally(() => {
        inflight = null;
        if (!buffer.closed && buffer.lines.length > 0) schedule();
      });
    return inflight;
  }

  function close() {
    if (closing) return closing;
    buffer.closed = true;
    closeDeadline = now() + FINAL_BUDGET_MS;
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    closing = (async () => {
      try {
        if (inflight) await inflight;
        while (!stopped && buffer.lines.length > 0 && now() < closeDeadline) {
          await sendBatch(takeBatch());
        }
        if (!stopped) {
          buffer.dropped += buffer.lines.length;
          buffer.lines = [];
          buffer.bytes = 0;
          const droppedBefore = buffer.dropped;
          buffer.dropped = 0;
          await sendBatch({ lines: [], droppedBefore }, { final: true });
        }
      } catch (_error) {
        // Logging never changes the job result. The result was already sent.
      } finally {
        claims.delete(claimId);
      }
    })();
    return closing;
  }

  const logger = {
    step(name) {
      step = STEPS.has(name) ? name : "other";
      return logger;
    },
    info(message, details) {
      echo.info(message, details);
      enqueue({ level: "info", step, message, fields: details });
    },
    warn(message, details) {
      echo.info(message, details);
      enqueue({ level: "warn", step, message, fields: details });
    },
    error(message, details) {
      echo.error(message, details);
      enqueue({ level: "error", step, message, fields: details });
    },
  };

  // Copies a line the agent already printed; never echoes it again.
  function mirror(level, message, details) {
    let text = String(message ?? "");
    if (text.startsWith(prefix)) text = text.slice(prefix.length);
    const lineLevel = /^WARNING:/i.test(text) ? "warn" : level;
    enqueue({ level: lineLevel, step: inferStep(text, step), message: text, fields: details });
  }

  return { logger, mirror, close, flush };
}

function withJobConsole(session, fn) {
  return session ? jobConsole.run(session, fn) : fn();
}

function mirrorToJobConsole(level, message, details) {
  const session = jobConsole.getStore();
  if (!session) return;
  try {
    session.mirror(level, message, details);
  } catch (_error) {
    // Console output is best-effort.
  }
}

function closeInBackground(session) {
  if (!session) return;
  const done = Promise.resolve()
    .then(() => session.close())
    .catch(() => {})
    .finally(() => pendingCloses.delete(done));
  pendingCloses.add(done);
}

async function drainJobLogSessions(timeoutMs = SHUTDOWN_DRAIN_MS) {
  if (pendingCloses.size === 0) return;
  let timer;
  await Promise.race([
    Promise.allSettled([...pendingCloses]),
    new Promise((resolve) => {
      timer = setTimeout(resolve, timeoutMs);
      timer.unref?.();
    }),
  ]);
  clearTimeout(timer);
}

module.exports = {
  createJobLogSession,
  withJobConsole,
  mirrorToJobConsole,
  closeInBackground,
  drainJobLogSessions,
  inferStep,
  MAX_BATCH_BYTES,
  MAX_BATCH_LINES,
  MAX_LINES,
  MAX_CLAIM_BYTES,
  MAX_AGENT_BYTES,
};
