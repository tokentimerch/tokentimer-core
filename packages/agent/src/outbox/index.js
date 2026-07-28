"use strict";

/**
 * Durable local outbox for job outcomes pending control-plane transmission.
 *
 * Separates real-world execution success/failure from reportResult /
 * reportEvidence network delivery (B8). After a job finishes, the exact
 * outcome (+ any buffered evidence bodies) is persisted under the agent's
 * state directory BEFORE any network call. Transmission then retries the
 * same persisted entry idempotently until the server acknowledges it; the
 * entry is cleared only after a successful POST. A restart drains
 * un-acknowledged entries before new claim polling resumes.
 *
 * Storage conventions match src/config: 0700 directory, 0600 files,
 * atomic write + rename. Entries are public result/evidence payloads only
 * (never private keys).
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const OUTBOX_DIR_NAME = "outbox";
const ENTRY_FILE_SUFFIX = ".json";
const MAX_ENTRY_BYTES = 512 * 1024;

function fsyncParentDirectory(filePath) {
  let directoryFd;
  try {
    directoryFd = fs.openSync(path.dirname(filePath), "r");
    fs.fsyncSync(directoryFd);
  } catch (_err) {
    // Best effort across platforms/filesystems.
  } finally {
    if (directoryFd !== undefined) {
      try {
        fs.closeSync(directoryFd);
      } catch (_err) {
        // Best effort close.
      }
    }
  }
}

function writeFileAtomically(filePath, contents, mode) {
  const temporaryPath = `${filePath}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temporaryPath, "wx", mode);
    fs.writeFileSync(fd, contents, "utf8");
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temporaryPath, filePath);
    try {
      fs.chmodSync(filePath, mode);
    } catch (_err) {
      // Best effort on win32.
    }
    fsyncParentDirectory(filePath);
  } catch (err) {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch (_err) {
        // Best effort close.
      }
    }
    try {
      fs.unlinkSync(temporaryPath);
    } catch (_err) {
      // May already be renamed or absent.
    }
    throw err;
  }
}

/**
 * @param {string} configDir
 * @returns {string}
 */
function resolveOutboxDir(configDir) {
  return path.join(configDir, OUTBOX_DIR_NAME);
}

/**
 * Ensures the outbox directory exists with 0700 permissions.
 * @param {string} outboxDir
 * @returns {string} outboxDir
 */
function ensureOutboxDir(outboxDir) {
  fs.mkdirSync(outboxDir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(outboxDir, 0o700);
  } catch (_err) {
    // Best effort on win32.
  }
  return outboxDir;
}

function entryPath(outboxDir, id) {
  return path.join(outboxDir, `${id}${ENTRY_FILE_SUFFIX}`);
}

function validateEntry(entry) {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    throw new Error("tokentimer-agent: outbox entry must be an object");
  }
  if (typeof entry.id !== "string" || entry.id.length === 0 || entry.id.length > 128) {
    throw new Error("tokentimer-agent: outbox entry.id must be a 1-128 char string");
  }
  if (!/^[A-Za-z0-9_.:-]+$/.test(entry.id)) {
    throw new Error("tokentimer-agent: outbox entry.id has an invalid format");
  }
  if (typeof entry.createdAt !== "string" || entry.createdAt.length === 0) {
    throw new Error("tokentimer-agent: outbox entry.createdAt is required");
  }
  if (entry.result === null || typeof entry.result !== "object" || Array.isArray(entry.result)) {
    throw new Error("tokentimer-agent: outbox entry.result must be an object");
  }
  if (!Array.isArray(entry.evidence)) {
    throw new Error("tokentimer-agent: outbox entry.evidence must be an array");
  }
  return entry;
}

/**
 * Persists an outcome+evidence entry BEFORE any network transmission.
 * @param {string} outboxDir
 * @param {{
 *   id?: string,
 *   createdAt?: string,
 *   result: object,
 *   evidence?: object[],
 * }} partial
 * @returns {{ id: string, createdAt: string, result: object, evidence: object[] }}
 */
function enqueueOutboxEntry(outboxDir, partial) {
  ensureOutboxDir(outboxDir);
  const id =
    typeof partial.id === "string" && partial.id.length > 0
      ? partial.id
      : `outbox-${crypto.randomBytes(12).toString("hex")}`;
  const entry = validateEntry({
    id,
    createdAt: partial.createdAt || new Date().toISOString(),
    result: partial.result,
    evidence: Array.isArray(partial.evidence) ? partial.evidence : [],
  });
  const serialized = `${JSON.stringify(entry)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_ENTRY_BYTES) {
    throw new Error(
      `tokentimer-agent: outbox entry exceeds ${MAX_ENTRY_BYTES} bytes`,
    );
  }
  writeFileAtomically(entryPath(outboxDir, entry.id), serialized, 0o600);
  return entry;
}

/**
 * @param {string} outboxDir
 * @returns {Array<{ id: string, createdAt: string, result: object, evidence: object[] }>}
 */
function listOutboxEntries(outboxDir) {
  if (!fs.existsSync(outboxDir)) return [];
  let names;
  try {
    names = fs.readdirSync(outboxDir);
  } catch (_err) {
    return [];
  }
  const entries = [];
  for (const name of names) {
    if (!name.endsWith(ENTRY_FILE_SUFFIX) || name.endsWith(".tmp")) continue;
    const filePath = path.join(outboxDir, name);
    let raw;
    try {
      const stats = fs.lstatSync(filePath);
      if (stats.isSymbolicLink() || !stats.isFile()) continue;
      if (stats.size < 1 || stats.size > MAX_ENTRY_BYTES) continue;
      raw = fs.readFileSync(filePath, "utf8");
    } catch (_err) {
      continue;
    }
    try {
      entries.push(validateEntry(JSON.parse(raw)));
    } catch (_err) {
      // Leave corrupt files for operators; skip them during drain.
    }
  }
  entries.sort((a, b) => {
    if (a.createdAt < b.createdAt) return -1;
    if (a.createdAt > b.createdAt) return 1;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
  return entries;
}

/**
 * Clears an entry only after the control plane acknowledged transmission.
 * @param {string} outboxDir
 * @param {string} id
 * @returns {boolean} true when a file was removed
 */
function acknowledgeOutboxEntry(outboxDir, id) {
  const filePath = entryPath(outboxDir, id);
  try {
    fs.unlinkSync(filePath);
    fsyncParentDirectory(filePath);
    return true;
  } catch (err) {
    if (err && err.code === "ENOENT") return false;
    throw err;
  }
}

/**
 * Transmits one persisted entry: evidence bodies first (in order), then
 * the terminal result. Safe to retry: the same payloads are re-sent.
 *
 * @param {object} entry
 * @param {{ reportEvidence: Function, reportResult: Function }} client
 * @returns {Promise<void>}
 */
async function transmitOutboxEntry(entry, client) {
  const validated = validateEntry(entry);
  for (const evidenceBody of validated.evidence) {
    await client.reportEvidence(evidenceBody);
  }
  await client.reportResult(validated.result);
}

/**
 * Attempts to deliver every pending outbox entry. On transmission failure
 * the entry is left on disk for a later retry; later entries are still
 * attempted so one stuck job does not block unrelated acknowledgements.
 *
 * @param {string} outboxDir
 * @param {{ reportEvidence: Function, reportResult: Function }} client
 * @param {{ onError?: (err: Error, entry: object) => void }} [options]
 * @returns {Promise<{ transmitted: number, remaining: number }>}
 */
async function drainOutbox(outboxDir, client, { onError } = {}) {
  const pending = listOutboxEntries(outboxDir);
  let transmitted = 0;
  for (const entry of pending) {
    try {
      await transmitOutboxEntry(entry, client);
      acknowledgeOutboxEntry(outboxDir, entry.id);
      transmitted += 1;
    } catch (err) {
      if (typeof onError === "function") onError(err, entry);
    }
  }
  return {
    transmitted,
    remaining: listOutboxEntries(outboxDir).length,
  };
}

/**
 * Creates a protocol-client shim that buffers reportEvidence calls instead
 * of sending them, so step evidence can be persisted with the terminal
 * result in one outbox entry.
 *
 * @returns {{
 *   reportEvidence: (body: object) => Promise<void>,
 *   takeEvidence: () => object[],
 * }}
 */
function createEvidenceBuffer() {
  const buffered = [];
  return {
    reportEvidence(body) {
      buffered.push(body);
      return Promise.resolve();
    },
    takeEvidence() {
      return buffered.splice(0, buffered.length);
    },
  };
}

module.exports = {
  OUTBOX_DIR_NAME,
  resolveOutboxDir,
  ensureOutboxDir,
  enqueueOutboxEntry,
  listOutboxEntries,
  acknowledgeOutboxEntry,
  transmitOutboxEntry,
  drainOutbox,
  createEvidenceBuffer,
};
