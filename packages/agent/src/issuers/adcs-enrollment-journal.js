"use strict";

/**
 * Durable AD CS enrollment journal and artifacts (ADR-0014 decision 10).
 *
 * Layout under <stateDir>/adcs-enrollments/<enrollmentId>/:
 *   keygen-intent.json  — written before certreq -new
 *   csr.pem             — public CSR; required once prepared is committed
 *   leaf.pem            — issued leaf; required once issued / deferred
 *   chain.pem           — optional chain material
 *   journal.json        — state + hashes (never private key material)
 *
 * Legacy layout: <stateDir>/adcs-enrollments/<enrollmentId>.json
 * (RequestId-only). Reads are typed; conflicting legacy+v2 or incomplete
 * legacy trust bindings fail closed (corrupt), never reconstructed from
 * live config/caches.
 *
 * Durability: restrictive ACL/0600, write tmp, fsync, rename, best-effort
 * directory fsync. Failure to persist submitting must block CA submit
 * (caller responsibility).
 */

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const { applyRestrictivePermissions } = require("../platform/index.js");

const ENROLLMENT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64 = /^[a-f0-9]{64}$/;
const OID_PATTERN = /^[0-2](\.(0|[1-9][0-9]{0,9})){1,63}$/;
const JOURNAL_SCHEMA_VERSION = 1;
const ENROLLMENTS_DIR = "adcs-enrollments";
const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

/** Open (non-terminal) journal states that protect a CNG container. */
const OPEN_JOURNAL_STATES = Object.freeze([
  "keygen_intent",
  "prepared",
  "submitting",
  "submission_uncertain",
  "pending",
  "pending_issuance",
  "issued",
  "validation_deferred",
  "installing",
]);

const JOURNAL_STATES = Object.freeze([
  ...OPEN_JOURNAL_STATES,
  "installed",
  "install_failed",
  "rejected_invalid",
  "validation_expired",
  "denied",
  "refused",
  "abandoned",
  "expired",
  "cancelled",
]);

function assertEnrollmentId(enrollmentId) {
  if (typeof enrollmentId !== "string" || !ENROLLMENT_ID_PATTERN.test(enrollmentId)) {
    throw new TypeError(`enrollmentId must be a lowercase UUID (got ${JSON.stringify(enrollmentId)})`);
  }
}

function enrollmentsRoot(stateDir) {
  if (typeof stateDir !== "string" || stateDir.length === 0) {
    throw new TypeError("stateDir is required");
  }
  return path.join(stateDir, ENROLLMENTS_DIR);
}

function enrollmentDir(stateDir, enrollmentId) {
  assertEnrollmentId(enrollmentId);
  return path.join(enrollmentsRoot(stateDir), enrollmentId);
}

function journalV2Path(stateDir, enrollmentId) {
  return path.join(enrollmentDir(stateDir, enrollmentId), "journal.json");
}

function legacyJournalPath(stateDir, enrollmentId) {
  assertEnrollmentId(enrollmentId);
  return path.join(enrollmentsRoot(stateDir), `${enrollmentId}.json`);
}

function keygenIntentPath(stateDir, enrollmentId) {
  return path.join(enrollmentDir(stateDir, enrollmentId), "keygen-intent.json");
}

function csrArtifactPath(stateDir, enrollmentId) {
  return path.join(enrollmentDir(stateDir, enrollmentId), "csr.pem");
}

function leafArtifactPath(stateDir, enrollmentId) {
  return path.join(enrollmentDir(stateDir, enrollmentId), "leaf.pem");
}

function chainArtifactPath(stateDir, enrollmentId) {
  return path.join(enrollmentDir(stateDir, enrollmentId), "chain.pem");
}

function sha256HexOfString(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

function sha256HexOfBuffer(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/**
 * Ensure enrollment directory exists with restrictive permissions.
 */
function ensureEnrollmentDir(stateDir, enrollmentId) {
  const root = enrollmentsRoot(stateDir);
  fs.mkdirSync(root, { recursive: true, mode: DIR_MODE });
  applyRestrictivePermissions(root, { kind: "directory", mode: DIR_MODE });
  const dir = enrollmentDir(stateDir, enrollmentId);
  fs.mkdirSync(dir, { recursive: true, mode: DIR_MODE });
  applyRestrictivePermissions(dir, { kind: "directory", mode: DIR_MODE });
  return dir;
}

/**
 * Atomic durable write: tmp → permissions → fsync → rename → dir fsync.
 * @param {string} dest absolute path
 * @param {string|Buffer} contents
 */
function durableWriteFileSync(dest, contents) {
  const dir = path.dirname(dest);
  fs.mkdirSync(dir, { recursive: true, mode: DIR_MODE });
  applyRestrictivePermissions(dir, { kind: "directory", mode: DIR_MODE });
  const tmp = `${dest}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  const data = typeof contents === "string" ? contents : Buffer.from(contents);
  const fd = fs.openSync(tmp, "w", FILE_MODE);
  try {
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  applyRestrictivePermissions(tmp, { kind: "file", mode: FILE_MODE });
  fs.renameSync(tmp, dest);
  try {
    const dirFd = fs.openSync(dir, "r");
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  } catch {
    // Directory fsync is best-effort (not supported on all platforms).
  }
}

async function durableWriteFile(dest, contents) {
  durableWriteFileSync(dest, contents);
}

function parseJsonFile(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw);
}

/**
 * @returns {{ kind: "not_found" }
 *   | { kind: "legacy", journal: object, path: string }
 *   | { kind: "valid", journal: object, path: string, artifacts: object }
 *   | { kind: "corrupt", error: string, path?: string }}
 */
function readEnrollmentJournal(stateDir, enrollmentId) {
  assertEnrollmentId(enrollmentId);
  const v2 = journalV2Path(stateDir, enrollmentId);
  const legacy = legacyJournalPath(stateDir, enrollmentId);
  const v2Exists = fs.existsSync(v2);
  const legacyExists = fs.existsSync(legacy);

  if (v2Exists && legacyExists) {
    let v2Body;
    let legacyBody;
    try {
      v2Body = parseJsonFile(v2);
      legacyBody = parseJsonFile(legacy);
    } catch (err) {
      return {
        kind: "corrupt",
        error: `both legacy and v2 journals present but unreadable: ${err.message}`,
        path: v2,
      };
    }
    if (!journalsAgree(v2Body, legacyBody)) {
      return {
        kind: "corrupt",
        error:
          "both legacy and v2 enrollment journals exist and disagree; refusing to choose",
        path: v2,
      };
    }
    // Prefer v2 when they agree; still validate v2 fully.
  }

  if (v2Exists) {
    return readV2Journal(stateDir, enrollmentId, v2);
  }
  if (legacyExists) {
    return readLegacyJournal(legacy);
  }

  // Keygen intent alone (crash between -new and prepared) is an open protection.
  const intentPath = keygenIntentPath(stateDir, enrollmentId);
  if (fs.existsSync(intentPath)) {
    try {
      const intent = parseJsonFile(intentPath);
      if (
        intent &&
        intent.enrollmentId === enrollmentId &&
        typeof intent.containerName === "string" &&
        intent.containerName.length > 0
      ) {
        return {
          kind: "valid",
          path: intentPath,
          journal: {
            schemaVersion: JOURNAL_SCHEMA_VERSION,
            enrollmentId,
            state: "keygen_intent",
            containerName: intent.containerName,
            attempt: intent.attempt ?? null,
            snapshotSha256: intent.snapshotSha256 ?? null,
            jobId: intent.jobId ?? null,
            updatedAt: intent.updatedAt ?? null,
          },
          artifacts: { csrPem: null, leafPem: null, chainPem: null },
        };
      }
      return {
        kind: "corrupt",
        error: "keygen-intent.json is present but malformed",
        path: intentPath,
      };
    } catch (err) {
      return {
        kind: "corrupt",
        error: `keygen-intent.json unreadable: ${err.message}`,
        path: intentPath,
      };
    }
  }

  return { kind: "not_found" };
}

function journalsAgree(v2, legacy) {
  if (!v2 || !legacy) return false;
  if (v2.enrollmentId !== legacy.enrollmentId) return false;
  if (
    Number.isInteger(v2.requestId) &&
    Number.isInteger(legacy.requestId) &&
    v2.requestId !== legacy.requestId
  ) {
    return false;
  }
  if (
    typeof v2.snapshotSha256 === "string" &&
    typeof legacy.snapshotSha256 === "string" &&
    v2.snapshotSha256 !== legacy.snapshotSha256
  ) {
    return false;
  }
  if (
    typeof v2.csrSpkiSha256 === "string" &&
    typeof legacy.csrSpkiSha256 === "string" &&
    v2.csrSpkiSha256 !== legacy.csrSpkiSha256
  ) {
    return false;
  }
  if (
    typeof v2.templateOid === "string" &&
    typeof legacy.templateOid === "string" &&
    v2.templateOid !== legacy.templateOid
  ) {
    return false;
  }
  return true;
}

function readLegacyJournal(filePath) {
  let parsed;
  try {
    parsed = parseJsonFile(filePath);
  } catch (err) {
    return { kind: "corrupt", error: `legacy journal unreadable: ${err.message}`, path: filePath };
  }
  if (!parsed || typeof parsed !== "object") {
    return { kind: "corrupt", error: "legacy journal is not an object", path: filePath };
  }
  if (!Number.isInteger(parsed.requestId) || parsed.requestId < 1) {
    return {
      kind: "corrupt",
      error: "legacy journal lacks a valid requestId",
      path: filePath,
    };
  }
  // Decision-6 cannot run without these; do not invent them from caches.
  if (typeof parsed.csrSpkiSha256 !== "string" || !HEX64.test(parsed.csrSpkiSha256)) {
    return {
      kind: "corrupt",
      error:
        "legacy journal is missing csrSpkiSha256 required for decision-6; refusing to reconstruct from caches",
      path: filePath,
    };
  }
  if (typeof parsed.templateOid !== "string" || !OID_PATTERN.test(parsed.templateOid)) {
    return {
      kind: "corrupt",
      error:
        "legacy journal is missing templateOid required for decision-6; refusing to reconstruct from caches",
      path: filePath,
    };
  }
  return {
    kind: "legacy",
    path: filePath,
    journal: {
      schemaVersion: 0,
      enrollmentId: parsed.enrollmentId,
      attempt: parsed.attempt,
      state: "pending",
      requestId: parsed.requestId,
      snapshotSha256: parsed.snapshotSha256,
      jobId: parsed.jobId,
      csrSpkiSha256: parsed.csrSpkiSha256,
      templateOid: parsed.templateOid,
      updatedAt: parsed.updatedAt ?? null,
      legacy: true,
    },
  };
}

/** Fields required on the journal record for each state (artifacts checked separately). */
const REQUIRED_FIELDS_BY_STATE = Object.freeze({
  prepared: ["containerName", "snapshotSha256", "csrSha256", "csrSpkiSha256", "templateOid"],
  submitting: ["containerName", "snapshotSha256", "csrSha256", "csrSpkiSha256", "templateOid"],
  submission_uncertain: ["containerName", "snapshotSha256", "csrSha256", "csrSpkiSha256", "templateOid"],
  pending: ["containerName", "snapshotSha256", "csrSpkiSha256", "templateOid", "requestId"],
  pending_issuance: ["containerName", "snapshotSha256", "csrSpkiSha256", "templateOid", "requestId"],
  issued: ["containerName", "snapshotSha256", "csrSha256", "csrSpkiSha256", "templateOid", "leafSha256"],
  validation_deferred: [
    "containerName",
    "snapshotSha256",
    "csrSha256",
    "csrSpkiSha256",
    "templateOid",
    "leafSha256",
    "validationDeadlineAt",
  ],
  installing: [
    "containerName",
    "snapshotSha256",
    "csrSha256",
    "csrSpkiSha256",
    "templateOid",
    "leafSha256",
    "installStep",
  ],
  installed: ["containerName", "snapshotSha256", "csrSpkiSha256", "templateOid", "leafSha256"],
  install_failed: ["containerName", "snapshotSha256", "csrSpkiSha256", "templateOid", "leafSha256"],
  denied: ["containerName", "snapshotSha256", "csrSpkiSha256", "templateOid"],
  refused: ["containerName", "snapshotSha256", "csrSpkiSha256", "templateOid"],
  rejected_invalid: ["containerName", "snapshotSha256", "csrSpkiSha256", "templateOid"],
});

/** Allowed previous states for a write (null = no prior journal.json). */
const ALLOWED_TRANSITIONS = Object.freeze({
  prepared: new Set([null, "prepared", "submitting", "keygen_intent"]),
  submitting: new Set(["prepared"]),
  submission_uncertain: new Set(["submitting", "submission_uncertain"]),
  pending: new Set(["submitting", "submission_uncertain", "pending", null]),
  pending_issuance: new Set(["submitting", "submission_uncertain", "pending", "pending_issuance"]),
  issued: new Set(["submitting", "submission_uncertain", "pending", "pending_issuance", "issued"]),
  validation_deferred: new Set(["issued", "validation_deferred"]),
  installing: new Set(["issued", "validation_deferred", "installing", "install_failed"]),
  installed: new Set(["installing", "installed"]),
  install_failed: new Set(["installing", "install_failed"]),
  denied: new Set(["submitting", "denied"]),
  refused: new Set(["submitting", "prepared", "refused"]),
  rejected_invalid: new Set([
    "prepared",
    "submitting",
    "issued",
    "validation_deferred",
    "rejected_invalid",
  ]),
  validation_expired: new Set(["validation_deferred", "validation_expired"]),
  abandoned: new Set(JOURNAL_STATES),
  expired: new Set(JOURNAL_STATES),
  cancelled: new Set(JOURNAL_STATES),
});

function missingRequiredFields(state, parsed) {
  const required = REQUIRED_FIELDS_BY_STATE[state];
  if (!required) return null;
  for (const field of required) {
    const value = parsed[field];
    if (field === "requestId") {
      if (!Number.isInteger(value) || value < 1) return field;
      continue;
    }
    if (field.endsWith("Sha256") || field === "csrSpkiSha256" || field === "leafSha256") {
      if (typeof value !== "string" || !HEX64.test(value)) return field;
      continue;
    }
    if (field === "templateOid") {
      if (typeof value !== "string" || !OID_PATTERN.test(value)) return field;
      continue;
    }
    if (typeof value !== "string" || value.length === 0) return field;
  }
  return null;
}

function readV2Journal(stateDir, enrollmentId, filePath) {
  let parsed;
  try {
    parsed = parseJsonFile(filePath);
  } catch (err) {
    return { kind: "corrupt", error: `v2 journal unreadable: ${err.message}`, path: filePath };
  }
  if (!parsed || typeof parsed !== "object") {
    return { kind: "corrupt", error: "v2 journal is not an object", path: filePath };
  }
  if (parsed.schemaVersion !== JOURNAL_SCHEMA_VERSION) {
    return {
      kind: "corrupt",
      error: `unsupported journal schemaVersion ${JSON.stringify(parsed.schemaVersion)}`,
      path: filePath,
    };
  }
  if (parsed.enrollmentId !== enrollmentId) {
    return {
      kind: "corrupt",
      error: "journal enrollmentId does not match path",
      path: filePath,
    };
  }
  if (typeof parsed.state !== "string" || !JOURNAL_STATES.includes(parsed.state)) {
    return { kind: "corrupt", error: `unknown journal state ${JSON.stringify(parsed.state)}`, path: filePath };
  }

  const missing = missingRequiredFields(parsed.state, parsed);
  if (missing) {
    return {
      kind: "corrupt",
      error: `journal state ${parsed.state} is missing required field ${missing}`,
      path: filePath,
    };
  }

  const artifacts = { csrPem: null, leafPem: null, chainPem: null };
  // Resume-submit needs the CSR PEM. Pending retrieve can use csrSpkiSha256 alone.
  const needsCsr = ["prepared", "submitting", "submission_uncertain", "issued", "validation_deferred", "installing"].includes(
    parsed.state,
  );
  if (needsCsr || typeof parsed.csrSha256 === "string") {
    const csrPath = csrArtifactPath(stateDir, enrollmentId);
    if (needsCsr && !fs.existsSync(csrPath)) {
      return {
        kind: "corrupt",
        error: `journal state ${parsed.state} requires csr.pem but it is missing`,
        path: filePath,
      };
    }
    if (fs.existsSync(csrPath)) {
      try {
        const csrPem = fs.readFileSync(csrPath, "utf8");
        const csrSha256 = sha256HexOfString(csrPem);
        if (typeof parsed.csrSha256 !== "string" || !HEX64.test(parsed.csrSha256)) {
          return {
            kind: "corrupt",
            error: "journal is missing csrSha256 required to verify csr.pem",
            path: filePath,
          };
        }
        if (parsed.csrSha256 !== csrSha256) {
          return {
            kind: "corrupt",
            error: "csr.pem hash does not match journaled csrSha256",
            path: csrPath,
          };
        }
        artifacts.csrPem = csrPem;
      } catch (err) {
        return { kind: "corrupt", error: `failed to read csr.pem: ${err.message}`, path: csrPath };
      }
    }
  }

  const needsLeaf = ["issued", "validation_deferred", "installing", "installed", "install_failed"].includes(
    parsed.state,
  );
  if (needsLeaf) {
    const leafPath = leafArtifactPath(stateDir, enrollmentId);
    if (!fs.existsSync(leafPath)) {
      return {
        kind: "corrupt",
        error: `journal state ${parsed.state} requires leaf.pem but it is missing`,
        path: filePath,
      };
    }
    try {
      const leafPem = fs.readFileSync(leafPath, "utf8");
      const leafSha256 = sha256HexOfString(leafPem);
      if (typeof parsed.leafSha256 !== "string" || !HEX64.test(parsed.leafSha256)) {
        return {
          kind: "corrupt",
          error: "journal is missing leafSha256 required to verify leaf.pem",
          path: filePath,
        };
      }
      if (parsed.leafSha256 !== leafSha256) {
        return {
          kind: "corrupt",
          error: "leaf.pem hash does not match journaled leafSha256",
          path: leafPath,
        };
      }
      artifacts.leafPem = leafPem;
    } catch (err) {
      return { kind: "corrupt", error: `failed to read leaf.pem: ${err.message}`, path: leafPath };
    }
    const chainPath = chainArtifactPath(stateDir, enrollmentId);
    if (fs.existsSync(chainPath)) {
      try {
        artifacts.chainPem = fs.readFileSync(chainPath, "utf8");
      } catch (err) {
        return { kind: "corrupt", error: `failed to read chain.pem: ${err.message}`, path: chainPath };
      }
    }
  }

  return { kind: "valid", path: filePath, journal: parsed, artifacts };
}

/**
 * Write key-generation intent before certreq -new.
 */
async function writeKeygenIntent({
  stateDir,
  enrollmentId,
  containerName,
  attempt,
  snapshotSha256,
  jobId,
}) {
  assertEnrollmentId(enrollmentId);
  if (typeof containerName !== "string" || containerName.length === 0) {
    throw new TypeError("containerName is required");
  }
  ensureEnrollmentDir(stateDir, enrollmentId);
  const payload = {
    enrollmentId,
    containerName,
    attempt: Number.isInteger(attempt) ? attempt : null,
    snapshotSha256: typeof snapshotSha256 === "string" ? snapshotSha256 : null,
    jobId: typeof jobId === "string" ? jobId : null,
    updatedAt: new Date().toISOString(),
  };
  await durableWriteFile(keygenIntentPath(stateDir, enrollmentId), `${JSON.stringify(payload)}\n`);
  return payload;
}

function readKeygenIntent(stateDir, enrollmentId) {
  const dest = keygenIntentPath(stateDir, enrollmentId);
  if (!fs.existsSync(dest)) return null;
  try {
    const parsed = parseJsonFile(dest);
    if (!parsed || parsed.enrollmentId !== enrollmentId) return null;
    if (typeof parsed.containerName !== "string") return null;
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Persist CSR PEM and commit prepared journal (or update hashes for later states).
 */
async function writeCsrArtifact({ stateDir, enrollmentId, csrPem }) {
  assertEnrollmentId(enrollmentId);
  if (typeof csrPem !== "string" || !csrPem.includes("BEGIN")) {
    throw new TypeError("csrPem must be a PEM string");
  }
  ensureEnrollmentDir(stateDir, enrollmentId);
  // Hash the exact bytes persisted (normalize trailing newline first).
  const normalized = csrPem.endsWith("\n") ? csrPem : `${csrPem}\n`;
  const csrSha256 = sha256HexOfString(normalized);
  await durableWriteFile(csrArtifactPath(stateDir, enrollmentId), normalized);
  return { csrSha256, path: csrArtifactPath(stateDir, enrollmentId) };
}

async function writeIssuedCertificateArtifacts({
  stateDir,
  enrollmentId,
  leafPem,
  chainPem = null,
}) {
  assertEnrollmentId(enrollmentId);
  if (typeof leafPem !== "string" || !leafPem.includes("BEGIN")) {
    throw new TypeError("leafPem must be a PEM string");
  }
  ensureEnrollmentDir(stateDir, enrollmentId);
  const normalizedLeaf = leafPem.endsWith("\n") ? leafPem : `${leafPem}\n`;
  const leafSha256 = sha256HexOfString(normalizedLeaf);
  await durableWriteFile(leafArtifactPath(stateDir, enrollmentId), normalizedLeaf);
  let chainSha256 = null;
  if (typeof chainPem === "string" && chainPem.includes("BEGIN")) {
    const normalizedChain = chainPem.endsWith("\n") ? chainPem : `${chainPem}\n`;
    chainSha256 = sha256HexOfString(normalizedChain);
    await durableWriteFile(chainArtifactPath(stateDir, enrollmentId), normalizedChain);
  }
  return { leafSha256, chainSha256 };
}

/**
 * Commit a journal.json transition. Caller must hold the enrollment lock.
 * Enforces state-required fields, permitted transitions, and immutable
 * enrollment identity fields once committed past keygen_intent.
 * @param {object} fields journal body fields (state-required)
 */
async function writeEnrollmentJournal(stateDir, enrollmentId, fields) {
  assertEnrollmentId(enrollmentId);
  if (!fields || typeof fields !== "object") {
    throw new TypeError("journal fields are required");
  }
  if (typeof fields.state !== "string" || !JOURNAL_STATES.includes(fields.state)) {
    throw new TypeError(`invalid journal state ${JSON.stringify(fields?.state)}`);
  }
  const missing = missingRequiredFields(fields.state, fields);
  if (missing) {
    throw new TypeError(`journal state ${fields.state} is missing required field ${missing}`);
  }

  const existing = readEnrollmentJournal(stateDir, enrollmentId);
  if (existing.kind === "corrupt") {
    throw new Error(`cannot transition corrupt journal: ${existing.error}`);
  }
  let previousState = null;
  let previousJournal = null;
  if (existing.kind === "valid" || existing.kind === "legacy") {
    previousState = existing.journal.state;
    previousJournal = existing.journal;
  }

  const allowed = ALLOWED_TRANSITIONS[fields.state];
  if (!allowed || !allowed.has(previousState)) {
    throw new Error(
      `invalid journal transition ${previousState == null ? "(none)" : previousState} -> ${fields.state}`,
    );
  }

  if (previousJournal) {
    if (
      typeof previousJournal.containerName === "string" &&
      typeof fields.containerName === "string" &&
      previousJournal.containerName !== fields.containerName
    ) {
      throw new Error("journal field containerName is immutable after commit");
    }
    if (previousState !== "keygen_intent") {
      for (const field of ["snapshotSha256", "csrSpkiSha256", "templateOid", "csrSha256"]) {
        if (
          typeof previousJournal[field] === "string" &&
          typeof fields[field] === "string" &&
          previousJournal[field] !== fields[field]
        ) {
          throw new Error(`journal field ${field} is immutable after commit`);
        }
      }
    }
  }

  ensureEnrollmentDir(stateDir, enrollmentId);
  const payload = {
    schemaVersion: JOURNAL_SCHEMA_VERSION,
    enrollmentId,
    ...fields,
    updatedAt: new Date().toISOString(),
  };
  await durableWriteFile(journalV2Path(stateDir, enrollmentId), `${JSON.stringify(payload)}\n`);
  return payload;
}

/**
 * Scan open enrollments for CNG containers that must not be deleted.
 * Fail closed: any scan/read error yields ok:false (defer AD CS container deletes).
 *
 * @returns {{ ok: true, containers: Set<string>, enrollments: object[] }
 *   | { ok: false, error: string }}
 */
function listProtectedEnrollmentContainers(stateDir) {
  if (typeof stateDir !== "string" || stateDir.length === 0) {
    return { ok: false, error: "stateDir is required" };
  }
  const root = enrollmentsRoot(stateDir);
  let names;
  try {
    // readdir distinguishes missing (ENOENT) from inaccessible (EACCES/EPERM).
    // existsSync(false) must not be treated as an empty protected set.
    names = fs.readdirSync(root);
  } catch (err) {
    if (err && err.code === "ENOENT") {
      return { ok: true, containers: new Set(), enrollments: [] };
    }
    return { ok: false, error: `cannot read adcs-enrollments: ${err.message}` };
  }

  const containers = new Set();
  const enrollments = [];

  for (const name of names) {
    // Skip ephemeral tmp files
    if (name.endsWith(".tmp")) {
      return {
        ok: false,
        error: `transient write artifact present under adcs-enrollments (${name}); defer destructive sweep`,
      };
    }

    let enrollmentId = null;
    if (ENROLLMENT_ID_PATTERN.test(name)) {
      enrollmentId = name;
    } else if (name.endsWith(".json")) {
      const base = name.slice(0, -".json".length);
      if (ENROLLMENT_ID_PATTERN.test(base)) enrollmentId = base;
    }
    if (!enrollmentId) {
      // Unknown entry in the enrollments root: fail closed.
      return {
        ok: false,
        error: `unexpected entry in adcs-enrollments: ${name}`,
      };
    }

    const read = readEnrollmentJournal(stateDir, enrollmentId);
    if (read.kind === "corrupt") {
      return { ok: false, error: `enrollment ${enrollmentId}: ${read.error}` };
    }
    if (read.kind === "not_found") {
      // Directory exists without readable journal/intent — fail closed.
      // Use stat so permission errors are not treated as "absent".
      const dir = enrollmentDir(stateDir, enrollmentId);
      try {
        fs.statSync(dir);
        return {
          ok: false,
          error: `enrollment directory ${enrollmentId} has no readable journal or keygen intent`,
        };
      } catch (err) {
        if (err && err.code === "ENOENT") continue;
        return {
          ok: false,
          error: `cannot stat enrollment directory ${enrollmentId}: ${err.message}`,
        };
      }
    }

    const journal = read.journal;
    const state = journal.state;
    if (!OPEN_JOURNAL_STATES.includes(state) && state !== "install_failed") {
      // Terminal receipts (except install_failed, which must retain the key
      // until ownership is proven) do not protect containers for the sweep.
      // install_failed still protects.
      if (state === "installed" || state === "rejected_invalid" || state === "abandoned") {
        continue;
      }
      if (!OPEN_JOURNAL_STATES.includes(state) && state !== "install_failed") {
        // Other terminals: still protect until an explicit abandon clears them.
        if (
          ["validation_expired", "denied", "refused", "expired", "cancelled"].includes(state)
        ) {
          // Keys may still exist; protect until explicit abandon.
        } else {
          continue;
        }
      }
    }

    const protect =
      OPEN_JOURNAL_STATES.includes(state) ||
      state === "install_failed" ||
      ["validation_expired", "denied", "refused", "expired", "cancelled"].includes(state);

    if (!protect) continue;

    let containerName = journal.containerName;
    if (typeof containerName !== "string" || containerName.length === 0) {
      // Open enrollment without container name: fail closed rather than
      // allowing the sweep to guess.
      if (OPEN_JOURNAL_STATES.includes(state) || state === "keygen_intent") {
        return {
          ok: false,
          error: `open enrollment ${enrollmentId} (state ${state}) has no containerName`,
        };
      }
      continue;
    }
    containers.add(containerName);
    enrollments.push({ enrollmentId, state, containerName });
  }

  return { ok: true, containers, enrollments };
}

/**
 * Whether a CNG container name looks like an AD CS enrollment container.
 * Used when the protected-set scan fails: defer deletes for these only.
 */
function looksLikeEnrollmentContainerName(containerName) {
  if (typeof containerName !== "string") return false;
  // tokentimer-enr-<uuid> (prefix may vary; match enr-<uuid> segment)
  return /enr-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
    containerName,
  );
}

/** Extract enrollment UUID from an enrollment-shaped CNG container name. */
function enrollmentIdFromContainerName(containerName) {
  if (typeof containerName !== "string") return null;
  const match = containerName.match(
    /enr-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i,
  );
  return match ? match[1].toLowerCase() : null;
}

function journalStateProtectsContainer(state) {
  return (
    OPEN_JOURNAL_STATES.includes(state) ||
    state === "install_failed" ||
    ["validation_expired", "denied", "refused", "expired", "cancelled"].includes(state)
  );
}

/**
 * Recheck whether an enrollment currently protects a CNG container.
 * Caller must hold the enrollment lock. Fail closed on corrupt journals.
 */
function isEnrollmentContainerProtected(stateDir, enrollmentId, containerName) {
  assertEnrollmentId(enrollmentId);
  const read = readEnrollmentJournal(stateDir, enrollmentId);
  if (read.kind === "corrupt") {
    return {
      protected: true,
      reason: "corrupt AD CS enrollment journal; deferred",
    };
  }
  if (read.kind === "not_found") {
    return { protected: false };
  }
  const state = read.journal.state;
  if (!journalStateProtectsContainer(state)) {
    return { protected: false };
  }
  const journalContainer = read.journal.containerName;
  if (
    typeof journalContainer === "string" &&
    journalContainer.length > 0 &&
    journalContainer !== containerName
  ) {
    return { protected: false };
  }
  return {
    protected: true,
    reason: "open AD CS enrollment journal protects this container",
  };
}

/** @deprecated path helper kept for callers that still point at legacy files */
function enrollmentJournalPath(stateDir, enrollmentId) {
  return legacyJournalPath(stateDir, enrollmentId);
}

module.exports = {
  JOURNAL_SCHEMA_VERSION,
  OPEN_JOURNAL_STATES,
  JOURNAL_STATES,
  enrollmentsRoot,
  enrollmentDir,
  journalV2Path,
  legacyJournalPath,
  keygenIntentPath,
  csrArtifactPath,
  leafArtifactPath,
  chainArtifactPath,
  enrollmentJournalPath,
  sha256HexOfString,
  sha256HexOfBuffer,
  durableWriteFile,
  durableWriteFileSync,
  ensureEnrollmentDir,
  readEnrollmentJournal,
  writeKeygenIntent,
  readKeygenIntent,
  writeCsrArtifact,
  writeIssuedCertificateArtifacts,
  writeEnrollmentJournal,
  listProtectedEnrollmentContainers,
  looksLikeEnrollmentContainerName,
  enrollmentIdFromContainerName,
  isEnrollmentContainerProtected,
  ALLOWED_TRANSITIONS,
};
