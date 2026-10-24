"use strict";

// Onboarding sessions store intent, progress and non-secret operation
// references only. Anything that looks like a credential is rejected on write
// so a buggy client can never persist one.

const { containsPrivateKeyMaterial } = require("../../utils/secretMaterial");

const FLOWS = Object.freeze(["mega", "certops"]);
const STATUSES = Object.freeze(["in_progress", "completed", "dismissed"]);
const SECTIONS = Object.freeze(["intent", "progress", "operation_refs"]);

const MAX_DEPTH = 6;
const MAX_SECTION_BYTES = 32 * 1024;
const MAX_STRING = 512;
const MAX_ARRAY = 100;
const MAX_KEYS = 100;

const KEY_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;
const FORBIDDEN_KEY =
  /(password|passwd|secret|credential|api[_-]?key|private[_-]?key|bearer|authorization|access[_-]?token|bootstrap|session[_-]?id)/i;
const SECRET_VALUE =
  /^(ttboot_|ttagent_|ttx_|ghp_|github_pat_|glpat-|hvs\.|xox[bp]-)|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----/;

class OnboardingValidationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "OnboardingValidationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new OnboardingValidationError(code, message);
}

function sanitizeValue(value, path, depth) {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("INVALID_VALUE", `${path} must be finite`);
    return value;
  }
  if (typeof value === "string") {
    if (value.length > MAX_STRING) {
      fail("VALUE_TOO_LONG", `${path} exceeds ${MAX_STRING} characters`);
    }
    if (SECRET_VALUE.test(value)) {
      fail("SECRET_REJECTED", `${path} looks like a credential`);
    }
    return value;
  }
  if (depth >= MAX_DEPTH) fail("TOO_DEEP", `${path} is nested too deeply`);
  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY) {
      fail("TOO_MANY_ITEMS", `${path} exceeds ${MAX_ARRAY} items`);
    }
    return value.map((item, i) =>
      sanitizeValue(item, `${path}[${i}]`, depth + 1),
    );
  }
  if (typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length > MAX_KEYS) {
      fail("TOO_MANY_KEYS", `${path} exceeds ${MAX_KEYS} keys`);
    }
    const out = {};
    for (const key of keys) {
      if (!KEY_PATTERN.test(key)) fail("INVALID_KEY", `${path}.${key} is invalid`);
      if (FORBIDDEN_KEY.test(key)) {
        fail("SECRET_REJECTED", `${path}.${key} is not allowed`);
      }
      out[key] = sanitizeValue(value[key], `${path}.${key}`, depth + 1);
    }
    return out;
  }
  return fail("INVALID_VALUE", `${path} has an unsupported type`);
}

function sanitizeSection(name, value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_SECTION", `${name} must be an object`);
  }
  const clean = sanitizeValue(value, name, 0);
  if (Buffer.byteLength(JSON.stringify(clean), "utf8") > MAX_SECTION_BYTES) {
    fail("SECTION_TOO_LARGE", `${name} exceeds ${MAX_SECTION_BYTES} bytes`);
  }
  // Field names and credential prefixes are not enough: private material can
  // arrive as DER, encoded PEM, or a compact compressed value under an
  // ordinary key. Scan the bounded, validated section with the shared rule.
  if (containsPrivateKeyMaterial(clean)) {
    fail("SECRET_REJECTED", `${name} contains private key material`);
  }
  return clean;
}

function assertFlow(flow) {
  if (!FLOWS.includes(flow)) fail("INVALID_FLOW", "Unknown onboarding flow");
  return flow;
}

/**
 * Validates a client write. `expectedRevision` is mandatory so concurrent tabs
 * and devices cannot silently overwrite each other.
 */
function validateSessionWrite(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    fail("INVALID_BODY", "Request body must be an object");
  }
  const { expectedRevision } = body;
  if (!Number.isInteger(expectedRevision) || expectedRevision < 0) {
    fail("INVALID_REVISION", "expectedRevision must be a non-negative integer");
  }
  const patch = {};
  for (const section of SECTIONS) {
    if (body[section] !== undefined) {
      patch[section] = sanitizeSection(section, body[section]);
    }
  }
  if (body.status !== undefined) {
    if (!STATUSES.includes(body.status)) {
      fail("INVALID_STATUS", "status is not supported");
    }
    patch.status = body.status;
  }
  if (body.plannerVersion !== undefined) {
    if (!Number.isInteger(body.plannerVersion) || body.plannerVersion < 1) {
      fail("INVALID_PLANNER_VERSION", "plannerVersion must be a positive integer");
    }
    patch.plannerVersion = body.plannerVersion;
  }
  return { expectedRevision, patch };
}

module.exports = {
  FLOWS,
  STATUSES,
  OnboardingValidationError,
  assertFlow,
  validateSessionWrite,
};
