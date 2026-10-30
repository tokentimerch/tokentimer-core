"use strict";

// Strict query parsing for the operator read routes. The contract schemas use
// additionalProperties: false, so an unknown or repeated key is refused here
// too, and the fixtures in packages/contracts/mcp are replayed against these
// parsers in the tests so the two cannot drift apart.

const read = require("./readProjections");

const DISPLAY_STATUSES = [
  "discovered",
  "provisioning",
  "active",
  "renewing",
  "expiring",
  "expired",
  "revoked",
  "decommissioned",
];
const JOB_STATUSES = [
  "pending_approval",
  "approved",
  "rejected",
  "pending",
  "claimed",
  "running",
  "succeeded",
  "failed",
  "blocked",
  "cancelled",
  "dry_run_complete",
  "orphaned_unknown_effect",
  "awaiting_issuer",
];
const JOB_OPERATIONS = [
  "issue",
  "renew",
  "deploy",
  "deploy-from-store",
  "reload",
  "revoke",
  "noop",
  "protocol_smoke",
  "distribute-trust",
  "revoke-trust",
  "continue-enrollment",
  "adcs-preflight",
];
const CREATED_SINCE = ["24h", "7d", "30d"];
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

class QueryError extends Error {
  constructor(message) {
    super(message);
    this.code = "OPERATOR_VALIDATION_ERROR";
  }
}

function oneOf(list, name) {
  return (value) => {
    if (!list.includes(value)) throw new QueryError(`${name} is invalid`);
    return value;
  };
}

const validators = {
  limit(value) {
    const limit = read.clampLimit(value);
    if (limit === null) throw new QueryError("limit must be an integer from 1 to 50");
    return limit;
  },
  cursor(value) {
    return read.decodeCursor(value);
  },
  status: oneOf(DISPLAY_STATUSES, "status"),
  jobStatus: oneOf(JOB_STATUSES, "status"),
  operation: oneOf(JOB_OPERATIONS, "operation"),
  createdSince: oneOf(CREATED_SINCE, "createdSince"),
  includeRetired(value) {
    if (value !== "true" && value !== "false") throw new QueryError("includeRetired must be true or false");
    return value === "true";
  },
  expiresWithinDays(value) {
    const parsed = Number.parseInt(value, 10);
    if (String(parsed) !== value || parsed < 1 || parsed > 3650) {
      throw new QueryError("expiresWithinDays must be an integer from 1 to 3650");
    }
    return parsed;
  },
  expiresBefore(value) {
    const date = new Date(value);
    if (!RFC3339.test(value) || Number.isNaN(date.getTime())) throw new QueryError("expiresBefore must be a date-time");
    return date;
  },
  query(value) {
    if (value.length < 1 || value.length > 128) throw new QueryError("query must be 1 to 128 characters");
    return value;
  },
  subjectId(value) {
    if (!read.isUuid(value)) throw new QueryError("subjectId must be a UUID");
    return value;
  },
};

// spec: { requestKey: ["validatorName", "resultKey"] }
function parseQuery(query, spec) {
  const out = {};
  for (const [key, raw] of Object.entries(query || {})) {
    if (!Object.hasOwn(spec, key)) throw new QueryError(`Unknown parameter: ${key}`);
    if (typeof raw !== "string") throw new QueryError(`${key} must be a single value`);
    const [validatorName, resultKey] = spec[key];
    out[resultKey] = validators[validatorName](raw);
  }
  return out;
}

const SPECS = Object.freeze({
  certificates: {
    status: ["status", "status"],
    includeRetired: ["includeRetired", "includeRetired"],
    expiresWithinDays: ["expiresWithinDays", "expiresWithinDays"],
    expiresBefore: ["expiresBefore", "expiresBefore"],
    query: ["query", "query"],
    limit: ["limit", "limit"],
    cursor: ["cursor", "offset"],
  },
  paged: {
    limit: ["limit", "limit"],
    cursor: ["cursor", "offset"],
  },
  jobs: {
    status: ["jobStatus", "status"],
    operation: ["operation", "operation"],
    subjectId: ["subjectId", "subjectId"],
    createdSince: ["createdSince", "createdSince"],
    limit: ["limit", "limit"],
    cursor: ["cursor", "offset"],
  },
});

function parseCertificates(query) {
  const parsed = parseQuery(query, SPECS.certificates);
  if (parsed.expiresWithinDays !== undefined && parsed.expiresBefore !== undefined) {
    throw new QueryError("Use expiresWithinDays or expiresBefore, not both");
  }
  return parsed;
}

module.exports = {
  QueryError,
  SPECS,
  parseCertificates,
  parseJobs: (query) => parseQuery(query, SPECS.jobs),
  parsePaged: (query) => parseQuery(query, SPECS.paged),
  parseQuery,
};
