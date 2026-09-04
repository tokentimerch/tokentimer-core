"use strict";

const CERTOPS_LIST_SORT_INVALID = "CERTOPS_LIST_SORT_INVALID";

function sortError(message) {
  const error = new Error(message);
  error.code = CERTOPS_LIST_SORT_INVALID;
  return error;
}

/**
 * Resolves a public list sort onto a server-owned SQL expression. The caller
 * supplies the allowlist and tie-breaker; no request value is ever interpolated
 * into ORDER BY.
 */
function resolveListSort({
  sort,
  direction,
  allowlist,
  defaultOrderBy,
  tieBreaker,
}) {
  const hasSort = sort !== undefined && sort !== null && sort !== "";
  const hasDirection =
    direction !== undefined && direction !== null && direction !== "";

  if (!hasSort) {
    if (hasDirection) {
      throw sortError("direction requires a sort key");
    }
    return defaultOrderBy;
  }

  const key = String(sort).trim();
  if (!Object.prototype.hasOwnProperty.call(allowlist, key)) {
    throw sortError("Unsupported sort key");
  }

  const normalizedDirection = hasDirection ? String(direction).trim() : "asc";
  if (normalizedDirection !== "asc" && normalizedDirection !== "desc") {
    throw sortError("direction must be asc or desc");
  }

  const sqlDirection = normalizedDirection === "desc" ? "DESC" : "ASC";
  return `${allowlist[key]} ${sqlDirection} NULLS LAST, ${tieBreaker}`;
}

module.exports = {
  CERTOPS_LIST_SORT_INVALID,
  resolveListSort,
};
