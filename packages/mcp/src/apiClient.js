"use strict";

// The only code that sends the connection credential anywhere.
//
//  - GET only, and only below /api/v1/operator/.
//  - Redirects are refused, so the credential cannot be forwarded elsewhere.
//  - A timeout and a hard response-size cap bound every call.
//  - Errors map to fixed codes and fixed wording. The upstream body, headers
//    and URL are never copied into an error, so nothing the API says can
//    reach the model through a failure.

const crypto = require("node:crypto");

const OPERATOR_PREFIX = "/api/v1/operator/";

class ToolError extends Error {
  constructor(code, message, { retryable = false, correlationId, reason } = {}) {
    super(message);
    this.name = "ToolError";
    this.code = code;
    this.retryable = retryable;
    this.correlationId = correlationId || crypto.randomUUID();
    this.reason = reason;
  }

  toJSON() {
    const out = {
      code: this.code,
      message: this.message,
      retryable: this.retryable,
      correlationId: this.correlationId,
    };
    if (this.reason) out.reason = this.reason;
    return out;
  }
}

// What the API's own refusal codes mean to a client. Only a code found in this
// table is ever acted on; the wording is ours, never the server's, so nothing
// the API writes in a body can reach the model.
const CODE_ERRORS = Object.freeze({
  OPERATOR_WRITES_DISABLED: ["MCP_WRITES_DISABLED", "Assistant write requests are not enabled for this workspace.", false, null],
  OPERATOR_PLAN_EXPIRED: ["MCP_PLAN_EXPIRED", "The preview expired. Preview again.", false, null],
  OPERATOR_PLAN_MISMATCH: ["MCP_VALIDATION_ERROR", "The plan does not match what was previewed.", false, "plan_mismatch"],
  OPERATOR_INTENT_STALE: ["MCP_INTENT_STALE", "The certificate changed since the preview. Preview again.", false, null],
  OPERATOR_IDEMPOTENCY_CONFLICT: ["MCP_IDEMPOTENCY_CONFLICT", "This request id was already used for something different. Use a new request id.", false, null],
  OPERATOR_PENDING_LIMIT: ["MCP_RATE_LIMITED", "Too many assistant requests are already waiting for approval.", true, "pending_limit"],
  OPERATOR_REQUEST_NOT_CANCELLABLE: ["MCP_CONFLICT", "The request is no longer waiting for approval.", false, "not_cancellable"],
  OPERATOR_CERTIFICATE_NOT_MANAGED: ["MCP_CONFLICT", "TokenTimer is not managing this certificate.", false, "not_managed"],
  OPERATOR_CERTIFICATE_RETIRED: ["MCP_CONFLICT", "The certificate is retired.", false, "retired"],
  OPERATOR_RENEWAL_NOT_POSSIBLE: ["MCP_CONFLICT", "A renewal cannot be requested for this certificate.", false, "renewal_not_possible"],
  CERTOPS_RENEWAL_PER_CA_CAP_EXCEEDED: ["MCP_CONFLICT", "The certificate authority has too many renewals in progress. Try again later.", true, "capacity"],
  CERTOPS_WORKSPACE_PAUSED: ["MCP_CONFLICT", "Certificate operations are paused for this workspace.", true, "workspace_paused"],
});

const STATUS_ERRORS = Object.freeze({
  400: ["MCP_VALIDATION_ERROR", "The request was refused as invalid.", false],
  401: ["MCP_UNAUTHENTICATED", "The connection credential was not accepted. It may be revoked, expired or mistyped.", false],
  403: ["MCP_SCOPE_DENIED", "The connection is not allowed to use this tool.", false],
  404: ["MCP_NOT_FOUND", "Not found, or this interface is not enabled.", false],
  429: ["MCP_RATE_LIMITED", "Too many requests. Try again shortly.", true],
});

function pathIsConfined(path) {
  if (!path.startsWith(OPERATOR_PREFIX)) return false;
  // Plain segments only: no dot segments, empty segments or percent-encoding.
  return /^[A-Za-z0-9][A-Za-z0-9_-]*(?:\/[A-Za-z0-9][A-Za-z0-9_-]*)*$/.test(path.slice(OPERATOR_PREFIX.length));
}

function buildUrl(config, path, query) {
  if (!pathIsConfined(path)) {
    throw new ToolError("MCP_VALIDATION_ERROR", "The request path is not allowed.");
  }
  const url = new URL(`${config.origin}${config.basePath}${path}`);
  for (const [key, value] of Object.entries(query || {})) {
    if (value === undefined || value === null) continue;
    url.searchParams.append(key, String(value));
  }
  return url;
}

async function readCapped(response, maxBytes, correlationId) {
  const declared = Number.parseInt(response.headers.get("content-length") || "", 10);
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new ToolError("MCP_RESPONSE_TOO_LARGE", "The response was larger than the adapter allows.", { correlationId });
  }
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks = [];
  let total = 0;
  for (;;) {
    let chunk;
    try {
      chunk = await reader.read();
    } catch (error) {
      // The timeout also covers the body, and a connection can drop mid-read.
      const timedOut = error?.name === "TimeoutError" || error?.name === "AbortError";
      throw new ToolError(
        "MCP_UPSTREAM_ERROR",
        timedOut ? "The TokenTimer API did not answer in time." : "The TokenTimer API connection was interrupted.",
        { retryable: true, correlationId },
      );
    }
    const { done, value } = chunk;
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new ToolError("MCP_RESPONSE_TOO_LARGE", "The response was larger than the adapter allows.", { correlationId });
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

// Pulls the machine code (and a snake_case reason, if present) out of a
// refusal body, and nothing else. Anything unreadable is simply no code.
async function refusalCode(response, maxBytes, correlationId) {
  if (![403, 409, 410, 429].includes(response.status)) {
    await response.body?.cancel().catch(() => {});
    return null;
  }
  try {
    const text = await readCapped(response, Math.min(maxBytes, 8192), correlationId);
    const body = JSON.parse(text);
    const code = typeof body?.code === "string" && /^[A-Z][A-Z0-9_]{2,80}$/.test(body.code) ? body.code : null;
    const reason = typeof body?.reason === "string" && /^[a-z][a-z0-9_]{1,63}$/.test(body.reason) ? body.reason : undefined;
    return code ? { code, reason } : null;
  } catch (_error) {
    return null;
  }
}

function createApiClient(config, { fetchImpl = globalThis.fetch } = {}) {
  async function request(method, path, { query, body } = {}) {
    const correlationId = crypto.randomUUID();
    const url = buildUrl(config, path, query);
    const headers = {
      Authorization: config.authorizationHeader(),
      Accept: "application/json",
      "X-Request-Id": correlationId,
    };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    let response;
    try {
      response = await fetchImpl(url, {
        method,
        redirect: "error",
        signal: AbortSignal.timeout(config.requestTimeoutMs),
        headers,
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
    } catch (error) {
      const timedOut = error?.name === "TimeoutError" || error?.name === "AbortError";
      throw new ToolError(
        "MCP_UPSTREAM_ERROR",
        timedOut ? "The TokenTimer API did not answer in time." : "The TokenTimer API could not be reached.",
        { retryable: true, correlationId },
      );
    }

    if (response.status >= 300 && response.status < 400) {
      throw new ToolError("MCP_UPSTREAM_ERROR", "The TokenTimer API answered with an unexpected redirect.", { correlationId });
    }
    if (!response.ok) {
      // A refusal may carry one of the API's own codes. Read it only to look it
      // up in the table above; the body is otherwise discarded unread.
      const refusal = await refusalCode(response, config.maxResponseBytes, correlationId);
      if (refusal && Object.hasOwn(CODE_ERRORS, refusal.code)) {
        const [code, message, retryable, reason] = CODE_ERRORS[refusal.code];
        throw new ToolError(code, message, { retryable, correlationId, reason: refusal.reason || reason || undefined });
      }
      const mapped = STATUS_ERRORS[response.status];
      if (mapped) {
        throw new ToolError(mapped[0], mapped[1], { retryable: mapped[2], correlationId });
      }
      throw new ToolError("MCP_UPSTREAM_ERROR", "The TokenTimer API reported an error.", {
        retryable: response.status >= 500,
        correlationId,
      });
    }

    const text = await readCapped(response, config.maxResponseBytes, correlationId);
    try {
      return { body: JSON.parse(text), correlationId };
    } catch (_error) {
      throw new ToolError("MCP_UPSTREAM_ERROR", "The TokenTimer API returned something that is not JSON.", { correlationId });
    }
  }

  return Object.freeze({
    get: (path, query) => request("GET", path, { query }),
    post: (path, body) => request("POST", path, { body: body ?? {} }),
  });
}

module.exports = { OPERATOR_PREFIX, ToolError, buildUrl, createApiClient, pathIsConfined, readCapped };
