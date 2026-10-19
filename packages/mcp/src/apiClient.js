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
  constructor(code, message, { retryable = false, correlationId } = {}) {
    super(message);
    this.name = "ToolError";
    this.code = code;
    this.retryable = retryable;
    this.correlationId = correlationId || crypto.randomUUID();
  }

  toJSON() {
    return {
      code: this.code,
      message: this.message,
      retryable: this.retryable,
      correlationId: this.correlationId,
    };
  }
}

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

function createApiClient(config, { fetchImpl = globalThis.fetch } = {}) {
  async function get(path, query) {
    const correlationId = crypto.randomUUID();
    const url = buildUrl(config, path, query);
    let response;
    try {
      response = await fetchImpl(url, {
        method: "GET",
        redirect: "error",
        signal: AbortSignal.timeout(config.requestTimeoutMs),
        headers: {
          Authorization: config.authorizationHeader(),
          Accept: "application/json",
          "X-Request-Id": correlationId,
        },
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
      await response.body?.cancel().catch(() => {});
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

  return Object.freeze({ get });
}

module.exports = { OPERATOR_PREFIX, ToolError, buildUrl, createApiClient, pathIsConfined, readCapped };
