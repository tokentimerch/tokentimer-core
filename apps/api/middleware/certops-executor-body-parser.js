"use strict";

const express = require("express");
const {
  createCertOpsMachineTokenPreAuthRateLimit,
} = require("./machine-token-rate-limit");

const CERTOPS_EXECUTOR_EVENTS_PATH = "/api/v1/certops/executor/events";
// The largest contract-valid event can contain 16 evidence items, each with
// bounded metadata and artifact references. Four MiB permits that envelope
// even when JSON escaping expands string values, while remaining well below
// the general ten MiB API parser limit.
const CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES = 4 * 1024 * 1024;
const CERTOPS_EXECUTOR_EVENT_BODY_TOO_LARGE =
  "CERTOPS_EXECUTOR_EVENT_BODY_TOO_LARGE";
const CERTOPS_EXECUTOR_EVENT_INVALID = "CERTOPS_EXECUTOR_EVENT_INVALID";
const CERTOPS_EXECUTOR_PRE_AUTH_LIMITER_APPLIED = Symbol(
  "certopsExecutorPreAuthLimiterApplied",
);

function isExactExecutorEventPost(req) {
  return (
    req.method === "POST" &&
    (req.path || req.originalUrl?.split("?", 1)[0]) ===
      CERTOPS_EXECUTOR_EVENTS_PATH
  );
}

function hasCertOpsExecutorPreAuthLimit(req) {
  return Boolean(req?.[CERTOPS_EXECUTOR_PRE_AUTH_LIMITER_APPLIED]);
}

function markCertOpsExecutorPreAuthLimit(req) {
  Object.defineProperty(req, CERTOPS_EXECUTOR_PRE_AUTH_LIMITER_APPLIED, {
    configurable: false,
    enumerable: false,
    value: true,
  });
}

function createCertOpsExecutorEventJsonParser(options = {}) {
  return express.json({
    limit:
      options.limitBytes === undefined
        ? CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES
        : options.limitBytes,
    strict: true,
  });
}

function handleCertOpsExecutorEventBodyParserError(error, _req, res, next) {
  if (error?.type === "entity.too.large" || error?.status === 413) {
    return res.status(413).json({
      error: "Executor event payload is too large",
      code: CERTOPS_EXECUTOR_EVENT_BODY_TOO_LARGE,
    });
  }

  if (
    error?.type === "entity.parse.failed" ||
    (error instanceof SyntaxError && error?.status === 400)
  ) {
    return res.status(400).json({
      error: "Executor event payload is invalid",
      code: CERTOPS_EXECUTOR_EVENT_INVALID,
    });
  }

  return next(error);
}

/**
 * Production-only pre-parser boundary for the single M2 executor endpoint.
 * It applies the cheap prefix/IP limiter before any JSON parsing, feature
 * gating, token hashing, database access, or handler work. The router checks
 * the request marker and applies its own limiter only when mounted standalone.
 */
function createCertOpsExecutorEventPreParserBoundary(options = {}) {
  const preAuthRateLimitMiddleware =
    options.preAuthRateLimitMiddleware ||
    createCertOpsMachineTokenPreAuthRateLimit(options.rateLimitOptions || {});
  const parser =
    options.parser || createCertOpsExecutorEventJsonParser(options.parserOptions);
  const errorHandler =
    options.errorHandler || handleCertOpsExecutorEventBodyParserError;

  return function certOpsExecutorEventPreParserBoundary(req, res, next) {
    if (!isExactExecutorEventPost(req)) return next();
    return preAuthRateLimitMiddleware(req, res, (rateLimitError) => {
      if (rateLimitError) return next(rateLimitError);
      markCertOpsExecutorPreAuthLimit(req);
      return parser(req, res, (parserError) => {
        if (parserError) return errorHandler(parserError, req, res, next);
        return next();
      });
    });
  };
}

module.exports = {
  CERTOPS_EXECUTOR_EVENTS_PATH,
  CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES,
  CERTOPS_EXECUTOR_EVENT_BODY_TOO_LARGE,
  CERTOPS_EXECUTOR_EVENT_INVALID,
  CERTOPS_EXECUTOR_PRE_AUTH_LIMITER_APPLIED,
  createCertOpsExecutorEventJsonParser,
  createCertOpsExecutorEventPreParserBoundary,
  handleCertOpsExecutorEventBodyParserError,
  hasCertOpsExecutorPreAuthLimit,
  isExactExecutorEventPost,
};
