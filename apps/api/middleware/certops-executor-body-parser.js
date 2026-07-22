"use strict";

const express = require("express");
const {
  createCertOpsMachineTokenPreAuthRateLimit,
} = require("./machine-token-rate-limit");

const CERTOPS_EXECUTOR_EVENTS_PATH = "/api/v1/certops/executor/events";
const CERTOPS_CONTROLLER_OBSERVATIONS_PATH =
  "/api/v1/certops/executor/observations";
const CERTOPS_CONTROLLER_PROVISIONING_COMMANDS_PATH =
  "/api/v1/certops/executor/provisioning-commands/next";
const CERTOPS_CONTROLLER_PROVISIONING_AUTHORIZATION_PATH =
  "/api/v1/certops/executor/provisioning-commands/:jobId/authorize-mutation";
const CERTOPS_JOB_EVENTS_PATH = "/api/v1/certops/jobs/:jobId/events";
const CERTOPS_JOB_EVIDENCE_PATH = "/api/v1/certops/jobs/:jobId/evidence";
const CERTOPS_AGENT_REGISTER_PATH = "/api/v1/certops/agent/register";
const CERTOPS_AGENT_HEARTBEAT_PATH = "/api/v1/certops/agent/heartbeat";
const CERTOPS_AGENT_JOBS_CLAIM_PATH = "/api/v1/certops/agent/jobs/claim";
const CERTOPS_AGENT_JOBS_RESULTS_PATH = "/api/v1/certops/agent/jobs/results";
const CERTOPS_MACHINE_WRITE_ROUTE_FAMILIES = Object.freeze({
  aggregateExecutorEvents: "aggregate-executor-events",
  controllerObservations: "controller-observations",
  controllerProvisioningCommands: "controller-provisioning-commands",
  perJobEvents: "per-job-events",
  perJobEvidence: "per-job-evidence",
  agentProtocol: "agent-protocol",
});
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

function normalizedRequestPath(requestPath) {
  if (typeof requestPath !== "string") return "";
  return requestPath.split("?", 1)[0].toLowerCase();
}

/**
 * Returns the stable executor machine route family for exact route spellings only.
 * The optional mounted form is used by middleware mounted beneath /api, where
 * Express exposes /v1/... in req.path. This deliberately does not accept
 * arbitrary prefixes, empty path segments, duplicate slashes, or descendants.
 */
function certOpsMachineWriteRouteFamily(requestPath, options = {}) {
  const normalizedPath = normalizedRequestPath(requestPath);
  const prefixes = options.allowMountedPath
    ? ["/api/v1/certops", "/v1/certops"]
    : ["/api/v1/certops"];

  for (const prefix of prefixes) {
    if (normalizedPath === `${prefix}/executor/events` ||
        normalizedPath === `${prefix}/executor/events/`) {
      return CERTOPS_MACHINE_WRITE_ROUTE_FAMILIES.aggregateExecutorEvents;
    }
    if (
      normalizedPath === `${prefix}/executor/observations` ||
      normalizedPath === `${prefix}/executor/observations/`
    ) {
      return CERTOPS_MACHINE_WRITE_ROUTE_FAMILIES.controllerObservations;
    }
    if (
      normalizedPath === `${prefix}/executor/provisioning-commands/next` ||
      normalizedPath === `${prefix}/executor/provisioning-commands/next/`
    ) {
      return CERTOPS_MACHINE_WRITE_ROUTE_FAMILIES.controllerProvisioningCommands;
    }
    if (
      new RegExp(
        `^${prefix}/executor/provisioning-commands/[^/]+/authorize-mutation/?$`,
      ).test(normalizedPath)
    ) {
      return CERTOPS_MACHINE_WRITE_ROUTE_FAMILIES.controllerProvisioningCommands;
    }
    if (
      new RegExp(`^${prefix}/jobs/[^/]+/events/?$`).test(normalizedPath)
    ) {
      return CERTOPS_MACHINE_WRITE_ROUTE_FAMILIES.perJobEvents;
    }
    if (
      new RegExp(`^${prefix}/jobs/[^/]+/evidence/?$`).test(normalizedPath)
    ) {
      return CERTOPS_MACHINE_WRITE_ROUTE_FAMILIES.perJobEvidence;
    }
    // Agent-protocol routes: exact paths only (optional single trailing
    // slash, case-insensitive via normalization above), same guarantees as
    // the executor family.
    if (
      normalizedPath === `${prefix}/agent/register` ||
      normalizedPath === `${prefix}/agent/register/` ||
      normalizedPath === `${prefix}/agent/heartbeat` ||
      normalizedPath === `${prefix}/agent/heartbeat/` ||
      normalizedPath === `${prefix}/agent/jobs/claim` ||
      normalizedPath === `${prefix}/agent/jobs/claim/` ||
      normalizedPath === `${prefix}/agent/jobs/results` ||
      normalizedPath === `${prefix}/agent/jobs/results/`
    ) {
      return CERTOPS_MACHINE_WRITE_ROUTE_FAMILIES.agentProtocol;
    }
  }
  return null;
}

function certOpsMachineWriteRouteFamilyFromRequest(req, options = {}) {
  return certOpsMachineWriteRouteFamily(
    req?.path || req?.originalUrl,
    options,
  );
}

function isExactCertOpsMachineWritePost(req, options = {}) {
  return (
    String(req?.method || "").toUpperCase() === "POST" &&
    Boolean(certOpsMachineWriteRouteFamilyFromRequest(req, options))
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

function createCertOpsMachineWriteJsonParser(options = {}) {
  return express.json({
    limit:
      options.limitBytes === undefined
        ? CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES
        : options.limitBytes,
    strict: true,
  });
}

function handleCertOpsMachineWriteBodyParserError(error, _req, res, next) {
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
 * Production-only pre-parser boundary for the exact executor machine write routes.
 * It applies the cheap prefix/IP limiter before any JSON parsing, feature
 * gating, token hashing, database access, or handler work. The router checks
 * the request marker and applies its own limiter only when mounted standalone.
 */
function createCertOpsMachineWritePreParserBoundary(options = {}) {
  const preAuthRateLimitMiddleware =
    options.preAuthRateLimitMiddleware ||
    createCertOpsMachineTokenPreAuthRateLimit(options.rateLimitOptions || {});
  const parser =
    options.parser || createCertOpsMachineWriteJsonParser(options.parserOptions);
  const errorHandler =
    options.errorHandler || handleCertOpsMachineWriteBodyParserError;

  return function certOpsMachineWritePreParserBoundary(req, res, next) {
    if (!isExactCertOpsMachineWritePost(req)) return next();
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
  CERTOPS_AGENT_HEARTBEAT_PATH,
  CERTOPS_AGENT_JOBS_CLAIM_PATH,
  CERTOPS_AGENT_JOBS_RESULTS_PATH,
  CERTOPS_AGENT_REGISTER_PATH,
  CERTOPS_CONTROLLER_OBSERVATIONS_PATH,
  CERTOPS_CONTROLLER_PROVISIONING_AUTHORIZATION_PATH,
  CERTOPS_CONTROLLER_PROVISIONING_COMMANDS_PATH,
  CERTOPS_JOB_EVENTS_PATH,
  CERTOPS_JOB_EVIDENCE_PATH,
  CERTOPS_MACHINE_WRITE_ROUTE_FAMILIES,
  CERTOPS_EXECUTOR_EVENT_BODY_LIMIT_BYTES,
  CERTOPS_EXECUTOR_EVENT_BODY_TOO_LARGE,
  CERTOPS_EXECUTOR_EVENT_INVALID,
  CERTOPS_EXECUTOR_PRE_AUTH_LIMITER_APPLIED,
  createCertOpsMachineWriteJsonParser,
  createCertOpsMachineWritePreParserBoundary,
  certOpsMachineWriteRouteFamily,
  certOpsMachineWriteRouteFamilyFromRequest,
  handleCertOpsMachineWriteBodyParserError,
  hasCertOpsExecutorPreAuthLimit,
  isExactCertOpsMachineWritePost,
};
