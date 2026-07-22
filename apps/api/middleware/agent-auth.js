"use strict";

const {
  bearerTokenFromRequest,
  _test: apiTokenAuthTest,
} = require("./api-token-auth");
const {
  validateAgentCredential,
  validateBootstrapToken,
} = require("../services/certops/agentCredentials");

const CERTOPS_AGENT_BOOTSTRAP_UNAUTHORIZED =
  "CERTOPS_AGENT_BOOTSTRAP_UNAUTHORIZED";
const CERTOPS_AGENT_UNAUTHORIZED = "CERTOPS_AGENT_UNAUTHORIZED";
const CERTOPS_AGENT_SESSION_IDENTITY_FORBIDDEN =
  "CERTOPS_AGENT_SESSION_IDENTITY_FORBIDDEN";

const hasSessionIdentity = apiTokenAuthTest.hasSessionIdentity;

// Generic 401 bodies. Deliberately identical for unknown, bad-hash,
// expired, used, and revoked bootstrap tokens so callers cannot probe
// whether a token exists.
const BOOTSTRAP_UNAUTHORIZED_RESPONSE = Object.freeze({
  error: "CertOps agent bootstrap authentication required",
  code: CERTOPS_AGENT_BOOTSTRAP_UNAUTHORIZED,
});

const AGENT_UNAUTHORIZED_RESPONSE = Object.freeze({
  error: "CertOps agent authentication required",
  code: CERTOPS_AGENT_UNAUTHORIZED,
});

const SESSION_IDENTITY_RESPONSE = Object.freeze({
  error: "Session identity is not allowed for CertOps agent authentication",
  code: CERTOPS_AGENT_SESSION_IDENTITY_FORBIDDEN,
});

// Composition (mirrors apps/api/routes/certops-executor.js): the router
// wires pre-auth rate limit -> auth (this module) -> post-auth rate limit ->
// private-key-material rejection (422). These middlewares only authenticate;
// they never consume the bootstrap token. Consumption happens atomically in
// the register handler transaction via consumeBootstrapToken so a lost race
// surfaces as an auth failure there, not here.

function createAgentBootstrapTokenAuth(options = {}) {
  const validate = options.validateBootstrapToken || validateBootstrapToken;

  return async function agentBootstrapTokenAuth(req, res, next) {
    if (hasSessionIdentity(req)) {
      return res.status(401).json(SESSION_IDENTITY_RESPONSE);
    }

    const bearer = bearerTokenFromRequest(req);
    if (!bearer.ok) {
      return res.status(401).json(BOOTSTRAP_UNAUTHORIZED_RESPONSE);
    }

    let validation;
    try {
      validation = await validate({
        client: options.client,
        rawToken: bearer.rawToken,
      });
    } catch (error) {
      return next(error);
    }

    if (!validation?.valid || !validation.bootstrapToken) {
      // Same body regardless of validation.code (malformed, expired, used,
      // revoked, unknown): do not leak token state.
      return res.status(401).json(BOOTSTRAP_UNAUTHORIZED_RESPONSE);
    }

    req.agentBootstrapToken = validation.bootstrapToken;
    return next();
  };
}

function createAgentCredentialAuth(options = {}) {
  const validate = options.validateAgentCredential || validateAgentCredential;

  return async function agentCredentialAuth(req, res, next) {
    if (hasSessionIdentity(req)) {
      return res.status(401).json(SESSION_IDENTITY_RESPONSE);
    }

    const bearer = bearerTokenFromRequest(req);
    if (!bearer.ok) {
      return res.status(401).json(AGENT_UNAUTHORIZED_RESPONSE);
    }

    let validation;
    try {
      validation = await validate({
        client: options.client,
        rawCredential: bearer.rawToken,
      });
    } catch (error) {
      return next(error);
    }

    if (!validation?.valid || !validation.agent) {
      return res.status(401).json(AGENT_UNAUTHORIZED_RESPONSE);
    }

    // Retired agents authenticate successfully (frozen-retired rule); the
    // route inspects req.certopsAgent.status and answers 410 on heartbeat.
    req.certopsAgent = validation.agent;
    return next();
  };
}

module.exports = {
  CERTOPS_AGENT_BOOTSTRAP_UNAUTHORIZED,
  CERTOPS_AGENT_SESSION_IDENTITY_FORBIDDEN,
  CERTOPS_AGENT_UNAUTHORIZED,
  createAgentBootstrapTokenAuth,
  createAgentCredentialAuth,
  _test: {
    AGENT_UNAUTHORIZED_RESPONSE,
    BOOTSTRAP_UNAUTHORIZED_RESPONSE,
    SESSION_IDENTITY_RESPONSE,
    hasSessionIdentity,
  },
};
