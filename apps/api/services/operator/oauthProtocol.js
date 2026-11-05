"use strict";

const crypto = require("node:crypto");
const {
  defineCredentialFamily,
  sha256Hex,
  safeCompareSha256Hex,
} = require("../credentials/primitives");
const { OAUTH_SCOPE, loopback } = require("./remoteConfig");

const ACCESS = defineCredentialFamily({ prefix: "ttopm_" });
const REFRESH = defineCredentialFamily({ prefix: "ttopr_" });
const CODE = defineCredentialFamily({ prefix: "ttopq_" });
const READ_SCOPES = Object.freeze([
  "mcp:identity:read",
  "mcp:tokens:read",
  "mcp:certs:read",
  "mcp:jobs:read",
]);
const UUID =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;

function oauthError(code, status = 400) {
  const error = new Error("The MCP authorization request was refused");
  error.oauthCode = code;
  error.status = status;
  return error;
}

function string(value, max = 2048) {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > max ||
    /[\u0000-\u0020\u007f]/.test(value)
  )
    throw oauthError("invalid_request");
  return value;
}

function validRedirect(value) {
  string(value);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw oauthError("invalid_redirect_uri");
  }
  if (
    url.username ||
    url.password ||
    url.hash ||
    !(
      url.protocol === "https:" ||
      (url.protocol === "http:" && loopback(url.hostname))
    )
  )
    throw oauthError("invalid_redirect_uri");
  if (
    ["code", "state", "iss", "error", "error_description", "error_uri"].some(
      (key) => url.searchParams.has(key),
    )
  )
    throw oauthError("invalid_redirect_uri");
  return value;
}

function redirectMatches(registered, requested) {
  validRedirect(requested);
  return registered.some((entry) => {
    if (entry === requested) return true;
    const a = new URL(entry),
      b = new URL(requested);
    // Native loopback callbacks may choose a fresh port. Nothing else varies.
    if (
      a.protocol !== "http:" ||
      b.protocol !== "http:" ||
      !loopback(a.hostname) ||
      a.hostname !== b.hostname
    )
      return false;
    a.port = "";
    b.port = "";
    return a.href === b.href;
  });
}

function clientMetadata(input, clientId = null) {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw oauthError("invalid_client_metadata");
  if (clientId && input.client_id !== clientId)
    throw oauthError("invalid_client_metadata");
  if (
    !Array.isArray(input.redirect_uris) ||
    !input.redirect_uris.length ||
    input.redirect_uris.length > 8
  )
    throw oauthError("invalid_client_metadata");
  const redirects = [...new Set(input.redirect_uris.map(validRedirect))];
  const name =
    input.client_name === undefined ? "MCP assistant" : input.client_name;
  if (
    typeof name !== "string" ||
    !name.trim() ||
    name.length > 128 ||
    /[\u0000-\u001f\u007f]/.test(name) ||
    /-----BEGIN|ttop[cmrgq]_/.test(name)
  )
    throw oauthError("invalid_client_metadata");
  const grants = input.grant_types || ["authorization_code"];
  if (
    !Array.isArray(grants) ||
    !grants.includes("authorization_code") ||
    grants.some((x) => !["authorization_code", "refresh_token"].includes(x))
  )
    throw oauthError("invalid_client_metadata");
  if (
    input.response_types &&
    (!Array.isArray(input.response_types) ||
      input.response_types.length !== 1 ||
      input.response_types[0] !== "code")
  )
    throw oauthError("invalid_client_metadata");
  if (
    input.token_endpoint_auth_method &&
    input.token_endpoint_auth_method !== "none"
  )
    throw oauthError("invalid_client_metadata");
  return {
    client_name: name.trim(),
    redirect_uris: redirects,
    grant_types: [...new Set(grants)],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  };
}

function requestedScope(value) {
  if (value !== undefined && value !== OAUTH_SCOPE)
    throw oauthError("invalid_scope");
  return OAUTH_SCOPE;
}

function requireResource(value, config) {
  let url;
  try {
    url = new URL(string(value));
  } catch {
    throw oauthError("invalid_target");
  }
  if (url.href !== config.resource) throw oauthError("invalid_target");
}

function validateAuthorize(input, client, config) {
  if (!input || input.response_type !== "code")
    throw oauthError("unsupported_response_type");
  if (!redirectMatches(client.redirect_uris, input.redirect_uri))
    throw oauthError("invalid_redirect_uri");
  if (
    input.code_challenge_method !== "S256" ||
    typeof input.code_challenge !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(input.code_challenge)
  )
    throw oauthError("invalid_request");
  requireResource(input.resource, config);
  requestedScope(input.scope);
  if (
    input.state !== undefined &&
    (typeof input.state !== "string" ||
      input.state.length > 2048 ||
      /[\u0000-\u001f\u007f]/.test(input.state))
  )
    throw oauthError("invalid_request");
  return {
    redirectUri: input.redirect_uri,
    challenge: input.code_challenge,
    state: input.state || null,
  };
}

function validVerifier(value, challenge) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._~-]{43,128}$/.test(value))
    return false;
  return safeCompareSha256Hex(
    sha256Hex(crypto.createHash("sha256").update(value).digest("base64url")),
    sha256Hex(challenge),
  );
}

function callbackUrl(record, config, values) {
  const url = new URL(record.redirect_uri);
  if (record.state) url.searchParams.set("state", record.state);
  url.searchParams.set("iss", config.issuer);
  for (const [key, value] of Object.entries(values))
    url.searchParams.set(key, value);
  return url.href;
}

module.exports = {
  ACCESS,
  REFRESH,
  CODE,
  READ_SCOPES,
  UUID,
  oauthError,
  string,
  validRedirect,
  redirectMatches,
  clientMetadata,
  requestedScope,
  requireResource,
  validateAuthorize,
  validVerifier,
  callbackUrl,
};
