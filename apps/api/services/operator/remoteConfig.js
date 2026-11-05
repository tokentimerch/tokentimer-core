"use strict";

const MCP_PATH = "/api/v1/operator/mcp";
const OAUTH_PATH = "/api/v1/mcp/oauth";
const OAUTH_SCOPE = "mcp:connect";
const loopback = (host) => ["localhost", "127.0.0.1", "[::1]"].includes(host);
const enabled = (value) =>
  String(value || "")
    .trim()
    .toLowerCase() === "true";

function parsePublicUrl(value, env) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Remote MCP needs a valid public HTTPS URL");
  }
  const local =
    loopback(url.hostname) &&
    (env.NODE_ENV !== "production" ||
      enabled(env.SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE));
  if (
    (url.protocol !== "https:" && !(url.protocol === "http:" && local)) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    /[\u0000-\u0020\u007f]/.test(value)
  ) {
    throw new Error(
      "Remote MCP needs HTTPS; HTTP is allowed only for an explicitly local test",
    );
  }
  return url;
}

function remoteConfig(env = process.env) {
  if (
    !enabled(env.MCP_OPERATOR_INTERFACE_ENABLED) ||
    !enabled(env.MCP_OPERATOR_REMOTE_ENABLED)
  )
    return null;
  const resource = parsePublicUrl(String(env.MCP_PUBLIC_URL || ""), env);
  if (!resource.pathname.endsWith(MCP_PATH) || /%|\/\//.test(resource.pathname))
    throw new Error(`MCP_PUBLIC_URL must end in ${MCP_PATH}`);
  const app = parsePublicUrl(
    String(env.APP_URL || env.FRONTEND_URL || ""),
    env,
  );
  const prefix = resource.pathname.slice(0, -MCP_PATH.length);
  const issuer = resource.origin + prefix;
  const origins = new Set([resource.origin, app.origin]);
  for (const raw of String(env.MCP_ALLOWED_ORIGINS || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)) {
    const url = parsePublicUrl(raw, env);
    if (url.pathname !== "/")
      throw new Error("MCP_ALLOWED_ORIGINS accepts origins only");
    origins.add(url.origin);
  }
  return Object.freeze({
    resource: resource.href,
    issuer,
    host: resource.host.toLowerCase(),
    appUrl: app.href.replace(/\/$/, ""),
    origins,
    oauthBase: issuer + OAUTH_PATH,
    metadataPath: "/.well-known/oauth-protected-resource" + resource.pathname,
    authorizationMetadataPath:
      "/.well-known/oauth-authorization-server" + prefix,
    secureCookie: resource.protocol === "https:",
  });
}

function remoteSetup(env = process.env) {
  const config = remoteConfig(env);
  return { enabled: Boolean(config), serverUrl: config?.resource || null };
}

module.exports = {
  MCP_PATH,
  OAUTH_PATH,
  OAUTH_SCOPE,
  enabled,
  loopback,
  remoteConfig,
  remoteSetup,
};
