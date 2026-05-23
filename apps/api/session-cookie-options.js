"use strict";

function parseBooleanEnv(value) {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  return null;
}

function normalizeOrigin(value) {
  if (!value || typeof value !== "string") return null;
  try {
    return new URL(value.trim()).origin;
  } catch {
    return null;
  }
}

function parseOrigin(value) {
  if (!value) return null;
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

/** http://localhost / 127.0.0.1 / [::1] (any port) */
function isLocalHttpOrigin(origin) {
  const parsed = parseOrigin(origin);
  if (!parsed || parsed.protocol !== "http:") return false;
  const host = parsed.hostname.toLowerCase();
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]";
}

function isHttpsOrigin(origin) {
  const parsed = parseOrigin(origin);
  return Boolean(parsed && parsed.protocol === "https:");
}

/**
 * SameSite=None is only valid with Secure and is blocked as third-party on many
 * browsers. Use it only for HTTPS split-host (real subdomains). Local HTTP
 * split ports (Compose, Helm port-forward) stay Lax (same-site across ports).
 */
function shouldUseCrossOriginCookies(apiOrigin, appOrigin) {
  if (!apiOrigin || !appOrigin || apiOrigin === appOrigin) return false;
  if (isLocalHttpOrigin(apiOrigin) && isLocalHttpOrigin(appOrigin)) return false;
  return isHttpsOrigin(apiOrigin) && isHttpsOrigin(appOrigin);
}

function resolveProductionSecure(env) {
  const isProduction =
    (env.NODE_ENV || "").trim().toLowerCase() === "production";
  if (!isProduction) return false;

  const override =
    parseBooleanEnv(env.SESSION_COOKIE_SECURE_LOCALHOST_OVERRIDE) === true;
  if (!override) return true;

  const { apiOrigin, appOrigin } = resolveEffectiveOrigins(env);
  if (isLocalHttpOrigin(apiOrigin) && isLocalHttpOrigin(appOrigin)) {
    return false;
  }

  return true;
}

/**
 * Session (and CSRF) cookie options for split APP_URL / API_URL deployments.
 */
function resolveEffectiveOrigins(env = process.env) {
  const appOrigin = normalizeOrigin(env.APP_URL);
  const apiOrigin =
    normalizeOrigin(env.API_URL) || normalizeOrigin(env.APP_URL);
  return { apiOrigin, appOrigin };
}

function resolveSessionCookieOptions(env = process.env) {
  const productionSecure = resolveProductionSecure(env);

  const { apiOrigin, appOrigin } = resolveEffectiveOrigins(env);
  const useCrossOriginCookies = shouldUseCrossOriginCookies(
    apiOrigin,
    appOrigin,
  );

  const cookie = {
    httpOnly: true,
    sameSite: "lax",
    secure: productionSecure,
    maxAge: 2 * 60 * 60 * 1000,
  };

  const explicitDomain = String(env.SESSION_COOKIE_DOMAIN || "").trim();
  if (explicitDomain) {
    cookie.domain = explicitDomain.startsWith(".")
      ? explicitDomain
      : `.${explicitDomain}`;
  }

  if (useCrossOriginCookies) {
    cookie.sameSite = "none";
    cookie.secure = true;
  }

  return cookie;
}

/** Options that must match express-session when calling res.clearCookie. */
function resolveClearSessionCookieOptions(env = process.env) {
  const cookie = resolveSessionCookieOptions(env);
  const clearOptions = {
    path: "/",
    httpOnly: true,
    sameSite: cookie.sameSite,
    secure: cookie.secure,
  };
  if (cookie.domain) {
    clearOptions.domain = cookie.domain;
  }
  return clearOptions;
}

/**
 * __Host- prefix cookies cannot include Domain; only use when production Secure
 * and session cookie has no Domain attribute.
 */
function resolveCsrfCookieName(env, sessionCookie) {
  const isProduction =
    (env.NODE_ENV || "").trim().toLowerCase() === "production";
  const productionSecure = resolveProductionSecure(env);
  if (isProduction && productionSecure && !sessionCookie.domain) {
    return "__Host-psifi.x-csrf-token";
  }
  return "x-csrf-token";
}

/** Dev / port-forward origins when APP_URL or API_URL env are missing or mismatched. */
const LOCAL_DEV_CORS_ORIGINS = [
  "http://localhost:3000",
  "http://localhost:5173",
  "http://localhost:4000",
  "http://localhost:8080",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:4000",
  "http://127.0.0.1:8080",
];

function buildCorsOrigins(env = process.env) {
  const { apiOrigin, appOrigin } = resolveEffectiveOrigins(env);
  const origins = new Set();

  origins.add(appOrigin || "http://localhost:5173");
  if (apiOrigin) {
    origins.add(apiOrigin);
  }

  const isProd = (env.NODE_ENV || "").trim().toLowerCase() === "production";
  if (!isProd || parseBooleanEnv(env.ALLOW_LOCAL_DEV_CORS) === true) {
    for (const origin of LOCAL_DEV_CORS_ORIGINS) {
      origins.add(origin);
    }
  }

  return [...origins];
}

module.exports = {
  resolveSessionCookieOptions,
  resolveClearSessionCookieOptions,
  resolveCsrfCookieName,
  buildCorsOrigins,
  resolveEffectiveOrigins,
  resolveProductionSecure,
  normalizeOrigin,
  isLocalHttpOrigin,
  isHttpsOrigin,
  shouldUseCrossOriginCookies,
  LOCAL_DEV_CORS_ORIGINS,
};
