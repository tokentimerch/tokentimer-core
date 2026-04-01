"use strict";

const axios = require("axios");
const { tryParseDate, formatDateYmd } = require("./integrationUtils");
const { logger } = require("../utils/logger");

/**
 * Azure AD (Microsoft Graph API) integration for discovering app registrations
 * and service principals with expiring client secrets and certificates.
 *
 * API: Microsoft Graph API v1.0
 * Authentication: Bearer token with Application.Read.All permission
 * Base URL: https://graph.microsoft.com/v1.0
 */

async function graphRequest({ token, method = "GET", path, params = {} }) {
  const baseUrl = "https://graph.microsoft.com/v1.0";

  // Properly construct URL - join base URL and path
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  const fullUrl = baseUrl + cleanPath;
  const url = new URL(fullUrl);

  // Add query parameters
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      url.searchParams.set(key, String(value));
    }
  });

  const headers = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    Accept: "application/json",
  };

  try {
    const response = await axios({
      method,
      url: url.toString(),
      headers,
      timeout: 120000, // 120 second timeout (increased for up to 2000 items)
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      const errorMessage =
        error.response.data?.error?.message ||
        error.response.data?.error_description ||
        JSON.stringify(error.response.data);
      const errorCode =
        error.response.data?.error?.code || error.response.data?.error;

      const err = new Error(
        `Microsoft Graph ${method} ${path} ${error.response.status}: ${errorMessage}`,
      );
      err.status = error.response.status;
      err.body = error.response.data;
      err.graphError = errorCode;

      logger.warn("Microsoft Graph API request failed", {
        method,
        path,
        status: error.response.status,
        errorCode,
        errorMessage,
        url: url.toString(),
      });
      throw err;
    }
    logger.error("Microsoft Graph API request error", {
      method,
      path,
      error: error.message,
      code: error.code,
    });
    throw error;
  }
}

async function listApplications({ token, maxItems = 500 }) {
  const apps = [];
  let nextLink = null;
  let pageCount = 0;
  const maxPages = 50;

  do {
    try {
      let path = "/applications";
      let data;

      if (nextLink) {
        // Microsoft Graph returns full URLs in @odata.nextLink
        const nextUrl = new URL(nextLink);
        path = nextUrl.pathname + nextUrl.search;
        data = await graphRequest({ token, method: "GET", path });
      } else {
        // First page
        data = await graphRequest({
          token,
          method: "GET",
          path,
          params: {
            $top: 100,
          },
        });
      }

      if (Array.isArray(data.value)) {
        apps.push(...data.value);
      }

      nextLink = data["@odata.nextLink"] || null;
      pageCount++;

      if (apps.length >= maxItems || pageCount >= maxPages) break;
    } catch (e) {
      if (e.status === 404 || e.status === 403) break;
      throw e;
    }
  } while (nextLink && apps.length < maxItems);

  return apps.slice(0, maxItems);
}

async function listServicePrincipals({ token, maxItems = 500 }) {
  const sps = [];
  let nextLink = null;
  let pageCount = 0;
  const maxPages = 50;

  do {
    try {
      let path = "/servicePrincipals";
      let data;

      if (nextLink) {
        const nextUrl = new URL(nextLink);
        path = nextUrl.pathname + nextUrl.search;
        data = await graphRequest({ token, method: "GET", path });
      } else {
        data = await graphRequest({
          token,
          method: "GET",
          path,
          params: {
            $top: 100,
          },
        });
      }

      if (Array.isArray(data.value)) {
        sps.push(...data.value);
      }

      nextLink = data["@odata.nextLink"] || null;
      pageCount++;

      if (sps.length >= maxItems || pageCount >= maxPages) break;
    } catch (e) {
      if (e.status === 404 || e.status === 403) break;
      throw e;
    }
  } while (nextLink && sps.length < maxItems);

  return sps.slice(0, maxItems);
}

async function scanAzureAD({
  token,
  include = { applications: true, servicePrincipals: true },
  maxItems = 500,
}) {
  if (!token) throw new Error("token is required");

  // Clean and validate token
  const cleanToken = String(token)
    .trim()
    .replace(/[\r\n\t]/g, "");

  if (cleanToken.length === 0 || cleanToken.length > 3000) {
    throw new Error("Invalid token format");
  }
  if (!Number.isInteger(maxItems) || maxItems < 1 || maxItems > 2000) {
    throw new Error("maxItems must be between 1 and 2000");
  }

  // Check if token looks like a valid JWT (has 3 parts separated by dots)
  const tokenParts = cleanToken.split(".");
  if (tokenParts.length !== 3) {
    logger.warn("Azure AD token format check", {
      tokenParts: tokenParts.length,
      message: "Token does not appear to be a valid JWT (expected 3 parts)",
    });
  }

  // Decode JWT to check claims (without verifying signature)
  let tokenClaims = null;
  try {
    const payload = Buffer.from(tokenParts[1], "base64").toString("utf8");
    tokenClaims = JSON.parse(payload);
    logger.info("Azure AD token claims", {
      aud: tokenClaims.aud,
      iss: tokenClaims.iss,
      exp: tokenClaims.exp
        ? new Date(tokenClaims.exp * 1000).toISOString()
        : null,
      iat: tokenClaims.iat
        ? new Date(tokenClaims.iat * 1000).toISOString()
        : null,
      nbf: tokenClaims.nbf
        ? new Date(tokenClaims.nbf * 1000).toISOString()
        : null,
      now: new Date().toISOString(),
      isExpired: tokenClaims.exp ? tokenClaims.exp * 1000 < Date.now() : null,
    });
  } catch (e) {
    logger.warn("Failed to decode token claims", { error: e.message });
  }

  logger.info("Starting Azure AD scan", {
    maxItems,
    includeApps: include.applications,
    includeSPs: include.servicePrincipals,
    tokenLength: cleanToken.length,
    tokenParts: tokenParts.length,
    tokenPrefix: cleanToken.substring(0, 30) + "...",
    tokenAudience: tokenClaims?.aud,
  });

  const items = [];
  const summary = [];

  try {
    // Scan Applications
    if (include.applications) {
      try {
        const apps = await listApplications({ token: cleanToken, maxItems });
        let secretsCount = 0;
        let certsCount = 0;

        for (const app of apps) {
          if (items.length >= maxItems) break;

          logger.debug("Azure AD app credentials", {
            appId: app.appId,
            displayName: app.displayName,
            passwordCredsCount: app.passwordCredentials?.length || 0,
            keyCredsCount: app.keyCredentials?.length || 0,
          });

          // Process passwordCredentials (client secrets)
          for (const cred of app.passwordCredentials || []) {
            if (items.length >= maxItems) break;

            const expiresAt = cred.endDateTime
              ? tryParseDate(cred.endDateTime)
              : null;
            const startAt = cred.startDateTime
              ? tryParseDate(cred.startDateTime)
              : null;

            items.push({
              source: "azure-ad-client-secret",
              name: `${app.displayName || app.appId}/${cred.displayName || cred.hint || "Secret"}`,
              category: "key_secret",
              type: "api_key",
              expiration: expiresAt ? formatDateYmd(expiresAt) : null,
              location: `azure-ad:applications/${app.appId}/secrets/${cred.keyId}`,
              description: `App ID: ${app.appId}\nKey ID: ${cred.keyId}\nCreated: ${startAt ? startAt.toISOString().split("T")[0] : "N/A"}`,
              app_id: app.appId,
              app_name: app.displayName || app.appId,
              key_id: cred.keyId,
              created_at: startAt ? startAt.toISOString() : null,
            });
            secretsCount++;
          }

          // Process keyCredentials (certificates)
          for (const cert of app.keyCredentials || []) {
            if (items.length >= maxItems) break;

            const expiresAt = cert.endDateTime
              ? tryParseDate(cert.endDateTime)
              : null;
            const startAt = cert.startDateTime
              ? tryParseDate(cert.startDateTime)
              : null;

            items.push({
              source: "azure-ad-certificate",
              name: `${app.displayName || app.appId}/${cert.displayName || "Certificate"}`,
              category: "cert",
              type: "ssl_cert",
              expiration: expiresAt ? formatDateYmd(expiresAt) : null,
              location: `azure-ad:applications/${app.appId}/certificates/${cert.keyId}`,
              description: `App ID: ${app.appId}\nKey ID: ${cert.keyId}\nType: ${cert.type || "N/A"}\nUsage: ${cert.usage || "N/A"}\nCreated: ${startAt ? startAt.toISOString().split("T")[0] : "N/A"}`,
              app_id: app.appId,
              app_name: app.displayName || app.appId,
              key_id: cert.keyId,
              key_type: cert.type || null,
              usage: cert.usage || null,
              created_at: startAt ? startAt.toISOString() : null,
            });
            certsCount++;
          }
        }

        summary.push({
          type: "applications",
          found: apps.length,
          secrets: secretsCount,
          certificates: certsCount,
        });
        logger.info("Azure AD applications scan completed", {
          apps: apps.length,
          secrets: secretsCount,
          certs: certsCount,
          itemsExtracted: secretsCount + certsCount,
        });
      } catch (e) {
        logger.error("Azure AD applications scan failed", { error: e.message });
        summary.push({ type: "applications", error: e.message });
      }
    }

    // Scan Service Principals
    if (include.servicePrincipals) {
      try {
        const sps = await listServicePrincipals({
          token: cleanToken,
          maxItems,
        });
        let secretsCount = 0;
        let certsCount = 0;

        for (const sp of sps) {
          if (items.length >= maxItems) break;

          // Process passwordCredentials (client secrets)
          for (const cred of sp.passwordCredentials || []) {
            if (items.length >= maxItems) break;

            const expiresAt = cred.endDateTime
              ? tryParseDate(cred.endDateTime)
              : null;
            const startAt = cred.startDateTime
              ? tryParseDate(cred.startDateTime)
              : null;

            items.push({
              source: "azure-ad-sp-secret",
              name: `${sp.displayName || sp.appId}/SP/${cred.displayName || cred.hint || "Secret"}`,
              category: "key_secret",
              type: "api_key",
              expiration: expiresAt ? formatDateYmd(expiresAt) : null,
              location: `azure-ad:servicePrincipals/${sp.appId}/secrets/${cred.keyId}`,
              description: `Service Principal\nApp ID: ${sp.appId}\nKey ID: ${cred.keyId}\nCreated: ${startAt ? startAt.toISOString().split("T")[0] : "N/A"}`,
              app_id: sp.appId,
              sp_name: sp.displayName || sp.appId,
              key_id: cred.keyId,
              created_at: startAt ? startAt.toISOString() : null,
            });
            secretsCount++;
          }

          // Process keyCredentials (certificates)
          for (const cert of sp.keyCredentials || []) {
            if (items.length >= maxItems) break;

            const expiresAt = cert.endDateTime
              ? tryParseDate(cert.endDateTime)
              : null;
            const startAt = cert.startDateTime
              ? tryParseDate(cert.startDateTime)
              : null;

            items.push({
              source: "azure-ad-sp-certificate",
              name: `${sp.displayName || sp.appId}/SP/${cert.displayName || "Certificate"}`,
              category: "cert",
              type: "ssl_cert",
              expiration: expiresAt ? formatDateYmd(expiresAt) : null,
              location: `azure-ad:servicePrincipals/${sp.appId}/certificates/${cert.keyId}`,
              description: `Service Principal\nApp ID: ${sp.appId}\nKey ID: ${cert.keyId}\nType: ${cert.type || "N/A"}\nUsage: ${cert.usage || "N/A"}\nCreated: ${startAt ? startAt.toISOString().split("T")[0] : "N/A"}`,
              app_id: sp.appId,
              sp_name: sp.displayName || sp.appId,
              key_id: cert.keyId,
              key_type: cert.type || null,
              usage: cert.usage || null,
              created_at: startAt ? startAt.toISOString() : null,
            });
            certsCount++;
          }
        }

        summary.push({
          type: "service_principals",
          found: sps.length,
          secrets: secretsCount,
          certificates: certsCount,
        });
        logger.info("Azure AD service principals scan completed", {
          sps: sps.length,
          secrets: secretsCount,
          certs: certsCount,
        });
      } catch (e) {
        logger.error("Azure AD service principals scan failed", {
          error: e.message,
        });
        summary.push({ type: "service_principals", error: e.message });
      }
    }
  } catch (e) {
    logger.error("Azure AD scan failed", { error: e.message });
    summary.push({ type: "scan", error: e.message });
  }

  // If all scan types failed with authentication errors, throw instead of returning partial results
  const allFailed = summary.every((s) => s.error);
  const hasAuthError = summary.some(
    (s) =>
      s.error &&
      (s.error.includes("401") ||
        s.error.includes("403") ||
        s.error.includes("Unauthorized") ||
        s.error.includes("Forbidden")),
  );

  if (allFailed && hasAuthError && items.length === 0) {
    const err = new Error("Authentication failed");
    err.status = 401;
    throw err;
  }

  logger.info("Azure AD scan completed", {
    itemsFound: items.length,
    summaryCount: summary.length,
    items: items.map((i) => ({ name: i.name, type: i.type, source: i.source })),
  });
  return { items, summary };
}

module.exports = {
  scanAzureAD,
};

// Test-only exports for unit coverage of helpers
if (process.env.NODE_ENV === "test") {
  module.exports._test = {
    graphRequest,
    listApplications,
    listServicePrincipals,
  };
}
