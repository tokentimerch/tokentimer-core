"use strict";

const axios = require("axios");
const { tryParseDate, formatDateYmd } = require("./integrationUtils");
const { logger } = require("../utils/logger");

async function gcpRequest({ accessToken, method = "GET", path, body = null }) {
  const baseUrl = `https://secretmanager.googleapis.com/v1`;

  // Properly construct URL - join base URL and path
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  const fullUrl = baseUrl + cleanPath;
  const url = new URL(fullUrl);

  const headers = {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
  };

  try {
    const response = await axios({
      method,
      url: url.toString(),
      headers,
      data: body ? JSON.stringify(body) : undefined,
      timeout: 120000, // 120 second timeout (increased for up to 2000 items)
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      const err = new Error(
        `GCP Secret Manager ${method} ${path} ${error.response.status}`,
      );
      err.status = error.response.status;
      err.body = error.response.data;
      logger.warn("GCP Secret Manager API request failed", {
        method,
        path,
        status: error.response.status,
      });
      throw err;
    }
    logger.error("GCP Secret Manager API request error", {
      method,
      path,
      error: error.message,
      code: error.code,
    });
    throw error;
  }
}

async function listSecrets({ projectId, accessToken, maxItems = 500 }) {
  const secrets = [];
  let nextPageToken = null;
  let pageCount = 0;
  const maxPages = 50;

  do {
    try {
      const path = "/projects/" + encodeURIComponent(projectId) + "/secrets";
      const params = { pageSize: 50 };
      if (nextPageToken) params.pageToken = nextPageToken;

      const fullUrl = "https://secretmanager.googleapis.com/v1" + path;
      const url = new URL(fullUrl);
      Object.entries(params).forEach(([key, value]) => {
        url.searchParams.set(key, String(value));
      });

      const response = await axios({
        method: "GET",
        url: url.toString(),
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
        timeout: 120000, // 120 second timeout (increased for up to 2000 items)
      });

      const data = response.data;
      if (Array.isArray(data.secrets)) {
        secrets.push(...data.secrets);
      }

      nextPageToken = data.nextPageToken || null;
      pageCount++;

      if (secrets.length >= maxItems || pageCount >= maxPages) break;
    } catch (e) {
      // Axios errors have response.status, not status directly
      const status = e.response?.status || e.status;
      if (status === 404) break; // Not found is OK, return empty
      // 403 and other errors should propagate to caller for proper handling
      // Normalize error to include status for upstream handling
      if (e.response && !e.status) {
        e.status = e.response.status;
      }
      throw e;
    }
  } while (nextPageToken && secrets.length < maxItems);

  return secrets.slice(0, maxItems);
}

async function getSecretVersions({ projectId, accessToken, secretId }) {
  try {
    const path = `/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(secretId)}/versions`;
    const fullUrl = "https://secretmanager.googleapis.com/v1" + path;
    const url = new URL(fullUrl);

    const response = await axios({
      method: "GET",
      url: url.toString(),
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
      timeout: 30000,
    });

    const versions = Array.isArray(response.data.versions)
      ? response.data.versions
      : [];
    logger.debug("GCP versions response", {
      secretId,
      versionCount: versions.length,
      firstVersionSample:
        versions.length > 0
          ? {
              name: versions[0].name,
              state: versions[0].state,
              expireTime: versions[0].expireTime,
              hasExpireTime: !!versions[0].expireTime,
            }
          : null,
    });
    return versions;
  } catch (e) {
    // Axios errors have response.status, not status directly
    const status = e.response?.status || e.status;
    if (status === 404) return []; // Not found is OK
    // Let auth errors propagate
    throw e;
  }
}

async function getSecretVersion({
  projectId,
  accessToken,
  secretId,
  versionId = "latest",
}) {
  try {
    const path = `/projects/${encodeURIComponent(projectId)}/secrets/${encodeURIComponent(secretId)}/versions/${encodeURIComponent(versionId)}`;
    const fullUrl = "https://secretmanager.googleapis.com/v1" + path;
    const url = new URL(fullUrl);

    const response = await axios({
      method: "GET",
      url: url.toString(),
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
      timeout: 30000,
    });

    return response.data;
  } catch (e) {
    // Axios errors have response.status, not status directly
    const status = e.response?.status || e.status;
    if (status === 404) return null; // Not found is OK
    // Let auth errors propagate
    throw e;
  }
}

async function scanGCP({
  projectId,
  accessToken,
  include = { secrets: true },
  maxItems = 500,
}) {
  if (!projectId || !accessToken)
    throw new Error("projectId and accessToken are required");

  // Validate inputs
  if (typeof projectId !== "string" || projectId.length > 200) {
    throw new Error("Invalid projectId format");
  }
  if (typeof accessToken !== "string" || accessToken.length > 5000) {
    throw new Error("Invalid accessToken format");
  }
  if (!Number.isInteger(maxItems) || maxItems < 1 || maxItems > 2000) {
    throw new Error("maxItems must be between 1 and 2000");
  }

  logger.info("Starting GCP Secret Manager scan", { projectId, maxItems });

  const items = [];
  const summary = [];

  try {
    // Scan Secrets
    if (include.secrets) {
      try {
        const secrets = await listSecrets({ projectId, accessToken, maxItems });
        logger.info("GCP secrets listed", {
          count: secrets.length,
          firstSecretSample:
            secrets.length > 0
              ? {
                  name: secrets[0].name,
                  hasExpireTime: !!secrets[0].expireTime,
                  expireTime: secrets[0].expireTime,
                  hasExpiration: !!secrets[0].expiration,
                  expiration: secrets[0].expiration,
                }
              : null,
        });

        const BATCH_SIZE = 10;
        for (let i = 0; i < secrets.length; i += BATCH_SIZE) {
          if (items.length >= maxItems) break;
          const batch = secrets.slice(i, i + BATCH_SIZE);

          await Promise.all(
            batch.map(async (secret) => {
              if (items.length >= maxItems) return;

              // Get enabled versions to check expiration
              try {
                const versions = await getSecretVersions({
                  projectId,
                  accessToken,
                  secretId: secret.name.split("/").pop(),
                });

                // Filter for enabled versions and get the latest by version number
                const enabledVersions = versions.filter(
                  (v) => v.state === "ENABLED",
                );

                // Sort by version number (extracted from name like "projects/.../versions/5")
                // GCP version numbers are incrementing integers, higher = newer
                const sortedVersions = enabledVersions.sort((a, b) => {
                  const aNum = parseInt(a.name?.split("/").pop() || "0", 10);
                  const bNum = parseInt(b.name?.split("/").pop() || "0", 10);
                  return bNum - aNum; // Descending order (newest first)
                });

                const latestEnabledVersion =
                  sortedVersions.length > 0 ? sortedVersions[0] : null;

                // Check for expiration on secret level first, then version level
                let expiresAt = null;

                // GCP Secret Manager has expiration directly on secret (secret.expireTime)
                if (secret.expireTime) {
                  expiresAt = tryParseDate(secret.expireTime);
                }
                // Also check nested secret.expiration.expireTime (alternative API format)
                else if (secret.expiration?.expireTime) {
                  expiresAt = tryParseDate(secret.expiration.expireTime);
                }
                // Fallback to version-level expireTime
                else if (latestEnabledVersion?.expireTime) {
                  expiresAt = tryParseDate(latestEnabledVersion.expireTime);
                }

                logger.debug("GCP secret expiration check", {
                  secretName: secret.name.split("/").pop(),
                  hasSecretExpireTime: !!secret.expireTime,
                  secretExpireTime: secret.expireTime,
                  hasNestedExpiration: !!secret.expiration?.expireTime,
                  nestedExpireTime: secret.expiration?.expireTime,
                  versionExpireTime: latestEnabledVersion?.expireTime,
                  parsedExpiration: expiresAt ? expiresAt.toISOString() : null,
                  finalExpirationYmd: expiresAt
                    ? formatDateYmd(expiresAt)
                    : null,
                });

                items.push({
                  source: "gcp-secret-manager",
                  name: secret.name.split("/").pop() || secret.name,
                  category: "key_secret",
                  type: "secret",
                  expiration: expiresAt ? formatDateYmd(expiresAt) : null,
                  location: `gcp:${projectId}/secrets/${secret.name.split("/").pop()}`,
                  created_at: secret.createTime || null,
                  updated_at: secret.updateTime || null,
                  version_count: versions.length || 0,
                  enabled_versions: enabledVersions.length || 0,
                });
              } catch (e) {
                logger.warn("Failed to get GCP secret versions", {
                  secretName: secret.name,
                  error: e.message,
                });
                // Add secret without expiration if we can't access versions
                items.push({
                  source: "gcp-secret-manager",
                  name: secret.name.split("/").pop() || secret.name,
                  category: "key_secret",
                  type: "secret",
                  expiration: null,
                  location: `gcp:${projectId}/secrets/${secret.name.split("/").pop()}`,
                  created_at: secret.createTime || null,
                  updated_at: secret.updateTime || null,
                });
              }
            }),
          );
        }
        summary.push({ type: "secrets", found: secrets.length });
        logger.info("GCP secrets scan completed", {
          secretsFound: secrets.length,
          itemsExtracted: items.length,
        });
      } catch (e) {
        logger.error("GCP secrets scan failed", {
          error: e.message,
          status: e.status || e.response?.status,
          projectId,
        });
        summary.push({
          type: "secrets",
          error: e.message,
          status: e.status || e.response?.status,
        });
      }
    }
  } catch (e) {
    logger.error("GCP scan failed", { error: e.message, projectId });
    summary.push({ type: "scan", error: e.message });
  }

  // If all scan types failed with authentication errors, throw instead of returning partial results
  const allFailed = summary.length > 0 && summary.every((s) => s.error);

  // Check if we got authentication/permission errors
  // Note: When listSecrets throws, the error gets caught and the message is stored in summary
  const hasAuthError = summary.some((s) => {
    if (!s.error) return false;
    // Check status field directly
    if (s.status === 401 || s.status === 403) return true;
    // Also check error message for auth patterns
    const errorStr = String(s.error);
    return (
      errorStr.includes("401") ||
      errorStr.includes("403") ||
      errorStr.includes("Unauthorized") ||
      errorStr.includes("Forbidden") ||
      errorStr.includes("PERMISSION_DENIED") ||
      errorStr.includes("UNAUTHENTICATED")
    );
  });

  if (allFailed && hasAuthError && items.length === 0) {
    const err = new Error("Authentication failed");
    err.status =
      summary.find((s) => s.status === 401 || s.status === 403)?.status || 401;
    throw err;
  }

  logger.info("GCP scan completed", {
    itemsFound: items.length,
    projectId,
    items: items.map((i) => ({
      name: i.name,
      type: i.type,
      expiration: i.expiration,
    })),
  });
  return { items, summary };
}

module.exports = {
  scanGCP,
};

// Test-only exports for unit coverage of helpers
if (process.env.NODE_ENV === "test") {
  module.exports._test = {
    gcpRequest,
    listSecrets,
    getSecretVersion,
    getSecretVersions,
  };
}
