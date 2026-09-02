"use strict";

const axios = require("axios");
const {
  tryParseDate,
  formatDateYmd,
  CREDENTIALED_AXIOS_REDIRECTS,
} = require("./integrationUtils");
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
      ...CREDENTIALED_AXIOS_REDIRECTS,
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
  let truncated = false;

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
        ...CREDENTIALED_AXIOS_REDIRECTS,
      });

      const data = response.data;
      if (Array.isArray(data.secrets)) {
        secrets.push(...data.secrets);
      }

      nextPageToken = data.nextPageToken || null;
      pageCount++;

      if (secrets.length >= maxItems || pageCount >= maxPages) {
        truncated = Boolean(nextPageToken) || secrets.length > maxItems;
        break;
      }
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

  return { items: secrets.slice(0, maxItems), truncated };
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
      ...CREDENTIALED_AXIOS_REDIRECTS,
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
      ...CREDENTIALED_AXIOS_REDIRECTS,
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

// Certificate Manager certificates are scoped to a location ("global" or a
// region, for regional external HTTPS load balancers). Only "global" is
// scanned today -- covers the common case without a per-region sweep like
// AWS's, which regional Certificate Manager users would need to request.
async function listCertificateManagerCertificates({
  projectId,
  accessToken,
  location = "global",
  maxItems = 500,
}) {
  const certs = [];
  let nextPageToken = null;
  let pageCount = 0;
  const maxPages = 50;
  let truncated = false;

  do {
    try {
      const path = `/projects/${encodeURIComponent(projectId)}/locations/${encodeURIComponent(location)}/certificates`;
      const params = { pageSize: 50 };
      if (nextPageToken) params.pageToken = nextPageToken;

      const fullUrl = "https://certificatemanager.googleapis.com/v1" + path;
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
        timeout: 120000,
        ...CREDENTIALED_AXIOS_REDIRECTS,
      });

      const data = response.data;
      if (Array.isArray(data.certificates)) {
        certs.push(...data.certificates);
      }

      nextPageToken = data.nextPageToken || null;
      pageCount++;

      if (certs.length >= maxItems || pageCount >= maxPages) {
        truncated = Boolean(nextPageToken) || certs.length > maxItems;
        break;
      }
    } catch (e) {
      // A 404 here is not a genuine "no certificates in this location"
      // signal -- a real empty location returns 200 with an empty array.
      // 404 typically means Certificate Manager isn't enabled for the
      // project or the location doesn't exist, so it must propagate like
      // any other error and leave this sub-scope reported errored, not
      // complete-and-empty (which would make cleanup delete every
      // previously-imported certificate of this kind).
      if (e.response && !e.status) {
        e.status = e.response.status;
      }
      throw e;
    }
  } while (nextPageToken && certs.length < maxItems);

  return { items: certs.slice(0, maxItems), truncated };
}

// Compute Engine sslCertificates support both a global scope (classic load
// balancers) and per-region scopes (regional external HTTPS/SSL proxy load
// balancers). aggregatedList covers every scope in one call; the
// global-only `list` method used previously silently missed every regional
// certificate.
async function listComputeSslCertificates({
  projectId,
  accessToken,
  maxItems = 500,
}) {
  const certs = [];
  let nextPageToken = null;
  let pageCount = 0;
  const maxPages = 50;
  let truncated = false;

  do {
    try {
      const path = `/projects/${encodeURIComponent(projectId)}/aggregated/sslCertificates`;
      const params = { maxResults: 50 };
      if (nextPageToken) params.pageToken = nextPageToken;

      const fullUrl = "https://compute.googleapis.com/compute/v1" + path;
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
        timeout: 120000,
        ...CREDENTIALED_AXIOS_REDIRECTS,
      });

      const data = response.data;
      // aggregatedList buckets results under a per-scope key ("global" or
      // "regions/<region>"); flatten every scope's sslCertificates into one
      // list, tagging each with the scope it came from.
      if (data.items && typeof data.items === "object") {
        for (const [scopeName, scoped] of Object.entries(data.items)) {
          if (Array.isArray(scoped?.sslCertificates)) {
            for (const cert of scoped.sslCertificates) {
              certs.push({ ...cert, scope: scopeName });
            }
          }
        }
      }

      nextPageToken = data.nextPageToken || null;
      pageCount++;

      if (certs.length >= maxItems || pageCount >= maxPages) {
        truncated = Boolean(nextPageToken) || certs.length > maxItems;
        break;
      }
    } catch (e) {
      // Same reasoning as listCertificateManagerCertificates: a 404 does
      // not mean "confirmed no certificates" and must not be swallowed
      // into an empty-but-complete result.
      if (e.response && !e.status) {
        e.status = e.response.status;
      }
      throw e;
    }
  } while (nextPageToken && certs.length < maxItems);

  return { items: certs.slice(0, maxItems), truncated };
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

  logger.info("Starting GCP scan", {
    projectId,
    maxItems,
    includeSecrets: include.secrets,
    includeCertificates: include.certificates,
  });

  const items = [];
  const summary = [];

  try {
    // Scan Secrets
    if (include.secrets) {
      try {
        const { items: secrets, truncated: secretsTruncated } =
          await listSecrets({ projectId, accessToken, maxItems });
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

        let describeFailedCount = 0;
        const BATCH_SIZE = 10;
        for (let i = 0; i < secrets.length; i += BATCH_SIZE) {
          if (items.length >= maxItems) break;
          const batch = secrets.slice(i, i + BATCH_SIZE);

          await Promise.all(
            batch.map(async (secret) => {
              if (items.length >= maxItems) return;
              const secretName = secret.name.split("/").pop();

              // Get enabled versions to check expiration
              try {
                const versions = await getSecretVersions({
                  projectId,
                  accessToken,
                  secretId: secretName,
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
                  secretName,
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
                  sourceKind: "gcp-secret-manager",
                  sourceObjectId: secretName,
                  name: secretName || secret.name,
                  category: "key_secret",
                  type: "secret",
                  expiration: expiresAt ? formatDateYmd(expiresAt) : null,
                  location: `gcp:${projectId}/secrets/${secretName}`,
                  created_at: secret.createTime || null,
                  updated_at: secret.updateTime || null,
                  version_count: versions.length || 0,
                  enabled_versions: enabledVersions.length || 0,
                });
              } catch (e) {
                // Version lookup is expiration metadata, not membership.
                // The secret was already listed, so record it without an
                // expiry and keep the kind complete: cleanup must still
                // drop secrets that were not on this list.
                describeFailedCount++;
                logger.warn("Failed to get GCP secret versions", {
                  secretName: secret.name,
                  error: e.message,
                });
                items.push({
                  source: "gcp-secret-manager",
                  sourceKind: "gcp-secret-manager",
                  sourceObjectId: secretName,
                  name: secretName || secret.name,
                  category: "key_secret",
                  type: "secret",
                  expiration: null,
                  location: `gcp:${projectId}/secrets/${secretName}`,
                  created_at: secret.createTime || null,
                  updated_at: secret.updateTime || null,
                });
              }
            }),
          );
        }
        summary.push({
          type: "secrets",
          sourceKind: "gcp-secret-manager",
          found: secrets.length,
          failedCount: describeFailedCount,
          truncated: secretsTruncated,
          complete: !secretsTruncated,
        });
        logger.info("GCP secrets scan completed", {
          secretsFound: secrets.length,
          itemsExtracted: items.length,
          versionLookupFailures: describeFailedCount,
        });
      } catch (e) {
        logger.error("GCP secrets scan failed", {
          error: e.message,
          status: e.status || e.response?.status,
          projectId,
        });
        summary.push({
          type: "secrets",
          sourceKind: "gcp-secret-manager",
          error: e.message,
          status: e.status || e.response?.status,
          complete: false,
        });
      }
    }

    // Scan Certificate Manager (global location only -- see
    // listCertificateManagerCertificates)
    if (include.certificates) {
      const location = "global";
      try {
        const { items: certs, truncated: certsTruncated } =
          await listCertificateManagerCertificates({
            projectId,
            accessToken,
            location,
            maxItems,
          });
        logger.info("GCP Certificate Manager certificates listed", {
          count: certs.length,
          location,
        });

        let certsPushed = 0;
        for (const cert of certs) {
          if (items.length >= maxItems) break;
          const certName = cert.name.split("/").pop();
          const expiresAt = tryParseDate(cert.expireTime);
          const isManaged = Boolean(cert.managed);
          const domains =
            cert.sanDnsnames && cert.sanDnsnames.length > 0
              ? cert.sanDnsnames
              : isManaged
                ? cert.managed?.domains || []
                : [];

          items.push({
            source: "gcp-certificate-manager",
            sourceKind: "gcp-certificate-manager-cert",
            sourceObjectId: certName,
            name: certName || cert.name,
            category: "cert",
            type: "ssl_cert",
            expiration: expiresAt ? formatDateYmd(expiresAt) : null,
            location: `gcp:${projectId}/locations/${location}/certificates/${certName}`,
            domains,
            issuer: isManaged ? "Google Trust Services" : null,
            description: `${isManaged ? "Managed" : "Self-managed"}${cert.managed?.state ? `, ${cert.managed.state}` : ""}`,
            created_at: cert.createTime || null,
            updated_at: cert.updateTime || null,
            dimensions: { location },
          });
          certsPushed++;
        }
        // The shared items/maxItems budget can cut this kind short even
        // when its own listing wasn't truncated -- e.g. secrets already
        // consumed the budget. Either kind of truncation means cleanup
        // must not treat this sub-scope as a complete enumeration.
        const certsBudgetTruncated = certsPushed < certs.length;

        summary.push({
          type: "certificate_manager_certs",
          sourceKind: "gcp-certificate-manager-cert",
          location,
          found: certsPushed,
          truncated: certsTruncated || certsBudgetTruncated,
          complete: !certsTruncated && !certsBudgetTruncated,
          dimensions: { location },
        });
        logger.info("GCP Certificate Manager scan completed", {
          certsFound: certs.length,
          location,
        });
      } catch (e) {
        logger.error("GCP Certificate Manager scan failed", {
          error: e.message,
          status: e.status || e.response?.status,
          projectId,
        });
        summary.push({
          type: "certificate_manager_certs",
          sourceKind: "gcp-certificate-manager-cert",
          location,
          error: e.message,
          status: e.status || e.response?.status,
          complete: false,
          dimensions: { location },
        });
      }

      // Compute Engine sslCertificates cover both global and regional
      // scopes -- see listComputeSslCertificates.
      try {
        const { items: sslCerts, truncated: sslCertsTruncated } =
          await listComputeSslCertificates({ projectId, accessToken, maxItems });
        logger.info("GCP Compute Engine SSL certificates listed", {
          count: sslCerts.length,
        });

        let sslCertsPushed = 0;
        for (const cert of sslCerts) {
          if (items.length >= maxItems) break;
          const region =
            cert.scope && cert.scope !== "global"
              ? cert.scope.replace(/^regions\//, "")
              : null;
          const expiresAt = tryParseDate(cert.expireTime);
          const isManaged = Boolean(cert.managed);
          const domains = cert.subjectAlternativeNames?.length
            ? cert.subjectAlternativeNames
            : isManaged
              ? cert.managed?.domains || []
              : [];

          items.push({
            source: "gcp-compute-ssl-cert",
            sourceKind: "gcp-compute-ssl-cert",
            sourceObjectId: cert.name,
            name: cert.name,
            category: "cert",
            type: "ssl_cert",
            expiration: expiresAt ? formatDateYmd(expiresAt) : null,
            location: region
              ? `gcp:${projectId}/regions/${region}/sslCertificates/${cert.name}`
              : `gcp:${projectId}/global/sslCertificates/${cert.name}`,
            domains,
            issuer: isManaged ? "Google Trust Services" : null,
            description: `${isManaged ? "Managed" : "Self-managed"}${cert.managed?.status ? `, ${cert.managed.status}` : ""}`,
            created_at: cert.creationTimestamp || null,
            region,
          });
          sslCertsPushed++;
        }
        // See the certsBudgetTruncated comment above -- same shared-budget
        // hazard applies here, and this kind runs last so it is the most
        // exposed to a budget already spent by secrets and cert-manager.
        const sslCertsBudgetTruncated = sslCertsPushed < sslCerts.length;

        summary.push({
          type: "compute_ssl_certs",
          sourceKind: "gcp-compute-ssl-cert",
          found: sslCertsPushed,
          truncated: sslCertsTruncated || sslCertsBudgetTruncated,
          complete: !sslCertsTruncated && !sslCertsBudgetTruncated,
        });
        logger.info("GCP Compute Engine SSL certificate scan completed", {
          certsFound: sslCerts.length,
        });
      } catch (e) {
        logger.error("GCP Compute Engine SSL certificate scan failed", {
          error: e.message,
          status: e.status || e.response?.status,
          projectId,
        });
        summary.push({
          type: "compute_ssl_certs",
          sourceKind: "gcp-compute-ssl-cert",
          error: e.message,
          status: e.status || e.response?.status,
          complete: false,
        });
      }
    }
  } catch (e) {
    logger.error("GCP scan failed", { error: e.message, projectId });
    summary.push({ type: "scan", error: e.message, complete: false });
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
    listCertificateManagerCertificates,
    listComputeSslCertificates,
  };
}
