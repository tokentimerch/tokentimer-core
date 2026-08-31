"use strict";

const axios = require("axios");
const { X509Certificate } = require("crypto");
const {
  tryParseDate,
  formatDateYmd,
  CREDENTIALED_AXIOS_REDIRECTS,
  assertSameOriginFollowUp,
} = require("./integrationUtils");
const { logger } = require("../utils/logger");

async function azureRequest({
  vaultUrl,
  token,
  method = "GET",
  path,
  apiVersion = "7.4",
}) {
  const url = new URL(path.startsWith("/") ? path : `/${path}`, vaultUrl);
  url.searchParams.set("api-version", apiVersion);

  const headers = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };

  try {
    const response = await axios({
      method,
      url: url.toString(),
      headers,
      timeout: 120000, // 120 second timeout (increased for up to 2000 items)
      ...CREDENTIALED_AXIOS_REDIRECTS,
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      const err = new Error(
        `Azure Key Vault ${method} ${path} ${error.response.status}`,
      );
      err.status = error.response.status;
      err.body = error.response.data;
      logger.warn("Azure Key Vault API request failed", {
        method,
        path,
        status: error.response.status,
      });
      throw err;
    }
    logger.error("Azure Key Vault API request error", {
      method,
      path,
      error: error.message,
      code: error.code,
    });
    throw error;
  }
}

async function azureListPage({ vaultUrl, token, nextLink, defaultPath }) {
  const url = nextLink
    ? assertSameOriginFollowUp(
        nextLink,
        vaultUrl,
        "Azure Key Vault pagination URL",
      )
    : new URL(defaultPath, vaultUrl.endsWith("/") ? vaultUrl : `${vaultUrl}/`);
  url.searchParams.set("api-version", "7.4");
  if (!nextLink) url.searchParams.set("maxresults", "25");

  const response = await axios({
    method: "GET",
    url: url.toString(),
    headers: {
      Authorization: `Bearer ${token}`,
    },
    timeout: 120000, // 120 second timeout (increased for up to 2000 items)
    ...CREDENTIALED_AXIOS_REDIRECTS,
  });
  return response.data;
}

async function listSecrets({ vaultUrl, token, maxItems = 500 }) {
  const secrets = [];
  let nextLink = null;
  let pageCount = 0;
  const maxPages = 50;
  // truncated tracks "there was more to see than we looked at" -- distinct
  // from a 404/403 on the collection itself, which means "nothing here",
  // not "couldn't finish". A truncated listing must never gate cleanup as
  // if this source kind were fully enumerated.
  let truncated = false;

  do {
    try {
      const data = await azureListPage({
        vaultUrl,
        token,
        nextLink,
        defaultPath: "/secrets",
      });
      if (Array.isArray(data.value)) {
        secrets.push(...data.value);
      } else if (Array.isArray(data)) {
        secrets.push(...data);
      }

      nextLink = data.nextLink || null;
      pageCount++;

      if (secrets.length >= maxItems || pageCount >= maxPages) {
        truncated = Boolean(nextLink) || secrets.length > maxItems;
        break;
      }
    } catch (e) {
      if (e.status === 404 || e.status === 403) break;
      throw e;
    }
  } while (nextLink && secrets.length < maxItems);

  return { items: secrets.slice(0, maxItems), truncated };
}

async function _getSecretVersions({ vaultUrl, token, secretName }) {
  try {
    const data = await azureRequest({
      vaultUrl,
      token,
      method: "GET",
      path: `/secrets/${encodeURIComponent(secretName)}/versions`,
    });
    return Array.isArray(data.value) ? data.value : [];
  } catch (e) {
    if (e.status === 404 || e.status === 403) return [];
    throw e;
  }
}

async function getSecret({ vaultUrl, token, secretName, version = null }) {
  try {
    const path = version
      ? `/secrets/${encodeURIComponent(secretName)}/${encodeURIComponent(version)}`
      : `/secrets/${encodeURIComponent(secretName)}`;
    const data = await azureRequest({
      vaultUrl,
      token,
      method: "GET",
      path,
    });
    return data;
  } catch (e) {
    if (e.status === 404 || e.status === 403) return null;
    throw e;
  }
}

async function listCertificates({ vaultUrl, token, maxItems = 500 }) {
  const certificates = [];
  let nextLink = null;
  let pageCount = 0;
  const maxPages = 50;
  let truncated = false;

  do {
    try {
      const data = await azureListPage({
        vaultUrl,
        token,
        nextLink,
        defaultPath: "/certificates",
      });
      if (Array.isArray(data.value)) {
        certificates.push(...data.value);
      } else if (Array.isArray(data)) {
        certificates.push(...data);
      }

      nextLink = data.nextLink || null;
      pageCount++;

      if (certificates.length >= maxItems || pageCount >= maxPages) {
        truncated = Boolean(nextLink) || certificates.length > maxItems;
        break;
      }
    } catch (e) {
      if (e.status === 404 || e.status === 403) break;
      throw e;
    }
  } while (nextLink && certificates.length < maxItems);

  return { items: certificates.slice(0, maxItems), truncated };
}

async function getCertificate({
  vaultUrl,
  token,
  certificateName,
  version = null,
}) {
  try {
    const path = version
      ? `/certificates/${encodeURIComponent(certificateName)}/${encodeURIComponent(version)}`
      : `/certificates/${encodeURIComponent(certificateName)}`;
    const data = await azureRequest({
      vaultUrl,
      token,
      method: "GET",
      path,
    });
    return data;
  } catch (e) {
    if (e.status === 404 || e.status === 403) return null;
    throw e;
  }
}

async function listKeys({ vaultUrl, token, maxItems = 500 }) {
  const keys = [];
  let nextLink = null;
  let pageCount = 0;
  const maxPages = 50;
  let truncated = false;

  do {
    try {
      const data = await azureListPage({
        vaultUrl,
        token,
        nextLink,
        defaultPath: "/keys",
      });
      if (Array.isArray(data.value)) {
        keys.push(...data.value);
      } else if (Array.isArray(data)) {
        keys.push(...data);
      }

      nextLink = data.nextLink || null;
      pageCount++;

      if (keys.length >= maxItems || pageCount >= maxPages) {
        truncated = Boolean(nextLink) || keys.length > maxItems;
        break;
      }
    } catch (e) {
      if (e.status === 404 || e.status === 403) break;
      throw e;
    }
  } while (nextLink && keys.length < maxItems);

  return { items: keys.slice(0, maxItems), truncated };
}

async function scanAzure({
  vaultUrl,
  token,
  include = { secrets: true, certificates: true, keys: true },
  maxItems = 500,
}) {
  if (!vaultUrl || !token) throw new Error("vaultUrl and token are required");

  // Validate inputs
  if (typeof vaultUrl !== "string" || vaultUrl.length > 500) {
    throw new Error("Invalid vaultUrl format");
  }
  if (typeof token !== "string" || token.length > 5000) {
    throw new Error("Invalid token format");
  }
  if (!Number.isInteger(maxItems) || maxItems < 1 || maxItems > 2000) {
    throw new Error("maxItems must be between 1 and 2000");
  }

  logger.info("Starting Azure Key Vault scan", { maxItems });

  const items = [];
  const summary = [];

  try {
    // Normalize vaultUrl
    const normalizedUrl = vaultUrl.endsWith("/")
      ? vaultUrl.slice(0, -1)
      : vaultUrl;

    // Scan Secrets
    if (include.secrets) {
      try {
        const { items: secretList, truncated: secretsTruncated } =
          await listSecrets({
            vaultUrl: normalizedUrl,
            token,
            maxItems,
          });
        logger.info("Azure secrets list retrieved", {
          count: secretList.length,
        });

        // Deduplicate - Azure API may return multiple versions, keep only latest
        const seenSecrets = new Set();
        const BATCH_SIZE = 10;
        let describeFailedCount = 0;
        let secretsBudgetExhausted = false;

        for (let i = 0; i < secretList.length; i += BATCH_SIZE) {
          if (items.length >= maxItems) {
            // The shared cross-type item budget ran out before this
            // sub-scope finished processing its own listed secrets --
            // report incomplete even though listSecrets() itself paginated
            // fine, since some listed secrets here were never even
            // attempted.
            secretsBudgetExhausted = true;
            break;
          }
          const batch = secretList.slice(i, i + BATCH_SIZE);

          await Promise.all(
            batch.map(async (secret) => {
              if (items.length >= maxItems) return;

              // Extract secret name from id URL (remove version if present)
              // id format: "https://vault.vault.azure.net/secrets/secret-name" or
              // "https://vault.vault.azure.net/secrets/secret-name/version-id"
              const pathParts = secret.id
                ? secret.id.split("/").filter(Boolean)
                : [];
              const secretsIndex = pathParts.indexOf("secrets");
              const secretName =
                secretsIndex >= 0 && pathParts[secretsIndex + 1]
                  ? pathParts[secretsIndex + 1]
                  : null;

              if (!secretName) {
                logger.warn("Azure secret missing name", {
                  secretId: secret.id,
                });
                return;
              }

              // Skip if we've already processed this secret
              if (seenSecrets.has(secretName)) {
                logger.debug(
                  "Azure secret already processed (duplicate version)",
                  {
                    secretName,
                  },
                );
                return;
              }
              seenSecrets.add(secretName);

              // Get full secret details (latest version) to ensure we have expiration
              let secretDetails;
              try {
                secretDetails = await getSecret({
                  vaultUrl: normalizedUrl,
                  token,
                  secretName,
                });
              } catch (e) {
                // A failed detail fetch means this secret's continued
                // existence/expiration is unconfirmed -- count it so the
                // "secrets" sub-scope is reported incomplete rather than
                // silently treating the fetch failure as "not present".
                describeFailedCount++;
                logger.warn("Failed to get Azure secret details", {
                  secretName,
                  error: e.message,
                });
                return;
              }

              // Skip disabled secrets
              if (secretDetails?.attributes?.enabled === false) {
                logger.debug("Skipping disabled Azure secret", { secretName });
                return;
              }

              const expiresAt = secretDetails?.attributes?.exp
                ? tryParseDate(new Date(secretDetails.attributes.exp * 1000))
                : secret.attributes?.exp
                  ? tryParseDate(new Date(secret.attributes.exp * 1000))
                  : null;

              items.push({
                source: "azure-key-vault-secret",
                sourceKind: "azure-key-vault-secret",
                sourceObjectId: secretName,
                name: secretName,
                category: "key_secret",
                type: "secret",
                expiration: expiresAt ? formatDateYmd(expiresAt) : null,
                location: `azure:${normalizedUrl}/secrets/${secretName}`,
                created_at: secretDetails?.attributes?.created
                  ? new Date(
                      secretDetails.attributes.created * 1000,
                    ).toISOString()
                  : null,
                updated_at: secretDetails?.attributes?.updated
                  ? new Date(
                      secretDetails.attributes.updated * 1000,
                    ).toISOString()
                  : null,
              });
            }),
          );
        }
        const secretsFound = items.filter(
          (i) => i.source === "azure-key-vault-secret",
        ).length;
        summary.push({
          type: "secrets",
          sourceKind: "azure-key-vault-secret",
          found: secretsFound,
          failedCount: describeFailedCount,
          truncated: secretsTruncated || secretsBudgetExhausted,
          complete:
            describeFailedCount === 0 &&
            !secretsTruncated &&
            !secretsBudgetExhausted,
        });
        logger.info("Azure secrets scan completed", {
          found: secretsFound,
        });
      } catch (e) {
        logger.error("Azure secrets scan failed", { error: e.message });
        summary.push({
          type: "secrets",
          sourceKind: "azure-key-vault-secret",
          error: e.message,
          complete: false,
        });
      }
    }

    // Scan Certificates
    if (include.certificates) {
      try {
        const { items: certificateList, truncated: certsTruncated } =
          await listCertificates({
            vaultUrl: normalizedUrl,
            token,
            maxItems,
          });
        logger.info("Azure certificates list retrieved", {
          count: certificateList.length,
        });

        // Deduplicate - keep only latest version of each certificate
        const seenCertificates = new Set();
        const BATCH_SIZE = 10;
        let describeFailedCount = 0;
        let certsBudgetExhausted = false;

        for (let i = 0; i < certificateList.length; i += BATCH_SIZE) {
          if (items.length >= maxItems) {
            certsBudgetExhausted = true;
            break;
          }
          const batch = certificateList.slice(i, i + BATCH_SIZE);

          await Promise.all(
            batch.map(async (cert) => {
              if (items.length >= maxItems) return;

              // Extract certificate name from id URL (remove version if present)
              // id format: "https://vault.vault.azure.net/certificates/cert-name" or with version
              const pathParts = cert.id
                ? cert.id.split("/").filter(Boolean)
                : [];
              const certificatesIndex = pathParts.indexOf("certificates");
              const certName =
                certificatesIndex >= 0 && pathParts[certificatesIndex + 1]
                  ? pathParts[certificatesIndex + 1]
                  : null;

              if (!certName) {
                logger.warn("Azure certificate missing name", {
                  certId: cert.id,
                });
                return;
              }

              // Skip if we've already processed this certificate
              if (seenCertificates.has(certName)) {
                logger.debug(
                  "Azure certificate already processed (duplicate version)",
                  { certName },
                );
                return;
              }
              seenCertificates.add(certName);

              // Get full certificate details (latest version)
              let certDetails;
              try {
                certDetails = await getCertificate({
                  vaultUrl: normalizedUrl,
                  token,
                  certificateName: certName,
                });
              } catch (e) {
                describeFailedCount++;
                logger.warn("Failed to get Azure certificate details", {
                  certName,
                  error: e.message,
                });
                return;
              }

              // Skip disabled certificates
              if (certDetails?.attributes?.enabled === false) {
                logger.debug("Skipping disabled Azure certificate", {
                  certName,
                });
                return;
              }

              const expiresAt = certDetails?.attributes?.exp
                ? tryParseDate(new Date(certDetails.attributes.exp * 1000))
                : cert.attributes?.exp
                  ? tryParseDate(new Date(cert.attributes.exp * 1000))
                  : null;

              // CertificateBundle has no top-level subject/issuer: the X.509
              // subject lives in policy.x509_props.subject and the issuer name
              // in policy.issuer.name ("Self", "Unknown", or a CA provider).
              // The authoritative values come from the certificate itself,
              // returned base64-DER-encoded in `cer`.
              let subject = certDetails?.policy?.x509_props?.subject || null;
              let issuer = certDetails?.policy?.issuer?.name || null;
              if (certDetails?.cer) {
                try {
                  const parsed = new X509Certificate(
                    Buffer.from(certDetails.cer, "base64"),
                  );
                  subject = parsed.subject || subject;
                  issuer = parsed.issuer || issuer;
                } catch (e) {
                  logger.debug("Failed to parse Azure certificate cer", {
                    certName,
                    error: e.message,
                  });
                }
              }

              items.push({
                source: "azure-key-vault-certificate",
                sourceKind: "azure-key-vault-certificate",
                sourceObjectId: certName,
                name: certName,
                category: "cert",
                type: "ssl_cert",
                expiration: expiresAt ? formatDateYmd(expiresAt) : null,
                location: `azure:${normalizedUrl}/certificates/${certName}`,
                issuer: issuer,
                subject: subject || certName,
                created_at: certDetails?.attributes?.created
                  ? new Date(
                      certDetails.attributes.created * 1000,
                    ).toISOString()
                  : null,
                updated_at: certDetails?.attributes?.updated
                  ? new Date(
                      certDetails.attributes.updated * 1000,
                    ).toISOString()
                  : null,
              });
            }),
          );
        }
        const certsFound = items.filter(
          (i) => i.source === "azure-key-vault-certificate",
        ).length;
        summary.push({
          type: "certificates",
          sourceKind: "azure-key-vault-certificate",
          found: certsFound,
          failedCount: describeFailedCount,
          truncated: certsTruncated || certsBudgetExhausted,
          complete:
            describeFailedCount === 0 &&
            !certsTruncated &&
            !certsBudgetExhausted,
        });
        logger.info("Azure certificates scan completed", {
          found: certsFound,
        });
      } catch (e) {
        logger.error("Azure certificates scan failed", { error: e.message });
        summary.push({
          type: "certificates",
          sourceKind: "azure-key-vault-certificate",
          error: e.message,
          complete: false,
        });
      }
    }

    // Scan Keys
    if (include.keys) {
      try {
        const { items: keyList, truncated: keysTruncated } = await listKeys({
          vaultUrl: normalizedUrl,
          token,
          maxItems,
        });
        logger.info("Azure keys list retrieved", { count: keyList.length });

        // Deduplicate - keep only latest version of each key
        const seenKeys = new Set();
        let keysBudgetExhausted = false;

        for (const key of keyList) {
          if (items.length >= maxItems) {
            keysBudgetExhausted = true;
            break;
          }

          // Extract key name from identifier URL (remove version if present)
          // The keys list API returns the identifier in `kid` (not `id`):
          // "https://vault.vault.azure.net/keys/key-name" or with version
          const keyId = key.kid || key.id;
          const pathParts = keyId ? keyId.split("/").filter(Boolean) : [];
          const keysIndex = pathParts.indexOf("keys");
          const keyName =
            keysIndex >= 0 && pathParts[keysIndex + 1]
              ? pathParts[keysIndex + 1]
              : null;

          if (!keyName) {
            logger.warn("Azure key missing name", { keyId });
            continue;
          }

          // Skip if we've already processed this key
          if (seenKeys.has(keyName)) {
            logger.debug("Azure key already processed (duplicate version)", {
              keyName,
            });
            continue;
          }
          seenKeys.add(keyName);

          // Skip disabled keys
          if (key.attributes?.enabled === false) {
            logger.debug("Skipping disabled Azure key", { keyName });
            continue;
          }

          const expiresAt = key.attributes?.exp
            ? tryParseDate(new Date(key.attributes.exp * 1000))
            : null;

          items.push({
            source: "azure-key-vault-key",
            sourceKind: "azure-key-vault-key",
            sourceObjectId: keyName,
            name: keyName,
            category: "key_secret",
            type: "encryption_key",
            expiration: expiresAt ? formatDateYmd(expiresAt) : null,
            location: `azure:${normalizedUrl}/keys/${keyName}`,
            key_type: key.kty || null,
            key_size: key.key_size || null,
            algorithm: key.kty || null,
            created_at: key.attributes?.created
              ? new Date(key.attributes.created * 1000).toISOString()
              : null,
            updated_at: key.attributes?.updated
              ? new Date(key.attributes.updated * 1000).toISOString()
              : null,
          });
        }
        const keysFound = items.filter(
          (i) => i.source === "azure-key-vault-key",
        ).length;
        summary.push({
          type: "keys",
          sourceKind: "azure-key-vault-key",
          found: keysFound,
          truncated: keysTruncated || keysBudgetExhausted,
          complete: !keysTruncated && !keysBudgetExhausted,
        });
        logger.info("Azure keys scan completed", {
          found: keysFound,
        });
      } catch (e) {
        logger.error("Azure keys scan failed", { error: e.message });
        summary.push({
          type: "keys",
          sourceKind: "azure-key-vault-key",
          error: e.message,
          complete: false,
        });
      }
    }
  } catch (e) {
    logger.error("Azure scan failed", { error: e.message });
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

  logger.info("Azure scan completed", { itemsFound: items.length });
  return { items, summary };
}

module.exports = {
  scanAzure,
};

// Test-only exports for unit coverage of helpers
if (process.env.NODE_ENV === "test") {
  module.exports._test = {
    azureRequest,
    listSecrets,
    listCertificates,
    listKeys,
    getSecret,
    getCertificate,
  };
}
