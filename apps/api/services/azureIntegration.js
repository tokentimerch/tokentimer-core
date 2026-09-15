"use strict";

const axios = require("axios");
const { X509Certificate } = require("crypto");
const {
  tryParseDate,
  formatDateYmd,
  CREDENTIALED_AXIOS_REDIRECTS,
  assertSameOriginFollowUp,
  throwIfAllScopesFailed,
} = require("./integrationUtils");
const { withCurrentTokenRetry } = require("./azureClientCredentials");
const { logger } = require("../utils/logger");

function wrapAzureError(error, method, path) {
  if (error && error.status && String(error.message || "").startsWith("Azure Key Vault")) {
    return error;
  }
  if (error && error.response) {
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
    return err;
  }
  return error;
}

async function azureRequest({
  vaultUrl,
  token,
  method = "GET",
  path,
  apiVersion = "7.4",
  authProvider,
}) {
  const url = new URL(path.startsWith("/") ? path : `/${path}`, vaultUrl);
  url.searchParams.set("api-version", apiVersion);

  const run = async (bearer) => {
    try {
      const response = await axios({
        method,
        url: url.toString(),
        headers: {
          Authorization: `Bearer ${bearer}`,
          "Content-Type": "application/json",
        },
        timeout: 120000,
        ...CREDENTIALED_AXIOS_REDIRECTS,
      });
      return response.data;
    } catch (error) {
      if (error.response) {
        throw wrapAzureError(error, method, path);
      }
      logger.error("Azure Key Vault API request error", {
        method,
        path,
        error: error.message,
        code: error.code,
      });
      throw error;
    }
  };

  return await withCurrentTokenRetry(authProvider, token, run);
}

async function azureListPage({
  vaultUrl,
  token,
  nextLink,
  defaultPath,
  authProvider,
}) {
  const url = nextLink
    ? assertSameOriginFollowUp(
        nextLink,
        vaultUrl,
        "Azure Key Vault pagination URL",
      )
    : new URL(defaultPath, vaultUrl.endsWith("/") ? vaultUrl : `${vaultUrl}/`);
  url.searchParams.set("api-version", "7.4");
  if (!nextLink) url.searchParams.set("maxresults", "25");

  const run = async (bearer) => {
    try {
      const response = await axios({
        method: "GET",
        url: url.toString(),
        headers: {
          Authorization: `Bearer ${bearer}`,
        },
        timeout: 120000,
        ...CREDENTIALED_AXIOS_REDIRECTS,
      });
      return response.data;
    } catch (error) {
      throw wrapAzureError(error, "GET", defaultPath || nextLink || "/");
    }
  };

  return await withCurrentTokenRetry(authProvider, token, run);
}

async function listCollection({
  vaultUrl,
  token,
  authProvider,
  defaultPath,
  maxItems = 500,
}) {
  const collected = [];
  let nextLink = null;
  let pageCount = 0;
  const maxPages = 50;
  let truncated = false;

  do {
    const data = await azureListPage({
      vaultUrl,
      token,
      authProvider,
      nextLink,
      defaultPath,
    });
    if (Array.isArray(data.value)) {
      collected.push(...data.value);
    } else if (Array.isArray(data)) {
      collected.push(...data);
    }

    nextLink = data.nextLink || null;
    pageCount++;

    if (collected.length >= maxItems || pageCount >= maxPages) {
      truncated = Boolean(nextLink) || collected.length > maxItems;
      break;
    }
  } while (nextLink && collected.length < maxItems);

  return { items: collected.slice(0, maxItems), truncated };
}

async function listSecrets(opts) {
  return listCollection({ ...opts, defaultPath: "/secrets" });
}

async function listCertificates(opts) {
  return listCollection({ ...opts, defaultPath: "/certificates" });
}

async function listKeys(opts) {
  return listCollection({ ...opts, defaultPath: "/keys" });
}

async function _getSecretVersions({ vaultUrl, token, secretName, authProvider }) {
  try {
    const data = await azureRequest({
      vaultUrl,
      token,
      authProvider,
      method: "GET",
      path: `/secrets/${encodeURIComponent(secretName)}/versions`,
    });
    return Array.isArray(data.value) ? data.value : [];
  } catch (e) {
    if (e.status === 404 || e.status === 403) return [];
    throw e;
  }
}

async function getSecret({
  vaultUrl,
  token,
  secretName,
  version = null,
  authProvider,
}) {
  try {
    const path = version
      ? `/secrets/${encodeURIComponent(secretName)}/${encodeURIComponent(version)}`
      : `/secrets/${encodeURIComponent(secretName)}`;
    return await azureRequest({
      vaultUrl,
      token,
      authProvider,
      method: "GET",
      path,
    });
  } catch (e) {
    if (e.status === 404 || e.status === 403) return null;
    throw e;
  }
}

async function getCertificate({
  vaultUrl,
  token,
  certificateName,
  version = null,
  authProvider,
}) {
  try {
    const path = version
      ? `/certificates/${encodeURIComponent(certificateName)}/${encodeURIComponent(version)}`
      : `/certificates/${encodeURIComponent(certificateName)}`;
    return await azureRequest({
      vaultUrl,
      token,
      authProvider,
      method: "GET",
      path,
    });
  } catch (e) {
    if (e.status === 404 || e.status === 403) return null;
    throw e;
  }
}

function nameFromId(id, segment) {
  const pathParts = id ? String(id).split("/").filter(Boolean) : [];
  const index = pathParts.indexOf(segment);
  return index >= 0 && pathParts[index + 1] ? pathParts[index + 1] : null;
}

function unixAttrIso(value) {
  if (value == null) return null;
  const d = new Date(Number(value) * 1000);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function unixExpYmd(value) {
  if (value == null) return null;
  const parsed = tryParseDate(new Date(Number(value) * 1000));
  return parsed ? formatDateYmd(parsed) : null;
}

function failedScopeSummary(type, sourceKind, error) {
  return {
    type,
    sourceKind,
    error: error?.message || String(error),
    status: error?.status,
    complete: false,
  };
}

async function scanAzure({
  vaultUrl,
  token,
  authProvider,
  include = { secrets: true, certificates: true, keys: true },
  maxItems = 500,
}) {
  if (!vaultUrl || !token) throw new Error("vaultUrl and token are required");

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
  const listOpts = { vaultUrl: null, token, authProvider, maxItems };

  try {
    const normalizedUrl = vaultUrl.endsWith("/")
      ? vaultUrl.slice(0, -1)
      : vaultUrl;
    listOpts.vaultUrl = normalizedUrl;

    if (include.secrets) {
      try {
        const { items: secretList, truncated: secretsTruncated } =
          await listSecrets(listOpts);
        logger.info("Azure secrets list retrieved", {
          count: secretList.length,
        });

        const seenSecrets = new Set();
        let secretsBudgetExhausted = false;

        for (const secret of secretList) {
          if (items.length >= maxItems) {
            secretsBudgetExhausted = true;
            break;
          }

          const secretName = nameFromId(secret.id, "secrets");
          if (!secretName) {
            logger.warn("Azure secret missing name", {
              secretId: secret.id,
            });
            continue;
          }
          if (seenSecrets.has(secretName)) continue;
          seenSecrets.add(secretName);

          if (secret.attributes?.enabled === false) {
            logger.debug("Skipping disabled Azure secret", { secretName });
            continue;
          }

          items.push({
            source: "azure-key-vault-secret",
            sourceKind: "azure-key-vault-secret",
            sourceObjectId: secretName,
            name: secretName,
            category: "key_secret",
            type: "secret",
            expiration: unixExpYmd(secret.attributes?.exp),
            location: `azure:${normalizedUrl}/secrets/${secretName}`,
            created_at: unixAttrIso(secret.attributes?.created),
            updated_at: unixAttrIso(secret.attributes?.updated),
          });
        }
        const secretsFound = items.filter(
          (i) => i.source === "azure-key-vault-secret",
        ).length;
        summary.push({
          type: "secrets",
          sourceKind: "azure-key-vault-secret",
          found: secretsFound,
          truncated: secretsTruncated || secretsBudgetExhausted,
          complete: !secretsTruncated && !secretsBudgetExhausted,
        });
        logger.info("Azure secrets scan completed", {
          found: secretsFound,
        });
      } catch (e) {
        logger.error("Azure secrets scan failed", { error: e.message });
        summary.push(
          failedScopeSummary("secrets", "azure-key-vault-secret", e),
        );
      }
    }

    if (include.certificates) {
      try {
        const { items: certificateList, truncated: certsTruncated } =
          await listCertificates(listOpts);
        logger.info("Azure certificates list retrieved", {
          count: certificateList.length,
        });

        const seenCertificates = new Set();
        const BATCH_SIZE = 10;
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

              const certName = nameFromId(cert.id, "certificates");
              if (!certName) {
                logger.warn("Azure certificate missing name", {
                  certId: cert.id,
                });
                return;
              }
              if (seenCertificates.has(certName)) return;
              seenCertificates.add(certName);

              if (cert.attributes?.enabled === false) {
                logger.debug("Skipping disabled Azure certificate", {
                  certName,
                });
                return;
              }

              let certDetails = null;
              try {
                certDetails = await getCertificate({
                  vaultUrl: normalizedUrl,
                  token,
                  authProvider,
                  certificateName: certName,
                });
              } catch (e) {
                logger.warn("Failed to get Azure certificate details", {
                  certName,
                  error: e.message,
                });
              }

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
                expiration: unixExpYmd(
                  certDetails?.attributes?.exp ?? cert.attributes?.exp,
                ),
                location: `azure:${normalizedUrl}/certificates/${certName}`,
                issuer: issuer,
                subject: subject || certName,
                created_at: unixAttrIso(
                  certDetails?.attributes?.created ?? cert.attributes?.created,
                ),
                updated_at: unixAttrIso(
                  certDetails?.attributes?.updated ?? cert.attributes?.updated,
                ),
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
          truncated: certsTruncated || certsBudgetExhausted,
          complete: !certsTruncated && !certsBudgetExhausted,
        });
        logger.info("Azure certificates scan completed", {
          found: certsFound,
        });
      } catch (e) {
        logger.error("Azure certificates scan failed", { error: e.message });
        summary.push(
          failedScopeSummary(
            "certificates",
            "azure-key-vault-certificate",
            e,
          ),
        );
      }
    }

    if (include.keys) {
      try {
        const { items: keyList, truncated: keysTruncated } =
          await listKeys(listOpts);
        logger.info("Azure keys list retrieved", { count: keyList.length });

        const seenKeys = new Set();
        let keysBudgetExhausted = false;

        for (const key of keyList) {
          if (items.length >= maxItems) {
            keysBudgetExhausted = true;
            break;
          }

          const keyId = key.kid || key.id;
          const keyName = nameFromId(keyId, "keys");
          if (!keyName) {
            logger.warn("Azure key missing name", { keyId });
            continue;
          }
          if (seenKeys.has(keyName)) continue;
          seenKeys.add(keyName);

          if (key.attributes?.enabled === false) {
            logger.debug("Skipping disabled Azure key", { keyName });
            continue;
          }

          items.push({
            source: "azure-key-vault-key",
            sourceKind: "azure-key-vault-key",
            sourceObjectId: keyName,
            name: keyName,
            category: "key_secret",
            type: "encryption_key",
            expiration: unixExpYmd(key.attributes?.exp),
            location: `azure:${normalizedUrl}/keys/${keyName}`,
            key_type: key.kty || null,
            key_size: key.key_size || null,
            algorithm: key.kty || null,
            created_at: unixAttrIso(key.attributes?.created),
            updated_at: unixAttrIso(key.attributes?.updated),
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
        summary.push(failedScopeSummary("keys", "azure-key-vault-key", e));
      }
    }
  } catch (e) {
    logger.error("Azure scan failed", { error: e.message });
    summary.push({
      type: "scan",
      error: e.message,
      status: e.status,
      complete: false,
    });
  }

  throwIfAllScopesFailed(summary, items);

  logger.info("Azure scan completed", { itemsFound: items.length });
  return { items, summary };
}

module.exports = {
  scanAzure,
};

if (process.env.NODE_ENV === "test") {
  module.exports._test = {
    azureRequest,
    azureListPage,
    listSecrets,
    listCertificates,
    listKeys,
    getSecret,
    getCertificate,
    _getSecretVersions,
  };
}
