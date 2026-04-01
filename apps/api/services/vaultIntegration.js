"use strict";

const { X509Certificate } = require("crypto");
const {
  discoverExpiryFromObject,
  formatDateYmd,
} = require("./integrationUtils");
const { logger } = require("../utils/logger");

async function vaultRequest({
  address,
  token,
  method = "GET",
  path,
  body,
  query,
}) {
  let url;
  try {
    url = new URL(path.startsWith("/") ? path : `/${path}`, address);
  } catch (e) {
    logger.error("Invalid Vault URL", { address, path, error: e.message });
    throw new Error(`Invalid Vault URL: ${e.message}`);
  }

  if (query && typeof query === "object") {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    }
  }

  // Create AbortController for timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 120000); // 120 second timeout (increased for up to 2000 items per mount)

  try {
    logger.debug("Vault API request", {
      method,
      path: url.pathname,
      address: address.replace(/\/\/[^@]+@/, "//***@"),
    });

    const res = await fetch(url, {
      method,
      headers: {
        "X-Vault-Token": token,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      logger.warn("Vault API request failed", {
        method,
        path: url.pathname,
        status: res.status,
        statusText: res.statusText,
        address: address.replace(/\/\/[^@]+@/, "//***@"),
        responseBody: text.substring(0, 200), // Log first 200 chars of response
      });
      const err = new Error(`Vault ${method} ${url.pathname} ${res.status}`);
      err.status = res.status;
      err.body = text;
      throw err;
    }
    // Some Vault endpoints return empty 204
    if (res.status === 204) return null;
    return await res.json();
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === "AbortError") {
      logger.error("Vault API request timeout", {
        method,
        path: url.pathname,
        address: address.replace(/\/\/[^@]+@/, "//***@"),
        timeoutMs: 30000,
      });
      const err = new Error(`Vault ${method} ${url.pathname} timeout`);
      err.status = 408;
      err.code = "ETIMEDOUT";
      throw err;
    }
    // Network/connection errors
    if (error.message && !error.status) {
      logger.error("Vault network error", {
        method,
        path: url?.pathname,
        address: address.replace(/\/\/[^@]+@/, "//***@"),
        error: error.message,
        errorCode: error.code,
        errorType: error.name,
        cause: error.cause?.message,
      });
    }
    throw error;
  }
}

async function listMounts({ address, token }) {
  logger.debug("Listing Vault mounts", {
    address: address.replace(/\/\/[^@]+@/, "//***@"),
  });

  try {
    const data = await vaultRequest({
      address,
      token,
      method: "GET",
      path: "/v1/sys/mounts",
    });
    // data looks like: { "secret/": { type: "kv", options: { version: "2" }, ... }, ... }
    const mounts = [];
    for (const [path, meta] of Object.entries(data || {})) {
      if (!meta || typeof meta !== "object") continue;
      const type = meta.type;
      mounts.push({ path, type, options: meta.options || {} });
    }
    logger.debug("Vault mounts parsed", { mountCount: mounts.length });
    return mounts;
  } catch (e) {
    logger.error("Failed to list Vault mounts", {
      address: address.replace(/\/\/[^@]+@/, "//***@"),
      error: e.message,
      errorCode: e.code,
      errorType: e.name,
      status: e.status,
    });
    throw e;
  }
}

function inferKindFromData(path, data) {
  try {
    const pathLc = String(path || "").toLowerCase();
    const keysLc = Object.keys(data || {}).map((k) => String(k).toLowerCase());
    const has = (k) => keysLc.includes(String(k).toLowerCase());
    const values = Object.values(data || {}).map((v) => String(v || ""));

    // PRIORITY 1: Check actual data content first (more reliable than path names)

    // Check if any value contains PEM certificate (very strong signal)
    const hasPemCert = values.some((v) => isLikelyPemCertificate(v));
    if (hasPemCert) {
      return { category: "cert", type: "ssl_cert" };
    }

    // Check for SSH key content
    if (
      has("ssh_private_key") ||
      has("private_key") ||
      has("ssh_key") ||
      values.some(
        (v) =>
          v.includes("-----BEGIN OPENSSH PRIVATE KEY-----") ||
          v.includes("-----BEGIN RSA PRIVATE KEY-----"),
      )
    ) {
      return { category: "key_secret", type: "ssh_key" };
    }

    // Check for encryption-related keys by data structure
    if (has("key_id") || has("cipher") || has("iv") || has("encryption_key")) {
      return { category: "key_secret", type: "encryption_key" };
    }

    // Check for explicit key names that indicate type
    if (has("api_key") || has("apikey") || has("access_key")) {
      return { category: "key_secret", type: "api_key" };
    }

    if (has("password") || has("passwd")) {
      return { category: "key_secret", type: "password" };
    }

    // PRIORITY 2: Use path as a hint only if data doesn't clearly indicate type
    // Be very conservative - most things should default to "secret"

    // Only classify as specific types if there's strong evidence
    // Multiple keys suggests mixed content - default to secret
    const keyCount = Object.keys(data || {}).length;

    if (keyCount > 3) {
      // Mixed content - could be config with multiple fields
      // Default to secret to avoid wrong classification
      logger.debug(
        "Vault secret has multiple keys, defaulting to secret type",
        { path, keyCount },
      );
      return { category: "key_secret", type: "secret" };
    }

    // Very specific path patterns only (must match exactly)

    // API key paths - very specific
    if (/(\/api-key$|\/apikey$|\/api_key$)/.test(pathLc)) {
      return { category: "key_secret", type: "api_key" };
    }

    // Password paths - very specific
    if (/(\/password$|\/passwd$)/.test(pathLc)) {
      return { category: "key_secret", type: "password" };
    }
  } catch (_) {}
  // Default: treat as generic secret (safest classification)
  return { category: "key_secret", type: "secret" };
}

function parseCertificatePemForDatesAndNames(pem) {
  try {
    const cert = new X509Certificate(pem);
    const notAfter = new Date(cert.validTo);
    // Subject and issuer in string form (e.g., 'CN=example.com, O=Org')
    const subject = cert.subject;
    const issuer = cert.issuer;
    return { notAfter, subject, issuer };
  } catch (_) {
    return null;
  }
}

function isLikelyPemCertificate(text) {
  if (typeof text !== "string") return false;
  return (
    text.includes("-----BEGIN CERTIFICATE-----") &&
    text.includes("-----END CERTIFICATE-----")
  );
}

function isBase64Like(text) {
  if (typeof text !== "string") return false;
  // Strip whitespace and newlines for heuristic
  const s = text.replace(/[\r\n\s]/g, "");
  if (s.length < 40) return false; // too short to be a cert
  // Base64 charset with optional '=' padding
  if (!/^[A-Za-z0-9+/=]+$/.test(s)) return false;
  // Length multiple of 4 is typical but not guaranteed if missing padding; allow near-multiple
  if (s.length % 4 !== 0 && s.length % 4 !== 2) return false;
  return true;
}

function parseCertificateFromUnknown(value) {
  // Try PEM first
  if (isLikelyPemCertificate(value)) {
    return parseCertificatePemForDatesAndNames(value);
  }
  // Then try base64 -> DER or base64 PEM
  if (isBase64Like(value)) {
    try {
      const buf = Buffer.from(value.replace(/[\r\n\s]/g, ""), "base64");
      if (buf && buf.length > 0) {
        try {
          const cert = new X509Certificate(buf);
          return {
            notAfter: new Date(cert.validTo),
            subject: cert.subject,
            issuer: cert.issuer,
          };
        } catch (_) {
          // Maybe it was base64 of PEM text
          try {
            const txt = buf.toString("utf8");
            if (isLikelyPemCertificate(txt)) {
              return parseCertificatePemForDatesAndNames(txt);
            }
          } catch (_) {}
        }
      }
    } catch (_) {}
  }
  return null;
}

async function listKvV2KeysRecursive({
  address,
  token,
  mountPath,
  prefix = "",
  limit = 1000,
}) {
  // LIST metadata to enumerate keys; recurse into folders
  const results = [];
  async function walk(pathPrefix) {
    const listPath = `/v1/${mountPath}metadata/${pathPrefix}`;
    let data;
    try {
      data = await vaultRequest({
        address,
        token,
        method: "LIST",
        path: listPath,
      });
    } catch (e) {
      // Not found or not listable
      if (e.status === 404) return;
      throw e;
    }
    const keys =
      data && data.data && Array.isArray(data.data.keys) ? data.data.keys : [];
    for (const key of keys) {
      if (results.length >= limit) return;
      if (key.endsWith("/")) {
        await walk(`${pathPrefix}${key}`);
      } else {
        results.push(`${pathPrefix}${key}`);
      }
    }
  }
  await walk(prefix);
  return results;
}

async function readKvV2Secret({ address, token, mountPath, secretPath }) {
  const data = await vaultRequest({
    address,
    token,
    method: "GET",
    path: `/v1/${mountPath}data/${secretPath}`,
  });
  // v2 shape: { data: { data: {...}, metadata: {...} } }
  const payload = (data && data.data) || {};
  return { data: payload.data || {}, metadata: payload.metadata || {} };
}

async function scanKvV2({
  address,
  token,
  mount,
  maxItems = 500,
  pathPrefix = "",
}) {
  const mountPath = mount.path; // already ends with '/'
  const normalizedPrefix =
    typeof pathPrefix === "string" && pathPrefix.length > 0
      ? `${pathPrefix.replace(/^\/+|\/+$/g, "")}/`
      : "";
  const keys = await listKvV2KeysRecursive({
    address,
    token,
    mountPath,
    prefix: normalizedPrefix,
    limit: maxItems,
  });
  const items = [];
  const BATCH_SIZE = 10;

  for (let i = 0; i < keys.length; i += BATCH_SIZE) {
    if (items.length >= maxItems) break;
    const batch = keys.slice(i, i + BATCH_SIZE);

    const batchResults = await Promise.all(
      batch.map(async (key) => {
        if (items.length >= maxItems) return null;
        let secret;
        try {
          secret = await readKvV2Secret({
            address,
            token,
            mountPath,
            secretPath: key,
          });
        } catch (_e) {
          // Skip secrets we cannot read
          return null;
        }
        const data = secret.data || {};
        const keyCount = Object.keys(data).length;
        let { category, type } = inferKindFromData(`${mountPath}${key}`, data);
        let issuer = null;
        let subject = null;
        let expires = discoverExpiryFromObject(data);
        let hasCertificateContent = false;

        // Heuristic: look for PEM certs in values (overrides path-based inference)
        for (const v of Object.values(data)) {
          if (typeof v !== "string") continue;
          let parsed = null;
          if (isLikelyPemCertificate(v)) {
            parsed = parseCertificatePemForDatesAndNames(v);
            hasCertificateContent = true;
          } else if (isBase64Like(v)) {
            parsed = parseCertificateFromUnknown(v);
            if (parsed) hasCertificateContent = true;
          }
          if (parsed) {
            category = "cert";
            type = "ssl_cert";
            issuer = parsed.issuer || issuer;
            subject = parsed.subject || subject;
            if (!expires && parsed.notAfter) expires = parsed.notAfter;
            logger.debug("Vault secret contains certificate", {
              path: `${mountPath}${key}`,
              hasSubject: !!subject,
            });
            break;
          }
        }

        // Log classification for debugging
        if (keyCount > 3 && !hasCertificateContent) {
          logger.debug("Vault secret with multiple keys", {
            path: `${mountPath}${key}`,
            keyCount,
            classifiedAs: `${category}/${type}`,
            keys: Object.keys(data).slice(0, 5), // Log first 5 key names
          });
        }

        // Determine best name: prefer Vault path unless CN is clearly a domain name
        const cn = subject
          ? subject.replace(/^CN=/, "").split(",")[0].trim()
          : null;

        // Generic/test CNs that should be ignored in favor of path name
        const isGenericCN =
          cn &&
          /^(test|example|localhost|default|cert|certificate|ca|root|intermediate)$/i.test(
            cn,
          );

        const vaultPath = `${mountPath}${key}`.replace(/\/$/, "");
        const pathName = key.split("/").filter(Boolean).pop() || vaultPath; // Get last segment of path

        // Use CN only if:
        // 1. It's not generic AND
        // 2. It looks like a domain (contains .) OR is meaningful (>8 chars)
        const useCN = cn && !isGenericCN && (cn.includes(".") || cn.length > 8);
        const name = useCN ? cn : pathName;

        logger.debug("Vault certificate name resolution", {
          cn,
          isGenericCN,
          pathName,
          selectedName: name,
          path: vaultPath,
        });

        return {
          source: "vault-kv",
          mount: mountPath,
          path: key,
          name,
          category,
          type,
          expiration: expires ? formatDateYmd(expires) : null,
          issuer,
          subject,
          location: `vault:${mountPath}${key}`,
          created_at: secret.metadata?.created_time || null,
          updated_at: secret.metadata?.updated_time || null,
        };
      }),
    );

    // Add non-null results to items
    for (const item of batchResults) {
      if (item && items.length < maxItems) {
        items.push(item);
      }
    }
  }
  return { items, truncated: keys.length > items.length };
}

async function tryListPkiCertSerials({ address, token, mountPath }) {
  try {
    const data = await vaultRequest({
      address,
      token,
      method: "LIST",
      path: `/v1/${mountPath}certs`,
    });
    const keys =
      data && data.data && Array.isArray(data.data.keys) ? data.data.keys : [];
    return keys;
  } catch (e) {
    if (e.status === 404) return [];
    throw e;
  }
}

async function readPkiCertBySerial({ address, token, mountPath, serial }) {
  const data = await vaultRequest({
    address,
    token,
    method: "GET",
    path: `/v1/${mountPath}cert/${encodeURIComponent(serial)}`,
  });
  // Response contains certificate (PEM)
  const pem =
    data && data.data && data.data.certificate ? data.data.certificate : null;
  return pem || null;
}

async function scanPki({ address, token, mount, maxItems = 500 }) {
  const mountPath = mount.path; // ends with '/'
  const serials = await tryListPkiCertSerials({ address, token, mountPath });
  const items = [];
  const BATCH_SIZE = 10;

  for (let i = 0; i < serials.length; i += BATCH_SIZE) {
    if (items.length >= maxItems) break;
    const batch = serials.slice(i, i + BATCH_SIZE);

    const batchResults = await Promise.all(
      batch.map(async (serial) => {
        if (items.length >= maxItems) return null;
        let pem = null;
        try {
          pem = await readPkiCertBySerial({
            address,
            token,
            mountPath,
            serial,
          });
        } catch (_) {
          return null;
        }
        if (!pem) return null;
        const parsed = parseCertificatePemForDatesAndNames(pem);
        const notAfter = parsed && parsed.notAfter ? parsed.notAfter : null;
        const subject = parsed && parsed.subject ? parsed.subject : null;
        const issuer = parsed && parsed.issuer ? parsed.issuer : null;
        const name = subject
          ? subject.replace(/^CN=/, "").split(",")[0].trim()
          : `${mountPath}cert/${serial}`;
        return {
          source: "vault-pki",
          mount: mountPath,
          path: `cert/${serial}`,
          name,
          category: "cert",
          type: "ssl_cert",
          expiration: notAfter ? formatDateYmd(notAfter) : null,
          issuer,
          subject,
          location: `vault:${mountPath}cert/${serial}`,
        };
      }),
    );

    // Add non-null results to items
    for (const item of batchResults) {
      if (item && items.length < maxItems) {
        items.push(item);
      }
    }
  }
  return { items, truncated: serials.length > items.length };
}

async function scanVault({
  address,
  token,
  include = { kv: true, pki: true },
  mounts: mountFilters = null,
  maxItemsPerMount = 250,
  pathPrefix = "",
}) {
  if (!address || !token) {
    logger.error("Vault scan missing required parameters", {
      hasAddress: !!address,
      hasToken: !!token,
    });
    throw new Error("address and token are required");
  }

  // Validate address format
  try {
    new URL(address);
  } catch (e) {
    logger.error("Invalid Vault address format", {
      address: address.substring(0, 50),
      error: e.message,
    });
    throw new Error(`Invalid Vault address: ${e.message}`);
  }

  logger.info("Starting Vault scan", {
    address: address.replace(/\/\/[^@]+@/, "//***@"),
    includeKV: include.kv,
    includePKI: include.pki,
    pathPrefix: pathPrefix || "none",
    mountFilters: mountFilters?.length || "none",
  });

  let mounts;
  try {
    mounts = await listMounts({ address, token });
    logger.info("Vault mounts retrieved", {
      totalMounts: mounts.length,
      mountTypes: [...new Set(mounts.map((m) => m.type))],
    });
  } catch (e) {
    logger.error("Failed to list Vault mounts", {
      address: address.replace(/\/\/[^@]+@/, "//***@"),
      error: e.message,
      errorCode: e.code,
      status: e.status,
    });
    throw new Error(`Failed to list Vault mounts: ${e.message}`);
  }

  const toScan = mounts.filter((m) => {
    if (
      mountFilters &&
      Array.isArray(mountFilters) &&
      mountFilters.length > 0
    ) {
      const match = mountFilters.some(
        (f) => String(f).toLowerCase() === String(m.path).toLowerCase(),
      );
      if (!match) return false;
    }
    if (m.type === "kv" && include.kv) {
      // Only v2 for metadata listing
      return String(m.options?.version || "1") === "2";
    }
    if (m.type === "pki" && include.pki) return true;
    return false;
  });

  logger.info("Vault mounts to scan", {
    totalMounts: mounts.length,
    mountsToScan: toScan.length,
    kvMounts: toScan.filter((m) => m.type === "kv").length,
    pkiMounts: toScan.filter((m) => m.type === "pki").length,
  });

  const results = [];
  const summary = [];

  for (const m of toScan) {
    if (m.type === "kv") {
      try {
        logger.debug("Scanning Vault KV mount", { mount: m.path });
        const { items, truncated } = await scanKvV2({
          address,
          token,
          mount: m,
          maxItems: maxItemsPerMount,
          pathPrefix,
        });
        results.push(...items);
        summary.push({
          mount: m.path,
          type: m.type,
          found: items.length,
          truncated,
        });
        logger.info("Vault KV mount scan completed", {
          mount: m.path,
          itemsFound: items.length,
          truncated,
        });
      } catch (e) {
        logger.warn("Vault KV mount scan failed", {
          mount: m.path,
          error: e.message,
          status: e.status,
        });
        summary.push({ mount: m.path, type: m.type, error: e.message });
      }
    } else if (m.type === "pki") {
      try {
        logger.debug("Scanning Vault PKI mount", { mount: m.path });
        const { items, truncated } = await scanPki({
          address,
          token,
          mount: m,
          maxItems: maxItemsPerMount,
        });
        results.push(...items);
        summary.push({
          mount: m.path,
          type: m.type,
          found: items.length,
          truncated,
        });
        logger.info("Vault PKI mount scan completed", {
          mount: m.path,
          itemsFound: items.length,
          truncated,
        });
      } catch (e) {
        logger.warn("Vault PKI mount scan failed", {
          mount: m.path,
          error: e.message,
          status: e.status,
        });
        summary.push({ mount: m.path, type: m.type, error: e.message });
      }
    }
  }

  logger.info("Vault scan completed", {
    totalItemsFound: results.length,
    mountsScanned: toScan.length,
    address: address.replace(/\/\/[^@]+@/, "//***@"),
  });

  return { items: results, summary, mounts };
}

module.exports = {
  scanVault,
  listMounts,
};

// Test-only exports for unit coverage of parsing helpers
if (process.env.NODE_ENV === "test") {
  module.exports._test = {
    parseCertificateFromUnknown,
    parseCertificatePemForDatesAndNames,
    isBase64Like,
    discoverExpiryFromObject,
    inferKindFromData,
  };
}
