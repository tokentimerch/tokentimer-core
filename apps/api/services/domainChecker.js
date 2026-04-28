"use strict";

const crypto = require("crypto");
const { runBinary } = require("./binaryRunner");
const {
  buildSubfinderArgs,
  parseSubfinderLine,
} = require("./subfinderAdapter");

const DEFAULT_TOOL_TIMEOUT_MS = 300000;
const DEFAULT_OVERALL_TIMEOUT_MS = 300000;
const DEFAULT_MAX_RESULTS = 10_000_000;
const DEFAULT_LOCK_TTL_MS = 420000;
const DEFAULT_TLS_TIMEOUT_MS = 5000;

const activeLookups = new Map();

function normalizeRootDomain(input) {
  const value = String(input || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/^\*\./, "")
    .replace(/\.$/, "");

  if (!value || value.length > 253) return null;
  if (!/^[a-z0-9.-]+$/.test(value)) return null;
  if (!value.includes(".")) return null;
  if (value.split(".").some((part) => part.length === 0 || part.length > 63)) {
    return null;
  }
  return value;
}

function normalizeHostname(input) {
  const value = String(input || "")
    .trim()
    .toLowerCase()
    .replace(/^dns:/, "")
    .replace(/^\*\./, "")
    .replace(/\.$/, "");

  if (!value || value.length > 253) return null;
  if (!/^[a-z0-9.-]+$/.test(value)) return null;
  if (value.split(".").some((part) => part.length === 0 || part.length > 63)) {
    return null;
  }
  return value;
}

function isWithinRootDomain(hostname, rootDomain) {
  return hostname === rootDomain || hostname.endsWith(`.${rootDomain}`);
}

function createDomainCheckerError(message, code, details = {}) {
  const error = new Error(message);
  error.code = code;
  Object.assign(error, details);
  return error;
}

/** Maps live fetch errors to stable skip `detail` values for domain-checker import (API + UI). */
function liveCertificateImportSkipDetail(tlsErr) {
  if (!tlsErr) return "live_certificate_unavailable";
  const code = tlsErr.code;
  if (code === "ENOTFOUND" || code === "ENOTDATA")
    return "live_certificate_dns_unresolved";
  if (code === "EAI_AGAIN") return "live_certificate_dns_temporary";
  if (code === "DOMAIN_CHECKER_TLS_TIMEOUT" || code === "ETIMEDOUT") {
    return "live_certificate_tls_timeout";
  }
  if (code === "ECONNRESET" || code === "EPIPE")
    return "live_certificate_connection_reset";
  if (code === "DOMAIN_CHECKER_TLS_NO_CERT")
    return "live_certificate_no_peer_cert";
  if (code === "INVALID_HOSTNAME") return "live_certificate_invalid_hostname";
  const msg = String(tlsErr.message || "");
  if (
    code === "ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE" ||
    /alert handshake failure|ssl3_read_bytes/i.test(msg)
  ) {
    return "live_certificate_tls_handshake_failed";
  }
  return "live_certificate_fetch_failed";
}

function compactStderr(stderr) {
  const value = String(stderr || "")
    .replace(/\s+/g, " ")
    .trim();
  return value ? value.slice(0, 1000) : undefined;
}

function hostId(hostname) {
  return `disc-${crypto.createHash("sha1").update(hostname).digest("hex").slice(0, 12)}`;
}

function cleanupLocks(now = Date.now()) {
  for (const [key, startedAt] of activeLookups.entries()) {
    if (now - startedAt > DEFAULT_LOCK_TTL_MS) activeLookups.delete(key);
  }
}

function addFinding(findings, rawHostname, source, rootDomain) {
  const hostname = normalizeHostname(rawHostname);
  if (!hostname || !isWithinRootDomain(hostname, rootDomain)) return false;

  const existing = findings.get(hostname);
  if (existing) {
    existing.sources.add(source);
    return false;
  }
  findings.set(hostname, { hostname, sources: new Set([source]) });
  return true;
}

function serializeFindings(findings) {
  return Array.from(findings.values())
    .map((finding) => ({
      id: hostId(finding.hostname),
      name: finding.hostname,
      domains: [finding.hostname],
      sources: Array.from(finding.sources).sort(),
      checked: true,
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function parseDiscoveryLines(linesBySource, rootDomain, options = {}) {
  const normalizedRoot = normalizeRootDomain(rootDomain);
  if (!normalizedRoot) {
    throw createDomainCheckerError("Invalid domain", "INVALID_DOMAIN");
  }

  const maxResults = Math.max(
    1,
    Number(options.maxResults || DEFAULT_MAX_RESULTS),
  );
  const findings = new Map();
  let skippedRows = 0;

  for (const [source, lines] of Object.entries(linesBySource || {})) {
    const sourceLines = Array.isArray(lines) ? lines : [];
    const parser = source === "subfinder" ? parseSubfinderLine : null;
    if (!parser) {
      skippedRows += sourceLines.length;
      continue;
    }
    for (const line of sourceLines) {
      if (findings.size >= maxResults) break;
      const rawHostname = parser(line);
      if (!addFinding(findings, rawHostname, source, normalizedRoot))
        skippedRows += 1;
    }
  }

  return { items: serializeFindings(findings), skippedRows };
}

async function fetchHostnameCertificate(hostname, options = {}) {
  const tls = require("tls");
  const { X509Certificate } = require("crypto");
  const normalizedHostname = normalizeHostname(hostname);
  if (!normalizedHostname) {
    throw createDomainCheckerError("Invalid hostname", "INVALID_HOSTNAME");
  }
  const timeoutMs = Math.max(
    1000,
    Number(
      options.timeoutMs ||
        process.env.DOMAIN_CHECKER_TLS_TIMEOUT_MS ||
        DEFAULT_TLS_TIMEOUT_MS,
    ),
  );

  const cert = await new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: normalizedHostname,
        port: 443,
        servername: normalizedHostname,
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      () => {
        const peerCert = socket.getPeerCertificate(true);
        socket.destroy();
        resolve(peerCert);
      },
    );
    socket.on("error", reject);
    socket.on("timeout", () => {
      socket.destroy();
      reject(
        createDomainCheckerError(
          "TLS certificate lookup timed out",
          "DOMAIN_CHECKER_TLS_TIMEOUT",
        ),
      );
    });
  });

  if (!cert || !cert.valid_to) {
    throw createDomainCheckerError(
      "No TLS certificate returned",
      "DOMAIN_CHECKER_TLS_NO_CERT",
    );
  }

  let x509 = null;
  try {
    if (cert.raw) x509 = new X509Certificate(cert.raw);
  } catch (_err) {
    x509 = null;
  }

  return {
    issuer: x509?.issuer || cert.issuer?.O || null,
    subject: x509?.subject || cert.subject?.CN || normalizedHostname,
    serialNumber: x509?.serialNumber || cert.serialNumber || null,
    validFrom: cert.valid_from ? new Date(cert.valid_from) : null,
    validTo: cert.valid_to ? new Date(cert.valid_to) : null,
    fingerprint: cert.fingerprint256 || cert.fingerprint || null,
  };
}

async function lookupDomain(domain, options = {}) {
  const normalizedRoot = normalizeRootDomain(domain);
  if (!normalizedRoot) {
    throw createDomainCheckerError("Invalid domain", "INVALID_DOMAIN");
  }

  cleanupLocks();
  const workspaceId = options.workspaceId || "global";
  const lockKey = `${workspaceId}:${normalizedRoot}`;
  if (activeLookups.has(lockKey)) {
    throw createDomainCheckerError(
      "A domain checker lookup is already running for this workspace",
      "DOMAIN_CHECKER_BUSY",
      {
        status: 409,
        retryAfterSec: 60,
      },
    );
  }
  activeLookups.set(lockKey, Date.now());

  const toolTimeoutMs = Math.max(
    1000,
    Number(
      options.toolTimeoutMs ||
        process.env.DOMAIN_CHECKER_TOOL_TIMEOUT_MS ||
        DEFAULT_TOOL_TIMEOUT_MS,
    ),
  );
  const overallTimeoutMs = Math.max(
    toolTimeoutMs,
    Number(
      options.timeoutMs ||
        process.env.DOMAIN_CHECKER_OVERALL_TIMEOUT_MS ||
        DEFAULT_OVERALL_TIMEOUT_MS,
    ),
  );
  const maxResults = Math.max(
    1,
    Number(
      options.maxResults ||
        process.env.DOMAIN_CHECKER_MAX_RESULTS ||
        DEFAULT_MAX_RESULTS,
    ),
  );
  const subfinderBin =
    options.subfinderBin || process.env.SUBFINDER_BIN || "subfinder";
  const runBinaryImpl = options.runBinary || runBinary;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), overallTimeoutMs);
  const findings = new Map();
  const startedAt = Date.now();
  let truncated = false;

  const ingest = (source, parser) => (line) => {
    if (findings.size >= maxResults) {
      truncated = true;
      controller.abort();
      return;
    }
    addFinding(findings, parser(line), source, normalizedRoot);
    if (findings.size >= maxResults) {
      truncated = true;
      controller.abort();
    }
  };

  const subfinderAll = Boolean(options.subfinderAll);
  const tools = [
    {
      name: "subfinder",
      bin: subfinderBin,
      args: buildSubfinderArgs(normalizedRoot, { all: subfinderAll }),
      parser: parseSubfinderLine,
    },
  ];
  try {
    const settled = await Promise.allSettled(
      tools.map((tool) =>
        runBinaryImpl({
          bin: tool.bin,
          args: tool.args,
          timeoutMs: toolTimeoutMs,
          signal: controller.signal,
          onLine: ingest(tool.name, tool.parser),
        }).then((result) => ({ tool: tool.name, ...result })),
      ),
    );

    const toolErrors = settled
      .map((result, index) => {
        if (result.status === "fulfilled") return null;
        const reason = result.reason || {};
        const tool = tools[index];
        return {
          tool: tool.name,
          code: reason.code || "DOMAIN_CHECKER_TOOL_ERROR",
          message: reason.message || "Discovery tool failed",
          bin: tool.bin,
          args: Array.isArray(reason.args) ? reason.args : tool.args,
          exitCode: reason.exitCode ?? null,
          durationMs: reason.durationMs ?? null,
          stderr: compactStderr(reason.stderr),
        };
      })
      .filter(Boolean);

    if (toolErrors.length === tools.length && findings.size === 0) {
      const timeoutOnly = toolErrors.every((error) =>
        ["DOMAIN_CHECKER_ABORTED", "DOMAIN_CHECKER_TOOL_TIMEOUT"].includes(
          error.code,
        ),
      );
      throw createDomainCheckerError(
        timeoutOnly
          ? "Domain checker lookup timed out"
          : "All domain discovery sources failed",
        timeoutOnly ? "DOMAIN_CHECKER_TIMEOUT" : "DOMAIN_CHECKER_FAILED",
        { status: timeoutOnly ? 504 : 503, toolErrors },
      );
    }

    return {
      domain: normalizedRoot,
      source: tools.map((tool) => tool.name).join(","),
      items: serializeFindings(findings),
      partial: toolErrors.length > 0 || truncated,
      toolErrors,
      meta: {
        tools: tools.map((tool) => tool.name),
        toolsSucceeded: tools.length - toolErrors.length,
        toolsFailed: toolErrors.length,
        truncated,
        durationMs: Date.now() - startedAt,
        maxResults,
      },
    };
  } finally {
    clearTimeout(timer);
    activeLookups.delete(lockKey);
  }
}

module.exports = {
  normalizeRootDomain,
  normalizeHostname,
  isWithinRootDomain,
  parseDiscoveryLines,
  lookupDomain,
  fetchHostnameCertificate,
  liveCertificateImportSkipDetail,
};
