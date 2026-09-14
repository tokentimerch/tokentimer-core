"use strict";

const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const tls = require("node:tls");
const dns = require("node:dns/promises");
const { isIP } = require("node:net");

const MAX_RESPONSE_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 5000;

class WebhookRequestError extends Error {
  constructor(message, { code, status } = {}) {
    super(message);
    this.name =
      code === "WEBHOOK_TIMEOUT" ? "AbortError" : "WebhookRequestError";
    this.code = code;
    if (status != null) this.status = status;
  }
}

function timeoutMessage(timeoutMs) {
  return `Timed out (${Math.max(1, Math.round(timeoutMs / 1000))}s)`;
}

function destinationPort(url) {
  if (url.port) return Number(url.port);
  return url.protocol === "https:" ? 443 : 80;
}

function buildHostHeader(url) {
  const hostname = url.hostname;
  const family = isIP(hostname);
  const host = family === 6 ? `[${hostname}]` : hostname;
  if (!url.port) return host;
  return `${host}:${url.port}`;
}

function connectAuthority(hostname, port) {
  const family = isIP(hostname);
  const host = family === 6 ? `[${hostname}]` : hostname;
  return `${host}:${port}`;
}

function orderPinnedAddresses(addresses) {
  const rows = normalizeLookupRows(addresses);
  const v4 = [];
  const rest = [];
  const seen = new Set();
  for (const row of rows) {
    const key = `${row.family}/${row.address}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (row.family === 4) v4.push(row);
    else rest.push(row);
  }
  return [...v4, ...rest];
}

function normalizeLookupRows(rows) {
  if (!Array.isArray(rows)) return [];
  return rows
    .map((row) => {
      if (typeof row === "string") {
        return { address: row, family: isIP(row) };
      }
      const address = row && row.address;
      if (!address) return null;
      return {
        address,
        family: Number(row.family) || isIP(address),
      };
    })
    .filter((row) => row && row.address && row.family);
}

async function defaultLookupAll(hostname) {
  try {
    const results = await dns.lookup(hostname, { all: true, verbatim: true });
    return normalizeLookupRows(results);
  } catch (err) {
    if (err && (err.code === "ENOTFOUND" || err.code === "ENODATA")) {
      return [];
    }
    throw err;
  }
}

function encodeBody(body) {
  if (body == null) return Buffer.from("{}", "utf8");
  if (Buffer.isBuffer(body)) return Buffer.from(body);
  if (typeof body === "string") return Buffer.from(body, "utf8");
  return Buffer.from(JSON.stringify(body), "utf8");
}

function firstEnv(names) {
  for (const name of names) {
    const value = process.env[name];
    if (value && String(value).trim()) return String(value).trim();
  }
  return "";
}

function envFlag(name) {
  const value = String(process.env[name] || "")
    .trim()
    .toLowerCase();
  return value === "1" || value === "true" || value === "yes";
}

function parseNoProxyEntry(raw) {
  let entry = String(raw || "")
    .trim()
    .toLowerCase();
  if (!entry) return null;
  if (entry === "*") return { all: true };
  if (entry.startsWith("*.")) entry = entry.slice(1);

  let host = entry;
  let port = null;
  if (entry.startsWith("[")) {
    const close = entry.indexOf("]");
    if (close !== -1) {
      host = entry.slice(1, close);
      if (entry[close + 1] === ":" && /^\d+$/.test(entry.slice(close + 2))) {
        port = Number(entry.slice(close + 2));
      }
    }
  } else {
    const colon = entry.lastIndexOf(":");
    if (colon !== -1 && /^\d+$/.test(entry.slice(colon + 1))) {
      host = entry.slice(0, colon);
      port = Number(entry.slice(colon + 1));
    }
  }
  return { host, port };
}

function hostMatchesNoProxy(hostname, noProxyRaw, destPort) {
  if (!noProxyRaw) return false;
  const host = String(hostname || "")
    .trim()
    .toLowerCase();
  if (!host) return false;
  const dest =
    destPort == null || destPort === "" ? null : Number(destPort);
  const entries = String(noProxyRaw)
    .split(/[\s,]+/)
    .map(parseNoProxyEntry)
    .filter(Boolean);
  for (const entry of entries) {
    if (entry.all) return true;
    if (entry.port != null && dest !== entry.port) continue;
    const needle = entry.host;
    if (!needle) continue;
    if (needle.startsWith(".")) {
      const bare = needle.slice(1);
      if (host === bare || host.endsWith(needle)) return true;
      continue;
    }
    if (host === needle || host.endsWith(`.${needle}`)) return true;
  }
  return false;
}

function proxyAuthorization(proxyUrl) {
  if (!proxyUrl.username && !proxyUrl.password) return "";
  const user = decodeURIComponent(proxyUrl.username || "");
  const pass = decodeURIComponent(proxyUrl.password || "");
  return `Basic ${Buffer.from(`${user}:${pass}`, "utf8").toString("base64")}`;
}

/**
 * Resolve the outbound forward-proxy for a webhook URL.
 * - "always": honor HTTP(S)_PROXY like axios (worker delivery).
 * - "node-flag": only when NODE_USE_ENV_PROXY is set (API Test / fetch parity).
 * - "never": skip proxy env entirely.
 */
function resolveOutboundProxy(url, proxyMode = "always") {
  if (proxyMode === "never") return null;
  if (proxyMode === "node-flag" && !envFlag("NODE_USE_ENV_PROXY")) return null;

  const proxyRaw =
    url.protocol === "https:"
      ? firstEnv(["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"])
      : firstEnv(["HTTP_PROXY", "http_proxy"]);
  if (!proxyRaw) return null;

  let proxyUrl;
  try {
    proxyUrl = new URL(proxyRaw);
  } catch (_) {
    throw new WebhookRequestError("Invalid HTTP proxy URL", {
      code: "WEBHOOK_UNREACHABLE",
    });
  }
  if (proxyUrl.protocol !== "http:" && proxyUrl.protocol !== "https:") {
    throw new WebhookRequestError("HTTP proxy URL must be http(s)", {
      code: "WEBHOOK_UNREACHABLE",
    });
  }
  if (
    hostMatchesNoProxy(
      url.hostname,
      firstEnv(["NO_PROXY", "no_proxy"]),
      destinationPort(url),
    )
  ) {
    return null;
  }
  return proxyUrl;
}

function createDeadline(timeoutMs, externalSignal) {
  const controller = new AbortController();
  const started = Date.now();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let onExternalAbort = null;
  if (externalSignal) {
    if (externalSignal.aborted) controller.abort();
    else {
      onExternalAbort = () => controller.abort();
      externalSignal.addEventListener("abort", onExternalAbort, {
        once: true,
      });
    }
  }
  return {
    signal: controller.signal,
    remainingMs() {
      // http.ClientRequest treats timeout 0 as unlimited; keep a 1ms floor.
      return Math.max(1, timeoutMs - (Date.now() - started));
    },
    dispose() {
      clearTimeout(timer);
      if (externalSignal && onExternalAbort) {
        externalSignal.removeEventListener("abort", onExternalAbort);
      }
    },
  };
}

function timeoutError(timeoutMs) {
  return new WebhookRequestError(timeoutMessage(timeoutMs), {
    code: "WEBHOOK_TIMEOUT",
  });
}

function extraCaBundle() {
  const extraPath = process.env.NODE_EXTRA_CA_CERTS;
  if (!extraPath) return null;
  try {
    const extra = fs.readFileSync(extraPath, "utf8");
    return extra.trim() ? extra : null;
  } catch (_err) {
    return null;
  }
}

function tlsTrustOptions() {
  const extra = extraCaBundle();
  if (!extra) return { rejectUnauthorized: true };
  return {
    rejectUnauthorized: true,
    ca: [...tls.rootCertificates, extra],
  };
}

const RETRYABLE_CONNECT_CODES = new Set([
  "ECONNREFUSED",
  "ENETUNREACH",
  "EHOSTUNREACH",
  "EADDRNOTAVAIL",
]);

function wrapUnreachable(err) {
  if (err instanceof WebhookRequestError) return err;
  const wrapped = new WebhookRequestError(
    (err && err.message) || "Webhook unreachable",
    { code: "WEBHOOK_UNREACHABLE" },
  );
  if (err && err.code) wrapped.causeCode = err.code;
  return wrapped;
}

function isRetryableConnectFailure(err) {
  if (!err) return false;
  if (err.retryConnect) return true;
  if (
    err.code === "WEBHOOK_REDIRECT_REFUSED" ||
    err.code === "WEBHOOK_TIMEOUT" ||
    err.code === "WEBHOOK_PRIVATE_IP_BLOCKED" ||
    err.code === "WEBHOOK_DNS_UNRESOLVED" ||
    err.code === "WEBHOOK_INVALID_URL" ||
    err.code === "WEBHOOK_INVALID_SCHEME"
  ) {
    return false;
  }
  const cause = err.causeCode || err.code;
  return RETRYABLE_CONNECT_CODES.has(cause);
}

function attachAbort(target, signal, onAbort) {
  if (!signal || !target) return () => {};
  if (signal.aborted) {
    try {
      target.destroy();
    } catch (_) {
      /* ignore */
    }
    onAbort();
    return () => {};
  }
  const listener = () => {
    try {
      target.destroy();
    } catch (_) {
      /* ignore */
    }
    onAbort();
  };
  signal.addEventListener("abort", listener, { once: true });
  return () => signal.removeEventListener("abort", listener);
}

function attachCommonRequestHandlers(req, { timeoutMs, signal, finish }) {
  req.on("timeout", () => {
    req.destroy();
    finish("reject", timeoutError(timeoutMs));
  });

  req.on("error", (err) => {
    if (err && (err.code === "ABORT_ERR" || err.code === "WEBHOOK_TIMEOUT")) {
      finish("reject", timeoutError(timeoutMs));
      return;
    }
    if (err instanceof WebhookRequestError) {
      finish("reject", err);
      return;
    }
    finish("reject", wrapUnreachable(err));
  });

  attachAbort(req, signal, () => finish("reject", timeoutError(timeoutMs)));
}

function collectResponse(req, res, finish) {
  const chunks = [];
  let size = 0;
  const fail = (err) => {
    try {
      req.destroy();
    } catch (_) {
      /* ignore */
    }
    if (err && err.code === "WEBHOOK_TIMEOUT") {
      finish("reject", err);
      return;
    }
    finish("reject", wrapUnreachable(err));
  };

  res.on("data", (chunk) => {
    size += chunk.length;
    if (size > MAX_RESPONSE_BYTES) {
      fail(
        new WebhookRequestError("Webhook response too large", {
          code: "WEBHOOK_UNREACHABLE",
        }),
      );
      return;
    }
    chunks.push(chunk);
  });
  res.on("end", () => {
    const bodyText = Buffer.concat(chunks).toString("utf8");
    const status = res.statusCode || 0;
    if (status >= 300 && status < 400) {
      finish(
        "reject",
        new WebhookRequestError(
          `Webhook blocked: HTTP ${status} redirect refused`,
          { code: "WEBHOOK_REDIRECT_REFUSED", status },
        ),
      );
      return;
    }
    finish("resolve", { status, bodyText });
  });
  res.on("error", (err) => fail(err));
  res.on("aborted", () => fail(new Error("Webhook response aborted")));
  res.on("close", () => {
    if (!res.complete) fail(new Error("Webhook response closed early"));
  });
}

function sendPinnedRequest({
  url,
  port,
  pinned,
  bodyBuffer,
  extraHeaders,
  timeoutMs,
  signal,
}) {
  const lib = url.protocol === "https:" ? https : http;
  const agent = new lib.Agent({
    keepAlive: false,
    lookup(hostname, lookupOptions, callback) {
      if (typeof lookupOptions === "function") {
        callback = lookupOptions;
      }
      const opts =
        typeof lookupOptions === "function" ? {} : lookupOptions || {};
      if (opts.all) {
        callback(null, [{ address: pinned.address, family: pinned.family }]);
        return;
      }
      callback(null, pinned.address, pinned.family);
    },
  });

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (kind, value) => {
      if (settled) return;
      settled = true;
      try {
        agent.destroy();
      } catch (_) {
        /* ignore */
      }
      if (kind === "resolve") resolve(value);
      else reject(value);
    };

    const req = lib.request(
      {
        agent,
        protocol: url.protocol,
        hostname: pinned.address,
        family: pinned.family,
        port,
        method: "POST",
        path: `${url.pathname || "/"}${url.search || ""}`,
        headers: {
          Host: buildHostHeader(url),
          "Content-Type": "application/json",
          "Content-Length": String(bodyBuffer.length),
          ...extraHeaders,
        },
        timeout: timeoutMs,
        ...(url.protocol === "https:"
          ? { servername: url.hostname, ...tlsTrustOptions() }
          : {}),
      },
      (res) => collectResponse(req, res, finish),
    );

    attachCommonRequestHandlers(req, { timeoutMs, signal, finish });
    req.end(bodyBuffer);
  });
}

function sendProxiedRequest({
  url,
  port,
  pinned,
  proxyUrl,
  bodyBuffer,
  extraHeaders,
  timeoutMs,
  signal,
}) {
  const headers = {
    Host: buildHostHeader(url),
    "Content-Type": "application/json",
    "Content-Length": String(bodyBuffer.length),
    ...extraHeaders,
  };
  const proxyAuth = proxyAuthorization(proxyUrl);
  if (proxyAuth) headers["Proxy-Authorization"] = proxyAuth;

  const hopHost = pinned ? pinned.address : url.hostname;
  const authority = connectAuthority(hopHost, port);

  if (url.protocol === "http:") {
    const proxyLib = proxyUrl.protocol === "https:" ? https : http;
    const proxyPort =
      Number(proxyUrl.port) || (proxyUrl.protocol === "https:" ? 443 : 80);
    const absolutePath = `${url.protocol}//${authority}${url.pathname || "/"}${url.search || ""}`;

    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (kind, value) => {
        if (settled) return;
        settled = true;
        if (kind === "resolve") resolve(value);
        else reject(value);
      };

      const req = proxyLib.request(
        {
          protocol: proxyUrl.protocol,
          hostname: proxyUrl.hostname,
          port: proxyPort,
          method: "POST",
          path: absolutePath,
          headers,
          timeout: timeoutMs,
        },
        (res) => collectResponse(req, res, finish),
      );

      attachCommonRequestHandlers(req, { timeoutMs, signal, finish });
      req.end(bodyBuffer);
    });
  }

  const proxyLib = proxyUrl.protocol === "https:" ? https : http;
  const proxyPort =
    Number(proxyUrl.port) || (proxyUrl.protocol === "https:" ? 443 : 80);
  const connectHeaders = { Host: authority };
  if (proxyAuth) connectHeaders["Proxy-Authorization"] = proxyAuth;

  return new Promise((resolve, reject) => {
    let settled = false;
    let tlsSocket = null;
    const finish = (kind, value) => {
      if (settled) return;
      settled = true;
      try {
        if (tlsSocket) tlsSocket.destroy();
      } catch (_) {
        /* ignore */
      }
      if (kind === "resolve") resolve(value);
      else reject(value);
    };

    const connectReq = proxyLib.request({
      protocol: proxyUrl.protocol,
      hostname: proxyUrl.hostname,
      port: proxyPort,
      method: "CONNECT",
      path: authority,
      headers: connectHeaders,
      timeout: timeoutMs,
    });

    connectReq.on("connect", (res, socket, head) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        const connectErr = new WebhookRequestError(
          `Proxy CONNECT failed (${res.statusCode || 0})`,
          { code: "WEBHOOK_UNREACHABLE" },
        );
        connectErr.retryConnect = true;
        finish("reject", connectErr);
        return;
      }
      if (head && head.length) socket.unshift(head);

      tlsSocket = tls.connect({
        socket,
        servername: url.hostname,
        ...tlsTrustOptions(),
      });
      tlsSocket.setTimeout(timeoutMs);
      tlsSocket.once("timeout", () => {
        tlsSocket.destroy();
        finish("reject", timeoutError(timeoutMs));
      });
      attachAbort(tlsSocket, signal, () =>
        finish("reject", timeoutError(timeoutMs)),
      );
      tlsSocket.once("secureConnect", () => {
        const req = http.request(
          {
            hostname: url.hostname,
            port,
            method: "POST",
            path: `${url.pathname || "/"}${url.search || ""}`,
            headers: {
              Host: buildHostHeader(url),
              "Content-Type": "application/json",
              "Content-Length": String(bodyBuffer.length),
              ...extraHeaders,
            },
            timeout: timeoutMs,
            createConnection: (_opts, callback) => {
              callback(null, tlsSocket);
            },
          },
          (res2) => collectResponse(req, res2, finish),
        );
        attachCommonRequestHandlers(req, { timeoutMs, signal, finish });
        req.end(bodyBuffer);
      });
      tlsSocket.on("error", (err) => {
        finish("reject", wrapUnreachable(err));
      });
    });

    attachCommonRequestHandlers(connectReq, { timeoutMs, signal, finish });
    connectReq.end();
  });
}

async function lookupWithDeadline(lookupAll, host, deadline, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      lookupAll(host),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(timeoutError(timeoutMs));
        }, deadline.remainingMs());
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function sendWithAddressFallback(
  addresses,
  sendOne,
  deadline,
  timeoutMs,
) {
  let lastError;
  for (let i = 0; i < addresses.length; i += 1) {
    if (deadline.signal.aborted) throw timeoutError(timeoutMs);
    try {
      return await sendOne(addresses[i]);
    } catch (err) {
      if (deadline.signal.aborted) throw timeoutError(timeoutMs);
      if (!isRetryableConnectFailure(err) || i === addresses.length - 1) {
        throw err;
      }
      lastError = err;
    }
  }
  throw (
    lastError ||
    new WebhookRequestError("Webhook unreachable", {
      code: "WEBHOOK_UNREACHABLE",
    })
  );
}

function createPostWebhook(policy) {
  const {
    isPrivateOrReservedIP,
    shouldEnforcePrivateIpCheck,
    canonicalizeHost,
  } = policy;

  return async function postWebhook(rawUrl, options = {}) {
    let url;
    try {
      url = new URL(rawUrl);
    } catch (_) {
      throw new WebhookRequestError("Invalid webhook URL", {
        code: "WEBHOOK_INVALID_URL",
      });
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new WebhookRequestError("Webhook URL must be http(s)", {
        code: "WEBHOOK_INVALID_SCHEME",
      });
    }

    const host = canonicalizeHost(url.hostname);
    const timeoutMs = Number(options.timeoutMs) || DEFAULT_TIMEOUT_MS;
    const enforce = shouldEnforcePrivateIpCheck();
    const proxyMode = options.proxyMode || "always";
    const proxyUrl = resolveOutboundProxy(url, proxyMode);
    const deadline = createDeadline(timeoutMs, options.signal);
    const port = url.port
      ? Number(url.port)
      : url.protocol === "https:"
        ? 443
        : 80;

    try {
      let addresses;

      if (isIP(host)) {
        addresses = [{ address: host, family: isIP(host) }];
      } else {
        const lookupAll = options.lookupAll || defaultLookupAll;
        try {
          addresses = normalizeLookupRows(
            await lookupWithDeadline(lookupAll, host, deadline, timeoutMs),
          );
        } catch (err) {
          if (err instanceof WebhookRequestError) throw err;
          if (proxyUrl && !enforce) {
            addresses = [];
          } else {
            throw new WebhookRequestError(
              err.message || `Failed to resolve ${host}`,
              { code: "WEBHOOK_DNS_UNRESOLVED" },
            );
          }
        }
      }

      if (!addresses.length) {
        if (enforce || !proxyUrl) {
          throw new WebhookRequestError(
            `Webhook blocked: ${host} did not resolve`,
            { code: "WEBHOOK_DNS_UNRESOLVED" },
          );
        }
      }

      if (enforce) {
        for (const row of addresses) {
          if (isPrivateOrReservedIP(row.address)) {
            if (typeof options.onBlocked === "function") {
              options.onBlocked({ hostname: host, resolvedIP: row.address });
            }
            throw new WebhookRequestError(
              `Webhook blocked: ${host} resolves to a private/reserved IP. Self-hosted deployments can set WEBHOOK_ALLOW_PRIVATE_IPS=true to allow private webhook destinations.`,
              { code: "WEBHOOK_PRIVATE_IP_BLOCKED" },
            );
          }
        }
      }

      const bodyBuffer = encodeBody(options.body);
      const extraHeaders = options.headers || {};
      const candidates = orderPinnedAddresses(addresses);

      const sendOne = (pinned) =>
        proxyUrl
          ? sendProxiedRequest({
              url,
              port,
              pinned,
              proxyUrl,
              bodyBuffer,
              extraHeaders,
              timeoutMs: deadline.remainingMs(),
              signal: deadline.signal,
            })
          : sendPinnedRequest({
              url,
              port,
              pinned,
              bodyBuffer,
              extraHeaders,
              timeoutMs: deadline.remainingMs(),
              signal: deadline.signal,
            });

      if (proxyUrl && candidates.length === 0) {
        return await sendOne(null);
      }

      return await sendWithAddressFallback(
        candidates,
        sendOne,
        deadline,
        timeoutMs,
      );
    } finally {
      deadline.dispose();
    }
  };
}

module.exports = {
  WebhookRequestError,
  createPostWebhook,
  resolveOutboundProxy,
  hostMatchesNoProxy,
  orderPinnedAddresses,
  destinationPort,
};
