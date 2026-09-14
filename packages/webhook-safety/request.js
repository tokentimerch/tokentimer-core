"use strict";

const http = require("node:http");
const https = require("node:https");
const dns = require("node:dns/promises");
const { isIP } = require("node:net");

const MAX_RESPONSE_BYTES = 64 * 1024;

class WebhookRequestError extends Error {
  constructor(message, { code, status } = {}) {
    super(message);
    this.name =
      code === "WEBHOOK_TIMEOUT" ? "AbortError" : "WebhookRequestError";
    this.code = code;
    if (status != null) this.status = status;
  }
}

function buildHostHeader(url) {
  const hostname = url.hostname;
  const family = isIP(hostname);
  const host = family === 6 ? `[${hostname}]` : hostname;
  if (!url.port) return host;
  return `${host}:${url.port}`;
}

function pickPinnedAddress(addresses) {
  const v4 = addresses.find((row) => Number(row.family) === 4);
  if (v4) return { address: v4.address, family: 4 };
  const first = addresses[0];
  const family = Number(first.family) || isIP(first.address);
  return { address: first.address, family };
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
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === "string") return Buffer.from(body, "utf8");
  return Buffer.from(JSON.stringify(body), "utf8");
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
    const timeoutMs = Number(options.timeoutMs) || 5000;
    const enforce = shouldEnforcePrivateIpCheck();
    let addresses;

    if (isIP(host)) {
      addresses = [{ address: host, family: isIP(host) }];
    } else {
      const lookupAll = options.lookupAll || defaultLookupAll;
      try {
        addresses = normalizeLookupRows(await lookupAll(host));
      } catch (err) {
        throw new WebhookRequestError(
          err.message || `Failed to resolve ${host}`,
          { code: "WEBHOOK_DNS_UNRESOLVED" },
        );
      }
    }

    if (!addresses.length) {
      throw new WebhookRequestError(`Webhook blocked: ${host} did not resolve`, {
        code: "WEBHOOK_DNS_UNRESOLVED",
      });
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

    const pinned = pickPinnedAddress(addresses);
    const bodyBuffer = encodeBody(options.body);
    const lib = url.protocol === "https:" ? https : http;
    const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
    const servername = url.hostname;
    const extraHeaders = options.headers || {};

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

    return await new Promise((resolve, reject) => {
      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        try {
          agent.destroy();
        } catch (_) {
          /* ignore */
        }
        fn(value);
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
          ...(url.protocol === "https:" ? { servername } : {}),
        },
        (res) => {
          const chunks = [];
          let size = 0;
          res.on("data", (chunk) => {
            size += chunk.length;
            if (size > MAX_RESPONSE_BYTES) {
              req.destroy();
              finish(
                reject,
                new WebhookRequestError("Webhook response too large", {
                  code: "WEBHOOK_UNREACHABLE",
                }),
              );
            } else {
              chunks.push(chunk);
            }
          });
          res.on("end", () => {
            const bodyText = Buffer.concat(chunks).toString("utf8");
            const status = res.statusCode || 0;
            if (status >= 300 && status < 400) {
              finish(
                reject,
                new WebhookRequestError(
                  `Webhook blocked: HTTP ${status} redirect refused`,
                  { code: "WEBHOOK_REDIRECT_REFUSED", status },
                ),
              );
              return;
            }
            finish(resolve, { status, bodyText });
          });
        },
      );

      req.on("timeout", () => {
        req.destroy();
        finish(
          reject,
          new WebhookRequestError(
            `Timed out (${Math.max(1, Math.round(timeoutMs / 1000))}s)`,
            { code: "WEBHOOK_TIMEOUT" },
          ),
        );
      });

      req.on("error", (err) => {
        if (err && err.code === "ABORT_ERR") {
          finish(
            reject,
            new WebhookRequestError(
              `Timed out (${Math.max(1, Math.round(timeoutMs / 1000))}s)`,
              { code: "WEBHOOK_TIMEOUT" },
            ),
          );
          return;
        }
        finish(
          reject,
          new WebhookRequestError(err.message || "Webhook unreachable", {
            code: "WEBHOOK_UNREACHABLE",
          }),
        );
      });

      const signal = options.signal;
      if (signal) {
        if (signal.aborted) {
          req.destroy();
          finish(
            reject,
            new WebhookRequestError(
              `Timed out (${Math.max(1, Math.round(timeoutMs / 1000))}s)`,
              { code: "WEBHOOK_TIMEOUT" },
            ),
          );
          return;
        }
        signal.addEventListener(
          "abort",
          () => {
            req.destroy();
          },
          { once: true },
        );
      }

      req.end(bodyBuffer);
    });
  };
}

module.exports = {
  WebhookRequestError,
  createPostWebhook,
};
