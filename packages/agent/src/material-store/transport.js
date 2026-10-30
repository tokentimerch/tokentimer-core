"use strict";
const https = require("node:https");
const http = require("node:http");
const { failure } = require("./index");

// No redirects, proxy discovery, raw response errors or SDK diagnostics. An
// absolute deadline includes DNS, TLS and an incomplete response body.
function requestJson(
  url,
  {
    method = "GET",
    headers = {},
    body,
    timeoutMs = 10000,
    maxBytes = 300000,
    ca,
  } = {},
) {
  const payload =
    body === undefined
      ? null
      : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const request = (url.protocol === "https:" ? https : http).request(
      url,
      {
        method,
        rejectUnauthorized: true,
        ca,
        headers: {
          ...headers,
          ...(payload ? { "Content-Length": payload.length } : {}),
        },
      },
      (response) => {
        const chunks = [];
        let bytes = 0;
        response.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes > maxBytes) request.destroy();
          else chunks.push(chunk);
        });
        response.on("error", () =>
          reject(failure("material_store_unavailable")),
        );
        response.on("end", () => {
          let json = null;
          // Error bodies may contain secrets, and must never escape this client.
          if (response.statusCode >= 200 && response.statusCode < 300) {
            try {
              json = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            } catch {
              reject(failure("material_response_invalid"));
              return;
            }
          }
          resolve({ status: response.statusCode, json });
        });
      },
    );
    const timer = setTimeout(() => request.destroy(), timeoutMs);
    request.on("close", () => clearTimeout(timer));
    request.on("error", () => reject(failure("material_store_unavailable")));
    if (payload) request.write(payload);
    request.end();
  });
}
module.exports = { requestJson };
