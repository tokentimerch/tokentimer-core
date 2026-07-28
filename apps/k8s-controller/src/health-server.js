"use strict";

const http = require("node:http");

function writePublicResponse(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "content-length": Buffer.byteLength(body),
    "content-type": "application/json; charset=utf-8",
  });
  res.end(body);
}

function createHealthServer({
  getStatus,
  host = "0.0.0.0",
  port = 8080,
  httpModule = http,
} = {}) {
  if (typeof getStatus !== "function") {
    throw new TypeError("getStatus is required");
  }

  const server = httpModule.createServer((req, res) => {
    const pathname = new URL(req.url, "http://localhost").pathname;
    if (req.method !== "GET") {
      return writePublicResponse(res, 404, { status: "not_found" });
    }

    const status = getStatus();
    if (pathname === "/healthz") {
      return writePublicResponse(
        res,
        status.healthy ? 200 : 503,
        { status: status.healthy ? "ok" : "unavailable" },
      );
    }
    if (pathname === "/readyz") {
      return writePublicResponse(
        res,
        status.ready ? 200 : 503,
        { status: status.ready ? "ready" : "not_ready" },
      );
    }
    return writePublicResponse(res, 404, { status: "not_found" });
  });

  return {
    close() {
      if (!server.listening) return Promise.resolve();
      return new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
    listen() {
      return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.off("error", reject);
          resolve(server.address());
        });
      });
    },
    server,
  };
}

module.exports = {
  createHealthServer,
  writePublicResponse,
};
