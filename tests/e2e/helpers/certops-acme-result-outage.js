"use strict";
/** Owned loopback transport fault, not a replacement API or result producer.
 * The caller must independently bind an actual native job/claim before arming.
 * No request bodies, credentials or signed envelopes are retained in receipts. */
const assert = require("node:assert/strict");
const http = require("node:http");
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const MAX_BYTES = 1048576;
const PATH =
  /^\/api\/v1\/certops\/agent\/(?:register|heartbeat|jobs\/(?:claim|results|[a-f0-9-]{36}\/(?:lease|logs)))$/;

function upstream(value) {
  const parsed = new URL(value);
  assert.ok(parsed.protocol === "http:" && parsed.hostname === "127.0.0.1");
  assert.ok(parsed.pathname === "/" && !parsed.search && !parsed.hash);
  assert.ok(!parsed.username && !parsed.password);
  const port = Number(parsed.port);
  assert.ok(Number.isInteger(port) && port > 0 && port <= 65535);
  return { hostname: "127.0.0.1", port };
}

async function startResultOutageGateway({ upstreamUrl }) {
  const target = upstream(upstreamUrl);
  const sockets = new Set(),
    requests = new Set();
  let armed = null,
    available = false,
    closed = false,
    closing = null;
  let refusedResults = 0,
    forwardedResults = 0,
    mismatchedResults = 0;
  const server = http.createServer((request, response) => {
    // Restrict the original relative request path before URL parsing, which
    // otherwise normalizes dot segments and could widen the proxy authority.
    if (request.method !== "POST" || !PATH.test(request.url)) {
      response.writeHead(404).end();
      return;
    }
    if (
      armed &&
      !available &&
      request.url === "/api/v1/certops/agent/jobs/claim"
    ) {
      response.writeHead(503).end();
      return;
    }
    const chunks = [];
    let size = 0,
      exceeded = false;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BYTES) exceeded = true;
      else chunks.push(chunk);
    });
    request.on("error", () => response.destroy());
    request.on("end", () => {
      if (response.destroyed) return;
      if (exceeded) {
        response.writeHead(413).end();
        return;
      }
      const bytes = Buffer.concat(chunks);
      let matching = false;
      if (request.url === "/api/v1/certops/agent/jobs/results" && armed) {
        let envelope;
        try {
          envelope = JSON.parse(bytes.toString("utf8"));
        } catch {
          /* Refuse malformed signed transport. */
        }
        matching =
          envelope?.messageType === "result" &&
          envelope.body?.jobId === armed.jobId &&
          envelope.body?.claimId === armed.claimId;
        if (envelope?.messageType !== "evidence" && !matching) {
          mismatchedResults++;
          response.writeHead(409).end();
          return;
        }
        if (matching && !available) {
          refusedResults++;
          // A real transient HTTP refusal forces the production durable
          // outbox path; no upstream result or successful ACK is invented.
          response.writeHead(503, { "content-type": "application/json" });
          response.end('{"error":"owned qualification transport unavailable"}');
          return;
        }
      }
      const headers = { ...request.headers, host: `127.0.0.1:${target.port}` };
      delete headers.connection;
      delete headers["transfer-encoding"];
      headers["content-length"] = String(bytes.length);
      const outgoing = http.request(
        { ...target, method: "POST", path: request.url, headers, agent: false },
        (incoming) => {
          if (matching) forwardedResults++;
          response.writeHead(incoming.statusCode, {
            "content-type":
              incoming.headers["content-type"] || "application/json",
          });
          incoming.pipe(response);
          incoming.on("error", () => response.destroy());
        },
      );
      requests.add(outgoing);
      outgoing.once("close", () => requests.delete(outgoing));
      response.once("close", () => {
        if (!outgoing.destroyed) outgoing.destroy();
      });
      outgoing.setTimeout(30000, () => outgoing.destroy());
      outgoing.on("error", () => {
        if (!response.headersSent && !response.destroyed)
          response.writeHead(502).end();
        else response.destroy();
      });
      // Original signed bytes are forwarded exactly, never parsed/re-signed.
      outgoing.end(bytes);
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return {
    agentUrl: `http://127.0.0.1:${server.address().port}`,
    arm(jobId, claimId) {
      assert.equal(armed, null);
      assert.match(jobId, UUID);
      assert.match(claimId, UUID);
      assert.equal(closed, false);
      armed = { jobId, claimId };
    },
    restoreDelivery() {
      assert.ok(armed && refusedResults > 0 && !closed);
      available = true;
    },
    disarm() {
      assert.ok(armed && available && forwardedResults > 0 && !closed);
      armed = null;
    },
    observation() {
      return {
        refusedResults,
        forwardedResults,
        mismatchedResults,
        deliveryRestored: available,
      };
    },
    hasLiveResource: () => !closed || sockets.size > 0 || requests.size > 0,
    async close() {
      if (closing) return await closing;
      closing = (async () => {
        for (const item of requests) item.destroy();
        for (const socket of sockets) socket.destroy();
        await new Promise((resolve, reject) =>
          server.close((error) =>
            error
              ? reject(new Error("Owned result gateway close failed"))
              : resolve(),
          ),
        );
        const end = performance.now() + 5000;
        while ((requests.size || sockets.size) && performance.now() < end)
          await new Promise((resolve) => setTimeout(resolve, 10));
        assert.equal(
          requests.size + sockets.size,
          0,
          "Owned result gateway remains live",
        );
        closed = true;
      })();
      return await closing;
    },
  };
}
module.exports = { startResultOutageGateway, upstream };
