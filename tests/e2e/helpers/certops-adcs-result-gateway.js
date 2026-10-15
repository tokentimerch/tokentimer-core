"use strict";

// A transport-only fault for the existing disposable AD CS member. The actual
// API still verifies original signed bytes. No result/claim/ACK is fabricated,
// and neither credentials nor request bodies enter the public observations.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const https = require("node:https");
const tls = require("node:tls");
const { setTimeout: delay } = require("node:timers/promises");
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const ROUTE =
  /^\/api\/v1\/certops\/agent\/(?:register|heartbeat|jobs\/(?:claim|results|[a-f0-9-]{36}\/(?:lease|logs)))$/;
const RESULT = "/api/v1/certops/agent/jobs/results";
const CLAIM = "/api/v1/certops/agent/jobs/claim";
const MAX_BYTES = 1048576;

function upstreamIdentity(value, certificateBytes) {
  const url = new URL(value);
  assert.equal(url.protocol, "https:");
  assert.ok(["10.64.0.6", "127.0.0.1"].includes(url.hostname));
  assert.equal(url.pathname, "/");
  assert.ok(!url.username && !url.password && !url.search && !url.hash);
  const port = Number(url.port || "443");
  assert.ok(Number.isInteger(port) && port >= 1 && port <= 65535);
  assert.ok(
    Buffer.isBuffer(certificateBytes) && certificateBytes.length <= 65536,
  );
  const certificate = new crypto.X509Certificate(certificateBytes);
  assert.ok(
    Date.parse(certificate.validFrom) <= Date.now() &&
      Date.now() < Date.parse(certificate.validTo),
  );
  return { hostname: url.hostname, port, certificate };
}

async function startOwnedResultGateway({
  upstreamUrl,
  upstreamCertificate,
  onCreated,
}) {
  const target = upstreamIdentity(upstreamUrl, upstreamCertificate);
  assert.equal(
    typeof onCreated,
    "function",
    "Ownership must register before listen",
  );
  const sockets = new Set(),
    requests = new Set();
  let selected = null,
    claimId = null,
    seenClaimId = null,
    delivery = false;
  let listening = false,
    closed = false,
    closing,
    failed = false;
  let refusedResults = 0,
    forwardedResults = 0,
    mismatchedResults = 0;
  const server = http.createServer(
    { maxHeaderSize: 16384 },
    (request, response) => {
      request.setTimeout(10000, () => {
        request.destroy();
        response.destroy();
      });
      const deadline = setTimeout(() => {
        request.destroy();
        response.destroy();
      }, 15000);
      // IncomingMessage close can mean the POST body finished while its
      // upstream response is still pending. Bound the complete exchange.
      response.once("close", () => clearTimeout(deadline));
      response.once("finish", () => clearTimeout(deadline));
      request.once("aborted", () => clearTimeout(deadline));
      if (
        closed ||
        failed ||
        requests.size >= 64 ||
        request.method !== "POST" ||
        !ROUTE.test(request.url)
      ) {
        response.writeHead(404).end();
        return;
      }
      // Hold all native admission until the parent has registered the actual
      // public enrollment's job ID. This removes a fast-certreq arming race.
      if (request.url === CLAIM && (!selected || (!delivery && seenClaimId))) {
        response.writeHead(503).end();
        return;
      }
      const chunks = [];
      let length = 0,
        oversized = false;
      request.on("data", (chunk) => {
        length += chunk.length;
        if (length > MAX_BYTES) oversized = true;
        else chunks.push(chunk);
      });
      request.once("error", () => response.destroy());
      request.once("end", () => {
        if (response.destroyed) return;
        if (oversized) {
          response.writeHead(413).end();
          return;
        }
        const bytes = Buffer.concat(chunks);
        let matching = false;
        if (request.url === RESULT) {
          let envelope;
          try {
            envelope = JSON.parse(bytes.toString("utf8"));
          } catch {
            /* Fail closed below. */
          }
          // Evidence uses this same API route and must continue to reach the
          // genuine API; refusing evidence would test a different failure.
          if (envelope?.messageType !== "evidence") {
            matching = Boolean(
              selected &&
              envelope?.messageType === "result" &&
              envelope.body?.jobId === selected &&
              UUID.test(envelope.body?.claimId),
            );
            if (
              !matching ||
              (claimId && envelope.body.claimId !== claimId) ||
              (seenClaimId && envelope.body.claimId !== seenClaimId)
            ) {
              mismatchedResults++;
              response.writeHead(409).end();
              return;
            }
            seenClaimId = envelope.body.claimId;
            if (!delivery) {
              refusedResults++;
              response
                .writeHead(503, { "content-type": "application/json" })
                .end(
                  '{"error":"owned qualification result transport unavailable"}',
                );
              return;
            }
          }
        }
        const headers = {
          ...request.headers,
          host: `${target.hostname}:${target.port}`,
          "content-length": String(bytes.length),
          "accept-encoding": "identity",
        };
        delete headers.connection;
        delete headers["transfer-encoding"];
        const outgoing = https.request(
          {
            hostname: target.hostname,
            port: target.port,
            path: request.url,
            method: "POST",
            headers,
            agent: false,
            ca: upstreamCertificate,
            rejectUnauthorized: true,
            checkServerIdentity(host, certificate) {
              const error = tls.checkServerIdentity(host, certificate);
              if (error) return error;
              if (!certificate.raw?.equals(target.certificate.raw))
                return new Error("Owned API certificate identity mismatch");
            },
          },
          (incoming) => {
            let received = 0;
            if (
              incoming.headers["content-encoding"] &&
              incoming.headers["content-encoding"] !== "identity"
            ) {
              incoming.destroy();
              response.writeHead(502).end();
              return;
            }
            if (matching && incoming.statusCode === 200) forwardedResults++;
            response.writeHead(incoming.statusCode, {
              "content-type":
                incoming.headers["content-type"] || "application/json",
              ...(incoming.headers.date ? { date: incoming.headers.date } : {}),
            });
            incoming.on("data", (chunk) => {
              received += chunk.length;
              if (received > MAX_BYTES) {
                incoming.destroy();
                response.destroy();
              } else response.write(chunk);
            });
            incoming.once("end", () => response.end());
            incoming.once("error", () => response.destroy());
          },
        );
        requests.add(outgoing);
        outgoing.once("close", () => requests.delete(outgoing));
        outgoing.setTimeout(15000, () => outgoing.destroy());
        outgoing.once("error", () => {
          if (!response.headersSent && !response.destroyed)
            response.writeHead(502).end();
          else response.destroy();
        });
        response.once("close", () => {
          if (!outgoing.destroyed) outgoing.destroy();
        });
        outgoing.end(bytes); // Exact original signed transport bytes.
      });
    },
  );
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    if (sockets.size > 64) socket.destroy();
  });
  server.on("error", () => {
    failed = true;
  });
  const resource = {
    get agentUrl() {
      assert.equal(listening, true);
      return `http://127.0.0.1:${server.address().port}`;
    },
    selectJob(jobId) {
      assert.match(jobId, UUID);
      assert.equal(selected, null);
      assert.equal(closed, false);
      selected = jobId;
    },
    bindClaim(value) {
      assert.match(value, UUID);
      assert.ok(selected && !delivery && !closed);
      assert.equal(claimId, null);
      if (seenClaimId) assert.equal(value, seenClaimId);
      claimId = value;
    },
    restoreDelivery() {
      assert.ok(
        selected &&
          claimId &&
          seenClaimId === claimId &&
          refusedResults > 0 &&
          !closed &&
          !failed,
      );
      delivery = true;
    },
    observation() {
      return {
        refusedResults,
        forwardedResults,
        mismatchedResults,
        deliveryRestored: delivery,
        gatewayHealthy: !failed,
      };
    },
    hasLiveResource() {
      return !closed || sockets.size > 0 || requests.size > 0;
    },
    async close() {
      if (closing) return await closing;
      closing = (async () => {
        for (const request of requests) request.destroy();
        for (const socket of sockets) socket.destroy();
        await new Promise((resolve, reject) =>
          server.close((error) =>
            error && error.code !== "ERR_SERVER_NOT_RUNNING"
              ? reject(new Error("Owned result gateway close failed"))
              : resolve(),
          ),
        );
        const end = performance.now() + 5000;
        while (sockets.size || requests.size) {
          assert.ok(
            performance.now() < end,
            "Owned result gateway did not drain",
          );
          await delay(10);
        }
        listening = false;
        closed = true;
      })();
      return await closing;
    },
  };
  onCreated(resource);
  try {
    await new Promise((resolve, reject) => {
      const failed = () =>
        reject(new Error("Owned result gateway listen failed"));
      server.once("error", failed);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", failed);
        listening = true;
        resolve();
      });
    });
    return resource;
  } catch {
    await resource.close();
    throw new Error("Owned result gateway did not start");
  }
}

module.exports = { upstreamIdentity, startOwnedResultGateway };
