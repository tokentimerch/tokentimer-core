"use strict";
/** Read-only public identity observation from an original signed claim response.
 * This never verifies a signature, changes signed bytes, or qualifies execution.
 * A caller must independently prove actual agent verification/current claim. */
const assert = require("node:assert/strict");
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
function observeClaimResponse(bytes) {
  assert.ok(
    Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 1048576,
    "Bounded original claim response required",
  );
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw Error("Original claim response is not bounded JSON");
  }
  assert.ok(
    value && Array.isArray(value.jobs) && value.jobs.length <= 128,
    "Bounded actual claim jobs required",
  );
  const records = [];
  for (const envelope of value.jobs) {
    assert.ok(
      envelope &&
        envelope.envelopeVersion === 2 &&
        typeof envelope.payloadB64 === "string" &&
        envelope.payloadB64.length > 0 &&
        envelope.payloadB64.length <= 1048576,
      "Original version2 signed envelope required",
    );
    const payloadBytes = Buffer.from(envelope.payloadB64, "base64");
    assert.ok(
      payloadBytes.toString("base64") === envelope.payloadB64,
      "Canonical original signed payload encoding required",
    );
    let payload;
    try {
      payload = JSON.parse(payloadBytes.toString("utf8"));
    } catch {
      throw Error("Original signed payload cannot be observed");
    }
    assert.ok(
      typeof payload.jobId === "string" && UUID.test(payload.jobId),
      "Public original job identity required",
    );
    assert.ok(
      typeof envelope.signingKeyId === "string" &&
        /^[A-Za-z0-9_.:-]{1,128}$/.test(envelope.signingKeyId),
      "Public original signing key identity required",
    );
    records.push({ jobId: payload.jobId, signingKeyId: envelope.signingKeyId });
  }
  assert.equal(
    new Set(records.map((r) => r.jobId.toLowerCase())).size,
    records.length,
    "One original envelope per claimed job required",
  );
  return records;
}
function createClaimObserver() {
  const seen = new Map();
  let responses = 0;
  return {
    observe(bytes) {
      for (const record of observeClaimResponse(bytes)) {
        const key = record.jobId.toLowerCase();
        if (seen.has(key))
          assert.equal(
            seen.get(key),
            record.signingKeyId,
            "Signing key changed for one observed native job",
          );
        else seen.set(key, record.signingKeyId);
      }
      responses++;
    },
    signingKeyFor(jobId) {
      assert.ok(typeof jobId === "string" && UUID.test(jobId));
      return seen.get(jobId.toLowerCase());
    },
    snapshot() {
      return { responseCount: responses, jobCount: seen.size };
    },
  };
}
async function startClaimGateway(upstreamUrl) {
  const http = require("node:http");
  const target = new URL(upstreamUrl);
  assert.ok(
    target.protocol === "http:" &&
      target.hostname === "127.0.0.1" &&
      target.pathname === "/" &&
      !target.search &&
      !target.hash &&
      !target.username &&
      !target.password,
  );
  const observer = createClaimObserver(),
    sockets = new Set(),
    requests = new Set();
  let failure,
    closed = false;
  const track = (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  };
  const server = http.createServer((request, response) => {
    const exchange = setTimeout(() => {
      failure = Error("Original signing exchange deadline exceeded");
      request.destroy();
      response.destroy();
    }, 30000);
    response.once("finish", () => clearTimeout(exchange));
    response.once("close", () => clearTimeout(exchange));
    if (
      request.method !== "POST" ||
      !/^\/api\/v1\/certops\/agent\/(?:register|heartbeat|jobs\/(?:claim|results|[a-f0-9-]{36}\/(?:lease|logs)))$/.test(
        request.url,
      )
    ) {
      response.writeHead(404).end();
      return;
    }
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size <= 1048576) chunks.push(chunk);
    });
    request.once("error", () => response.destroy());
    request.once("end", () => {
      if (size > 1048576) {
        response.writeHead(413).end();
        return;
      }
      const forwarded = http.request(
        {
          hostname: target.hostname,
          port: target.port,
          path: request.url,
          method: "POST",
          headers: {
            ...request.headers,
            host: target.host,
            connection: "close",
          },
        },
        (upstream) => {
          const data = [];
          let length = 0;
          upstream.on("data", (chunk) => {
            length += chunk.length;
            if (length <= 1048576) data.push(chunk);
            else upstream.destroy();
          });
          upstream.once("error", () => {
            failure = Error("Original signing response transport failed");
            response.destroy();
          });
          upstream.once("end", () => {
            try {
              assert.ok(length <= 1048576);
              const bytes = Buffer.concat(data);
              if (
                request.url.endsWith("/jobs/claim") &&
                upstream.statusCode === 200
              )
                observer.observe(bytes);
              response.writeHead(upstream.statusCode, {
                ...upstream.headers,
                connection: "close",
              });
              response.end(bytes);
            } catch {
              failure = Error("Original signing response observation failed");
              response.destroy();
            }
          });
        },
      );
      requests.add(forwarded);
      forwarded.once("close", () => requests.delete(forwarded));
      forwarded.once("socket", track);
      forwarded.once("error", () => {
        failure = Error("Original signing upstream failed");
        response.destroy();
      });
      forwarded.setTimeout(30000, () => forwarded.destroy());
      forwarded.end(Buffer.concat(chunks));
    });
  });
  server.on("connection", track);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return {
    agentUrl: `http://127.0.0.1:${server.address().port}`,
    signingKeyFor(id) {
      if (failure) throw failure;
      return observer.signingKeyFor(id);
    },
    async close() {
      if (closed) return;
      const drained = [...sockets].map(
        (socket) => new Promise((resolve) => socket.once("close", resolve)),
      );
      const completion = new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
      for (const request of requests) request.destroy();
      for (const socket of sockets) socket.destroy();
      await Promise.all([completion, ...drained]);
      assert.equal(sockets.size, 0);
      assert.equal(requests.size, 0);
      closed = true;
    },
    assertClean() {
      assert.equal(closed, true);
      assert.equal(sockets.size, 0);
      assert.equal(requests.size, 0);
      if (failure) throw failure;
    },
  };
}
module.exports = {
  observeClaimResponse,
  createClaimObserver,
  startClaimGateway,
};
