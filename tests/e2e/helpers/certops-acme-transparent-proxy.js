"use strict";
/** Qualification-only transparent HTTPS proxy for pinned Pebble v2.8.0.
 * Pebble derives advertised endpoints and expected protected JWS.url from Host.
 * Forwarding the original Host/path/body over pinned upstream TLS preserves that
 * protocol. No directory rewrite, signature mutation or substitute CA exists.
 * Fault modes refuse a stage BEFORE forwarding, so they qualify owned transport
 * refusal rather than a failure response emitted by the real CA. */
const assert = require("node:assert/strict");
const https = require("node:https");
const crypto = require("node:crypto");
const LIMIT = 262144;
const POST_EXACT = new Set([
  "/sign-me-up",
  "/order-plz",
  "/revoke-cert",
  "/rollover-account-key",
]);
const POST_PREFIX =
  /^\/(?:my-account|my-order|finalize-order|authZ|chalZ|certZ|list-orderz)\/[A-Za-z0-9_-]{1,256}$/;
const CERT_ALTERNATE = /^\/certZ\/[A-Za-z0-9_-]{1,256}\/alternate\/[0-9]{1,3}$/;
function endpoint(value) {
  const url = new URL(value);
  assert.equal(url.protocol, "https:");
  assert.equal(url.hostname, "127.0.0.1");
  assert.equal(url.port, "14000");
  assert.equal(url.pathname, "/dir");
  assert.ok(!url.username && !url.password && !url.search && !url.hash);
  return url;
}
function route({
  authority,
  expectedAuthority,
  method,
  rawPath,
  upstreamDirectory,
}) {
  const upstream = endpoint(upstreamDirectory);
  assert.match(expectedAuthority, /^127\.0\.0\.1:[1-9][0-9]{0,4}$/);
  assert.ok(Number(expectedAuthority.split(":")[1]) <= 65535);
  assert.equal(authority, expectedAuthority);
  assert.ok(
    typeof rawPath === "string" &&
      rawPath.length <= 512 &&
      !/[\\%?#\u0000-\u0020]/.test(rawPath),
  );
  assert.ok(!rawPath.includes("..") && !rawPath.includes("//"));
  const canonical = new URL(rawPath, `https://${expectedAuthority}`);
  assert.equal(canonical.origin, `https://${expectedAuthority}`);
  assert.equal(canonical.pathname, rawPath);
  const readEndpoint =
    rawPath === "/dir" ||
    rawPath === "/nonce-plz" ||
    /^\/draft-ietf-acme-ari-03\/renewalInfo\/[A-Za-z0-9_.-]{1,256}$/.test(
      rawPath,
    );
  assert.ok(
    (readEndpoint && ["GET", "HEAD", "POST"].includes(method)) ||
      (method === "POST" &&
        (POST_EXACT.has(rawPath) ||
          POST_PREFIX.test(rawPath) ||
          CERT_ALTERNATE.test(rawPath))),
  );
  const stage =
    rawPath === "/dir"
      ? "directory"
      : rawPath === "/order-plz"
        ? "new-order"
        : rawPath.startsWith("/finalize-order/")
          ? "finalize"
          : rawPath === "/sign-me-up"
            ? "account"
            : rawPath.startsWith("/authZ/")
              ? "authorization"
              : rawPath.startsWith("/my-order/")
                ? "order-observation"
                : "other";
  return {
    upstreamOrigin: upstream.origin,
    path: rawPath,
    host: expectedAuthority,
    stage,
  };
}
async function readBounded(stream) {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    assert.ok(size <= LIMIT, "Owned ACME transport payload exceeds bound");
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}
function identifiersDigest(identifiers) {
  assert.ok(
    Array.isArray(identifiers) &&
      identifiers.length >= 1 &&
      identifiers.length <= 16,
  );
  const rows = identifiers
    .map((item) => {
      assert.equal(item.type, "dns");
      assert.ok(typeof item.value === "string" && item.value.length <= 253);
      return { type: "dns", value: item.value };
    })
    .sort((a, b) => a.value.localeCompare(b.value));
  assert.equal(new Set(rows.map((item) => item.value)).size, rows.length);
  return crypto.createHash("sha256").update(JSON.stringify(rows)).digest("hex");
}
function createOrderObserver({ authority, upstreamDirectory }) {
  const orders = new Map();
  const nativePath = (value) => {
    const url = new URL(value);
    assert.equal(url.origin, `https://${authority}`);
    assert.ok(!url.username && !url.password && !url.search && !url.hash);
    route({
      authority,
      expectedAuthority: authority,
      method: "POST",
      rawPath: url.pathname,
      upstreamDirectory,
    });
    return url.pathname;
  };
  return {
    observe(selected, status, parsed) {
      if (selected.stage === "new-order" && status === 201) {
        assert.ok(orders.size < 64);
        const finalize = nativePath(parsed.finalize);
        assert.ok(finalize.startsWith("/finalize-order/"));
        assert.ok(
          Array.isArray(parsed.authorizations) &&
            parsed.authorizations.length >= 1 &&
            parsed.authorizations.length <= 16,
        );
        const paths = parsed.authorizations.map(nativePath);
        assert.ok(
          paths.every((item) => item.startsWith("/authZ/")) &&
            new Set(paths).size === paths.length,
        );
        assert.ok(!orders.has(finalize));
        orders.set(finalize, {
          authorizations: new Set(paths),
          valid: new Set(),
          identifiersSha256: identifiersDigest(parsed.identifiers),
        });
      }
      if (
        selected.stage === "authorization" &&
        status === 200 &&
        parsed?.status === "valid"
      )
        for (const order of orders.values())
          if (order.authorizations.has(selected.path))
            order.valid.add(selected.path);
    },
    refusal(finalizePath) {
      const order = orders.get(finalizePath);
      return order
        ? {
            knownOrder: true,
            authorizationCount: order.authorizations.size,
            validAuthorizationCount: order.valid.size,
            allAuthorizationsValid:
              order.valid.size === order.authorizations.size,
            identifiersSha256: order.identifiersSha256,
          }
        : { knownOrder: false };
    },
  };
}
function publicCounters() {
  return {
    received: 0,
    forwarded: 0,
    refused: 0,
    acceptedAccounts: 0,
    acceptedOrders: 0,
    validAuthorizations: 0,
    readyOrders: 0,
    forwardedFinalizations: 0,
    issuedResponses: 0,
    unchangedBodies: 0,
  };
}
async function startOwnedAcmeProxy({
  certificatePem,
  privateKeyPem,
  upstreamDirectory,
  upstreamCaPem,
}) {
  endpoint(upstreamDirectory);
  const leaf = new crypto.X509Certificate(certificatePem);
  assert.ok(leaf.checkPrivateKey(crypto.createPrivateKey(privateKeyPem)));
  assert.equal(leaf.checkIP("127.0.0.1"), "127.0.0.1");
  const upstreamCa = new crypto.X509Certificate(upstreamCaPem);
  assert.equal(upstreamCa.checkIP("127.0.0.1"), "127.0.0.1");
  assert.ok(
    upstreamCa.verify(upstreamCa.publicKey),
    "Owned HTTPS trust pin must be self-signed",
  );
  const sockets = new Set(),
    upstreamRequests = new Set(),
    counters = publicCounters();
  const perStage = Object.fromEntries(
    [
      "directory",
      "new-order",
      "finalize",
      "account",
      "authorization",
      "order-observation",
      "other",
    ].map((stage) => [stage, { received: 0, forwarded: 0, refused: 0 }]),
  );
  let authority,
    orderObserver,
    lastRefusedFinalize = null,
    failure = null,
    closed = false,
    failed = false;
  const server = https.createServer(
    { cert: certificatePem, key: privateKeyPem },
    (request, response) => {
      handle(request, response).catch(() => {
        failed = true;
        if (!response.headersSent) response.writeHead(502);
        response.end();
      });
    },
  );
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  server.on("tlsClientError", () => {});
  server.on("error", () => {
    failed = true;
  });
  async function handle(request, response) {
    const selected = route({
      authority: request.headers.host,
      expectedAuthority: authority,
      method: request.method,
      rawPath: request.url,
      upstreamDirectory,
    });
    const body = await readBounded(request);
    counters.received++;
    perStage[selected.stage].received++;
    if (
      failure &&
      (failure === selected.stage ||
        (selected.stage === "directory" &&
          ["unavailable", "rate-limited", "malformed"].includes(failure)))
    ) {
      if (selected.stage === "finalize")
        lastRefusedFinalize = orderObserver.refusal(selected.path);
      counters.refused++;
      perStage[selected.stage].refused++;
      if (failure === "malformed")
        response
          .writeHead(200, { "content-type": "application/json" })
          .end("{owned-invalid-directory");
      else if (failure === "rate-limited")
        response
          .writeHead(429, {
            "content-type": "application/problem+json",
            "retry-after": "0",
          })
          .end(
            JSON.stringify({
              type: "urn:ietf:params:acme:error:rateLimited",
              detail: "Owned qualification proxy transport refusal",
            }),
          );
      else
        response
          .writeHead(503, {
            "content-type": "application/problem+json",
            "retry-after": "0",
          })
          .end(
            JSON.stringify({
              type: "urn:ietf:params:acme:error:serverInternal",
              detail: "Owned qualification proxy transport refusal",
            }),
          );
      return;
    }
    const before = crypto.createHash("sha256").update(body).digest("hex");
    const headers = {
      host: selected.host,
      "x-forwarded-proto": "https",
      "content-length": String(body.length),
    };
    if (typeof request.headers["content-type"] === "string")
      headers["content-type"] = request.headers["content-type"];
    if (typeof request.headers.accept === "string")
      headers.accept = request.headers.accept;
    counters.forwarded++;
    perStage[selected.stage].forwarded++;
    if (selected.stage === "finalize") counters.forwardedFinalizations++;
    await new Promise((resolve, reject) => {
      const upstream = https.request(
        new URL(selected.upstreamOrigin),
        {
          path: selected.path,
          method: request.method,
          headers,
          ca: upstreamCaPem,
          rejectUnauthorized: true,
          timeout: 15000,
          agent: false,
        },
        (reply) => {
          readBounded(reply)
            .then((bytes) => {
              const status = reply.statusCode;
              assert.ok(
                Number.isInteger(status) && status >= 200 && status <= 599,
              );
              let parsed;
              try {
                parsed = JSON.parse(bytes.toString("utf8"));
              } catch {
                /* Certificate responses need not be JSON. */
              }
              if (selected.stage === "account" && [200, 201].includes(status))
                counters.acceptedAccounts++;
              if (selected.stage === "new-order" && status === 201)
                counters.acceptedOrders++;
              if (
                selected.stage === "authorization" &&
                status === 200 &&
                parsed?.status === "valid"
              )
                counters.validAuthorizations++;
              if (
                selected.stage === "order-observation" &&
                status === 200 &&
                parsed?.status === "ready"
              )
                counters.readyOrders++;
              if (status === 200 && selected.path.startsWith("/certZ/"))
                counters.issuedResponses++;
              orderObserver.observe(selected, status, parsed);
              if (
                selected.stage === "directory" &&
                status === 200 &&
                request.method !== "HEAD"
              ) {
                for (const name of ["newNonce", "newAccount", "newOrder"]) {
                  const advertised = new URL(parsed?.[name]);
                  assert.equal(advertised.origin, `https://${authority}`);
                  route({
                    authority,
                    expectedAuthority: authority,
                    method: name === "newNonce" ? "HEAD" : "POST",
                    rawPath: advertised.pathname,
                    upstreamDirectory,
                  });
                }
              }
              const publicHeaders = {};
              for (const name of [
                "content-type",
                "replay-nonce",
                "location",
                "link",
                "retry-after",
              ])
                if (reply.headers[name] !== undefined)
                  publicHeaders[name] = reply.headers[name];
              assert.ok(
                crypto.createHash("sha256").update(body).digest("hex") ===
                  before,
                "Original ACME signed request bytes changed",
              );
              counters.unchangedBodies++;
              response.writeHead(status, publicHeaders);
              response.end(bytes);
              resolve();
            })
            .catch(reject);
        },
      );
      upstreamRequests.add(upstream);
      upstream.once("close", () => upstreamRequests.delete(upstream));
      upstream.once("error", reject);
      upstream.once("timeout", () =>
        upstream.destroy(new Error("Owned ACME upstream deadline")),
      );
      // This exact original Buffer is forwarded; no JWS parse, rewrite or signing.
      upstream.end(body);
    });
  }
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      authority = `127.0.0.1:${server.address().port}`;
      orderObserver = createOrderObserver({ authority, upstreamDirectory });
      resolve();
    });
  });
  return {
    directory: `https://${authority}/dir`,
    setFailure(value) {
      assert.ok(
        [
          null,
          "unavailable",
          "rate-limited",
          "malformed",
          "new-order",
          "finalize",
        ].includes(value),
      );
      assert.equal(closed, false);
      failure = value;
    },
    snapshot() {
      return JSON.parse(
        JSON.stringify({
          ...counters,
          perStage,
          lastRefusedFinalize,
          transportFailed: failed,
        }),
      );
    },
    async close() {
      assert.equal(closed, false);
      closed = true;
      const drained = [...sockets, ...upstreamRequests].map(
        (resource) =>
          new Promise((resolve) => {
            if (resource.closed === true) {
              resolve();
              return;
            }
            resource.once("close", resolve);
            resource.destroy();
          }),
      );
      drained.push(
        new Promise((resolve, reject) =>
          server.close((error) => (error ? reject(error) : resolve())),
        ),
      );
      let timer;
      try {
        await Promise.race([
          Promise.all(drained),
          new Promise((_, reject) => {
            timer = setTimeout(
              () => reject(new Error("Owned ACME proxy drain unconfirmed")),
              10000,
            );
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
      assert.equal(sockets.size, 0);
      assert.equal(upstreamRequests.size, 0);
      assert.equal(server.listening, false);
    },
  };
}
module.exports = {
  LIMIT,
  route,
  endpoint,
  readBounded,
  identifiersDigest,
  createOrderObserver,
  startOwnedAcmeProxy,
};
