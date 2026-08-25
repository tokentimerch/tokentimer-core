"use strict";

// Local fixtures for the proxy smoke test: a minimal forward-proxy server
// (handles both absolute-URI plain HTTP requests and HTTPS CONNECT tunnels,
// recording which hosts it actually proxied) plus plain HTTP/HTTPS targets
// for the probes to hit through it.
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const { URL } = require("node:url");
const { generateSelfSignedCert } = require("./cert-gen.js");

/**
 * Force-close a server without waiting on `close()`'s callback. A CONNECT
 * tunnel's client-facing socket only half-closes cleanly once its piped
 * upstream peer also ends, which itself depends on the *next* hop (the
 * fixture target) closing first; waiting on the callback here would
 * deadlock unless every fixture were closed in exactly the right order.
 * Since this is a short-lived, single-run test fixture, destroying every
 * open socket directly and not relying on graceful shutdown bookkeeping is
 * the robust choice, with `unref()` as a belt-and-suspenders guard against
 * any other lingering handle keeping the process alive.
 */
function forceCloseServer(server) {
  server.closeAllConnections();
  server.close();
  server.unref();
}

/**
 * A real forward proxy. Absolute-URI requests on the plain HTTP port are
 * proxied directly by the normal `request` handler; HTTPS is proxied via
 * `CONNECT` tunnels. Both paths record the host they connected to, so
 * assertions can check "did the proxy see host X" without instrumenting
 * the client.
 *
 * @param {{ hostAliases?: Record<string, {host: string, port?: number}> }} [options]
 *   hostAliases lets a request/CONNECT target hostname that would not
 *   otherwise resolve (e.g. a reserved-TLD fixture host) be redirected to
 *   a real loopback address+port, without touching real DNS.
 */
function createForwardProxy({ hostAliases = {} } = {}) {
  const connections = [];
  const tunnelSockets = new Set();

  function resolveTarget(hostname, port) {
    const alias = hostAliases[hostname];
    if (alias) return { host: alias.host, port: alias.port ?? port };
    return { host: hostname, port };
  }

  const server = http.createServer((req, res) => {
    let target;
    try {
      target = new URL(req.url);
    } catch (_err) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("Bad Request: proxy fixture expected an absolute-URI request line");
      return;
    }

    const targetPort = target.port ? Number(target.port) : 80;
    connections.push({ host: target.hostname, port: targetPort, via: "http" });
    const resolved = resolveTarget(target.hostname, targetPort);

    const upstreamReq = http.request(
      {
        host: resolved.host,
        port: resolved.port,
        method: req.method,
        path: `${target.pathname}${target.search || ""}`,
        headers: req.headers,
      },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
        upstreamRes.pipe(res);
      },
    );
    upstreamReq.on("error", () => {
      if (!res.headersSent) res.writeHead(502, { "Content-Type": "text/plain" });
      res.end("Bad Gateway");
    });
    req.pipe(upstreamReq);
  });

  server.on("connect", (req, clientSocket, head) => {
    const lastColon = req.url.lastIndexOf(":");
    const hostname = lastColon === -1 ? req.url : req.url.slice(0, lastColon);
    const targetPort = lastColon === -1 ? 443 : Number(req.url.slice(lastColon + 1));
    connections.push({ host: hostname, port: targetPort, via: "connect" });
    const resolved = resolveTarget(hostname, targetPort);

    const upstreamSocket = net.connect(resolved.port, resolved.host, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head && head.length) upstreamSocket.write(head);
      upstreamSocket.pipe(clientSocket);
      clientSocket.pipe(upstreamSocket);
    });
    tunnelSockets.add(clientSocket);
    tunnelSockets.add(upstreamSocket);
    const untrack = () => {
      tunnelSockets.delete(clientSocket);
      tunnelSockets.delete(upstreamSocket);
    };
    upstreamSocket.on("error", () => {
      clientSocket.end();
    });
    clientSocket.on("error", () => {
      upstreamSocket.destroy();
    });
    upstreamSocket.on("close", untrack);
    clientSocket.on("close", untrack);
  });

  function wasConnectedTo(hostname) {
    return connections.some((entry) => entry.host === hostname);
  }

  function listen(port = 0) {
    return new Promise((resolve) => {
      server.listen(port, "127.0.0.1", () => resolve(server.address().port));
    });
  }

  function close() {
    // Destroy raw CONNECT tunnel sockets ourselves; they bypass the
    // http.Server request lifecycle entirely, so closeAllConnections()
    // (below) never reaches them.
    for (const socket of tunnelSockets) socket.destroy();
    tunnelSockets.clear();
    forceCloseServer(server);
    return Promise.resolve();
  }

  return { server, connections, wasConnectedTo, listen, close };
}

function createHttpTarget() {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("OK");
  });

  function listen(port = 0) {
    return new Promise((resolve) => {
      server.listen(port, "127.0.0.1", () => resolve(server.address().port));
    });
  }

  function close() {
    forceCloseServer(server);
    return Promise.resolve();
  }

  return { server, listen, close };
}

function createHttpsTarget({ commonName = "localhost", dnsNames = ["localhost"], ipAddresses = ["127.0.0.1"] } = {}) {
  const { certPem, keyPem } = generateSelfSignedCert({ commonName, dnsNames, ipAddresses });
  const server = https.createServer({ cert: certPem, key: keyPem }, (req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("OK");
  });

  function listen(port = 0) {
    return new Promise((resolve) => {
      server.listen(port, "127.0.0.1", () => resolve(server.address().port));
    });
  }

  function close() {
    forceCloseServer(server);
    return Promise.resolve();
  }

  return { server, certPem, listen, close };
}

module.exports = { createForwardProxy, createHttpTarget, createHttpsTarget };
