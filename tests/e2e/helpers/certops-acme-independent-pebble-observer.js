"use strict";

// Adapter for a separately built, loopback-only Pebble qualification fixture.
// A caller must supply independent, continuous process/endpoint monitoring;
// this module cannot infer continuity from two HTTP snapshots alone.
const assert = require("node:assert/strict");
const https = require("node:https");
const tls = require("node:tls");
const { createHash } = require("node:crypto");

const HASH = /^[a-f0-9]{64}$/;
const INSTANCE = /^[a-f0-9]{32}$/;
const DNS = /^tt-acme-[a-f0-9]{24}\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const MAX_BYTES = 65536;

function checkPin(hostname, cert, expected) {
  const error = tls.checkServerIdentity(hostname, cert);
  if (error) return error;
  if (!Buffer.isBuffer(cert.raw) || createHash("sha256").update(cert.raw).digest("hex") !== expected) {
    return new Error("Qualification CA TLS certificate pin mismatch");
  }
}

function requestSnapshot({ origin, caPem, tlsSha256, dnsName }) {
  const url = new URL(origin);
  assert.equal(url.protocol, "https:");
  assert.equal(url.hostname, "127.0.0.1");
  assert.ok(url.port && !url.username && !url.password && url.pathname === "/" && !url.search && !url.hash);
  assert.ok((typeof caPem === "string" || Buffer.isBuffer(caPem)) && caPem.length > 0, "Explicit test CA trust is required");
  assert.match(tlsSha256, HASH);
  assert.match(dnsName, DNS);
  url.pathname = "/qualification-orders";
  url.searchParams.set("dns", dnsName);
  return new Promise((resolve, reject) => {
    const request = https.get(url, {
      ca: caPem,
      rejectUnauthorized: true,
      timeout: 5000,
      agent: false,
      checkServerIdentity: (hostname, cert) => checkPin(hostname, cert, tlsSha256),
    }, (response) => {
      if (response.statusCode !== 200) { response.resume(); reject(new Error("CA snapshot failed")); return; }
      let size = 0;
      const chunks = [];
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BYTES) { request.destroy(new Error("CA snapshot exceeds limit")); return; }
        chunks.push(chunk);
      });
      response.once("error", reject);
      response.once("end", () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch { reject(new Error("Invalid CA snapshot")); }
      });
    });
    request.once("timeout", () => request.destroy(new Error("CA snapshot timed out")));
    request.once("error", reject);
  });
}

async function createIndependentPebbleObserver({ origin, caPem, tlsSha256, binarySha256, dnsName, inspectContinuity, readSnapshot = requestSnapshot }) {
  assert.match(binarySha256, HASH);
  assert.match(tlsSha256, HASH);
  assert.match(dnsName, DNS);
  assert.equal(typeof inspectContinuity, "function");
  const validateSnapshot = (snapshot) => {
    assert.match(snapshot?.instanceId, INSTANCE);
    assert.ok(Array.isArray(snapshot.orders) && snapshot.orders.length <= 10000);
    const ids = new Set();
    for (const row of snapshot.orders) {
      assert.match(row.orderId, HASH);
      assert.ok(!ids.has(row.orderId)); ids.add(row.orderId);
      if (row.fingerprintSha256 !== undefined) assert.match(row.fingerprintSha256, HASH);
    }
    return ids;
  };
  const read = () => readSnapshot({ origin, caPem, tlsSha256, dnsName });
  const initial = await read();
  validateSnapshot(initial);
  assert.equal(initial.orders.length, 0, "Qualification DNS must have no prior orders");
  const initialGuard = await inspectContinuity();
  function verifyGuard(guard) {
    assert.equal(guard?.coverageComplete, true);
    assert.equal(guard.startedBeforeIssue, true);
    assert.equal(guard.lossFree, true);
    assert.equal(guard.managementLoopback, true);
    assert.equal(guard.instanceId, initial.instanceId);
    assert.equal(guard.binarySha256, binarySha256);
    assert.ok(Number.isSafeInteger(guard.processId) && guard.processId > 0);
    assert.match(guard.captureId, INSTANCE);
  }
  verifyGuard(initialGuard);
  const previous = new Map();
  let failed = false, busy = false;
  return async function observe() {
    assert.equal(failed, false, "CA observation was permanently invalidated");
    if (busy) { failed = true; throw new Error("Concurrent CA observation invalidated the interval"); }
    busy = true;
    try {
    const guardBefore = await inspectContinuity(); verifyGuard(guardBefore);
    const current = await read(); validateSnapshot(current);
    const guardAfter = await inspectContinuity(); verifyGuard(guardAfter);
    for (const guard of [guardBefore, guardAfter]) {
      assert.equal(guard.captureId, initialGuard.captureId);
      assert.equal(guard.processId, initialGuard.processId);
    }
    assert.equal(current.instanceId, initial.instanceId, "CA instance changed during observation");
    const now = new Map(current.orders.map(row => [row.orderId, row.fingerprintSha256]));
    for (const [id, fingerprint] of previous) {
      assert.ok(now.has(id), "CA order disappeared");
      if (fingerprint !== undefined) assert.equal(now.get(id), fingerprint, "Issued identity changed");
    }
    for (const [id, fingerprint] of now) previous.set(id, fingerprint);
    const finalized = current.orders.filter(row => row.fingerprintSha256 !== undefined);
    assert.equal(failed, false, "CA observation was permanently invalidated");
    return { source: "independent-ca", dnsName, coverageComplete: true, coverageId: initialGuard.captureId,
      ordersForDns: current.orders.length, finalizedOrdersForDns: finalized.length,
      orderId: current.orders.length === 1 ? current.orders[0].orderId : null,
      fingerprintSha256: finalized.length === 1 ? finalized[0].fingerprintSha256 : null };
    } catch (error) { failed = true; throw error; } finally { busy = false; }
  };
}

module.exports = { checkPin, requestSnapshot, createIndependentPebbleObserver };
