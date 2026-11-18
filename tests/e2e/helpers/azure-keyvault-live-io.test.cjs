"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const https = require("node:https");
const { FaultBoundary } = require("./azure-keyvault-live-io.cjs");

const host = "ttkv" + "a".repeat(20) + ".vault.azure.net";
const path = "/secrets/tt-" + "b".repeat(64);

test("the owned-object loss helper observes only direct TLS and never affects a neighboring Azure secret", async t => {
  const events = [];
  const original = https.request;
  t.after(() => { https.request = original; });
  https.request = (_url, _options, callback) => {
    const request = new EventEmitter();
    request.destroy = error => {
      if (!request.destroyed) {
        request.destroyed = true;
        request.emit("error", error);
      }
    };
    setImmediate(() => {
      if (request.destroyed) return;
      const response = new EventEmitter();
      response.statusCode = 200;
      response.socket = { authorized: true };
      response.resume = () => setImmediate(() => response.emit("end"));
      callback(response);
    });
    return request;
  };
  const boundary = new FaultBoundary(host, { objectPath: path, observe: event => events.push(event) });
  assert.throws(() => boundary.set("ambiguous-put", path + "cc", { blockReads: true }), /FAULT_SCOPE_DENIED/);
  const loss = boundary.set("ambiguous-put", path, { blockReads: true });
  boundary.install();

  function request(method, route) {
    return new Promise((resolve, reject) => {
      const pending = https.request(new URL("https://" + host + route), { method, rejectUnauthorized: true },
        response => resolve(response.statusCode));
      pending.on("error", reject);
    });
  }
  assert.throws(() => https.request(new URL("https://" + host + path), { rejectUnauthorized: false }), /TLS_REQUIRED/);
  assert.equal(await request("GET", path + "/versions"), 200);
  await assert.rejects(request("PUT", path), { code: "ECONNRESET" });
  assert.equal(loss.committed, true);
  await assert.rejects(request("GET", path + "/versions"), { code: "ECONNRESET" });
  assert.equal(await request("GET", "/secrets/tt-" + "d".repeat(64)), 200);
  boundary.clear();
  assert.equal(await request("GET", path + "/" + "e".repeat(32)), 200);
  assert.equal(boundary.puts.get(path), 1);
  assert.deepEqual(events.filter(entry => entry.event !== "request"), [
    { event: "response", selected: "versions", method: "GET", status: 200 },
    { event: "response", selected: "object", method: "PUT", status: 200 },
    { event: "commit-lost", selected: "object", method: "PUT", status: 200 },
    { event: "read-blocked", selected: "versions", method: "GET" },
    { event: "response", selected: "version", method: "GET", version: "e".repeat(32), status: 200 },
  ]);
});
