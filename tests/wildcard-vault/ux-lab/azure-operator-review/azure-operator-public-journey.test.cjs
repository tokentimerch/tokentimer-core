"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
const { providerTrace } = require("./azure-operator-public-journey.cjs");

test("provider evidence binds one committed loss and all successful resumed reads to the exact version", () => {
  const version = "3".repeat(32);
  const write = { event: "request", method: "PUT", selected: "object" };
  const read = { event: "response", method: "GET", selected: "version", status: 200, version };
  const issuer = {
    interrupt: [write, { ...write, event: "commit-lost", status: 200 },
      { event: "read-blocked", method: "GET", selected: "versions" }],
    resume: [read],
  };
  const consumers = [[read], [read]];
  assert.deepEqual(providerTrace({ issuer, consumers, version }), {
    providerPutAttempts: 1, providerVersion: version, exactVersionReads: 3, latestFallbacks: 0, restartRepublishAttempts: 0,
  });
  assert.throws(() => providerTrace({ issuer: { ...issuer, resume: [...issuer.resume, write] }, consumers, version }));
  assert.throws(() => providerTrace({ issuer, consumers: [[{ ...read, version: "4".repeat(32) }]], version }), /different provider version/);
  assert.throws(() => providerTrace({ issuer, consumers: [[]], version }), /exact-version read/);
  const latest = { event: "request", method: "GET", selected: "object" };
  assert.throws(() => providerTrace({ issuer, consumers: [[read, latest]], version }));
});
