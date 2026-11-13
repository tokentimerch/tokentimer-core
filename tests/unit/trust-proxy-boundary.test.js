"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const express = createRequire(require.resolve("../../apps/api/package.json"))("express");
const request = require("supertest");
const { resolveTrustedProxyHops } = require("../../apps/api/config/trustProxy");
const { createCertOpsMachineIpRateLimit } = require("../../apps/api/middleware/machine-ip-rate-limit");

test("direct API ignores forged forwarding headers by default", async () => {
  const app = express();
  app.set("trust proxy", resolveTrustedProxyHops(undefined));
  const previous = process.env.CERTOPS_MACHINE_IP_RATE_LIMIT_MAX;
  process.env.CERTOPS_MACHINE_IP_RATE_LIMIT_MAX = "2";
  const limiter = createCertOpsMachineIpRateLimit();
  if (previous === undefined) delete process.env.CERTOPS_MACHINE_IP_RATE_LIMIT_MAX;
  else process.env.CERTOPS_MACHINE_IP_RATE_LIMIT_MAX = previous;
  app.use(limiter);
  app.get("/", (req, res) => res.json({ ip: req.ip, secure: req.secure }));
  const first = await request(app).get("/").set("X-Forwarded-For", "203.0.113.1").set("X-Forwarded-Proto", "https");
  const second = await request(app).get("/").set("X-Forwarded-For", "203.0.113.2").set("X-Forwarded-Proto", "https");
  assert.equal(first.body.ip, second.body.ip);
  assert.equal(first.body.secure, false);
  const third = await request(app).get("/").set("X-Forwarded-For", "203.0.113.3");
  assert.equal(third.status, 429);
});

test("explicitly configured proxy hops preserve client and protocol resolution", async () => {
  const app = express();
  app.set("trust proxy", resolveTrustedProxyHops("1"));
  app.get("/", (req, res) => res.json({ ip: req.ip, secure: req.secure }));
  const result = await request(app).get("/").set("X-Forwarded-For", "203.0.113.10").set("X-Forwarded-Proto", "https");
  assert.equal(result.body.ip, "203.0.113.10");
  assert.equal(result.body.secure, true);
});

test("proxy hop settings reject invalid or unsafe values", () => {
  assert.equal(resolveTrustedProxyHops(""), 0);
  assert.equal(resolveTrustedProxyHops("0"), 0);
  assert.equal(resolveTrustedProxyHops("2"), 2);
  for (const value of ["-1", "1.5", "true", "NaN", "999999999999999999999"]) {
    assert.throws(() => resolveTrustedProxyHops(value), /TRUST_PROXY_HOPS/);
  }
});

test("direct-access deployment templates default to no proxy trust", () => {
  const root = path.resolve(__dirname, "../..");
  const compose = fs.readFileSync(path.join(root, "deploy/compose/docker-compose.yml"), "utf8");
  const values = fs.readFileSync(path.join(root, "deploy/helm/values.yaml"), "utf8");
  const helper = fs.readFileSync(path.join(root, "deploy/helm/templates/_helpers.tpl"), "utf8");
  assert.match(compose, /TRUST_PROXY_HOPS:\s*\$\{TRUST_PROXY_HOPS:-0\}/);
  assert.match(values, /^\s+trustProxyHops:\s*0\s*$/m);
  assert.match(helper, /TRUST_PROXY_HOPS:\s*"0"/);
});
