"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createRequire } = require("node:module");
const apiRequire = createRequire(require.resolve("../../apps/api/index.js"));
const express = apiRequire("express");
const request = require("supertest");
const { createRemoteBodyParser, remoteCors } = require("../../apps/api/routes/mcpRemote");
const { MCP_PATH, OAUTH_PATH } = require("../../apps/api/services/operator/remoteConfig");

test("remote parser limits malformed and oversized requests before parsing, without limiting unrelated paths", async () => {
  const app = express();
  app.use(createRemoteBodyParser({ limit: 2 }));
  app.use((_req, res) => res.sendStatus(204));
  app.use((error, _req, res, _next) => res.sendStatus(error.status || 500));

  await request(app).post(OAUTH_PATH + "/token").type("json").send("{").expect(400);
  await request(app).post(MCP_PATH).type("json").send(JSON.stringify({ value: "x".repeat(270000) })).expect(413);
  const blocked = await request(app).post(OAUTH_PATH + "/token").type("json").send("{").expect(429);
  assert.equal(blocked.body.error, "temporarily_unavailable");
  await request(app).post("/unrelated").type("json").send("{").expect(204);
});

test("case and trailing-slash route aliases use the same pre-parser limit", async () => {
  for (const path of [MCP_PATH, OAUTH_PATH + "/token"]) {
    const app = express();
    app.use(createRemoteBodyParser({ limit: 1 }));
    app.post(path, (_req, res) => res.sendStatus(204));
    app.use((error, _req, res, _next) => res.sendStatus(error.status || 500));

    await request(app).post(path.toUpperCase() + "/").type("json").send("{").expect(400);
    await request(app).post(path).type("json").send("{}").expect(429);
  }
});

test("percent-encoded static path characters do not match Express routes", async () => {
  const app = express();
  app.use(createRemoteBodyParser({ limit: 1 }));
  app.post(MCP_PATH, (_req, res) => res.sendStatus(204));
  await request(app).post(MCP_PATH.replace("operator", "%6fperator")).type("json").send("{}").expect(404);
  await request(app).post(MCP_PATH).type("json").send("{}").expect(204);
});

test("consent aliases reject client-only origins even behind a public prefix", async () => {
  const keys = ["MCP_OPERATOR_INTERFACE_ENABLED", "MCP_OPERATOR_REMOTE_ENABLED", "MCP_PUBLIC_URL", "APP_URL", "MCP_ALLOWED_ORIGINS"];
  const saved = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  Object.assign(process.env, {
    MCP_OPERATOR_INTERFACE_ENABLED: "true",
    MCP_OPERATOR_REMOTE_ENABLED: "true",
    MCP_PUBLIC_URL: "https://api.example.test/prefix" + MCP_PATH,
    APP_URL: "https://app.example.test",
    MCP_ALLOWED_ORIGINS: "https://client.example.test",
  });
  try {
    const app = express();
    app.use(remoteCors);
    app.get(OAUTH_PATH + "/requests/:id", (_req, res) => res.sendStatus(204));
    await request(app).get((OAUTH_PATH + "/requests/abc").toUpperCase() + "/")
      .set("Host", "api.example.test").set("Origin", "https://client.example.test").expect(403);
    await request(app).get((OAUTH_PATH + "/requests/abc").toUpperCase() + "/")
      .set("Host", "api.example.test").set("Origin", "https://app.example.test").expect(204);
  } finally {
    for (const key of keys) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
});
