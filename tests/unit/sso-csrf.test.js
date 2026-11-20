"use strict";

const { it } = require("node:test");
const { createRequire } = require("node:module");
const request = require("supertest");
const apiRequire = createRequire(require.resolve("../../apps/api/package.json"));
const express = apiRequire("express");

it("only bypasses CSRF for the provider-scoped SAML callback POST", async (t) => {
  const previousEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = "development";
  const { csrfExempt } = require("../../apps/api/middleware/csrf.js");
  t.after(() => {
    if (previousEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousEnv;
  });

  const app = express();
  app.use("/api", csrfExempt);
  app.use("/auth", csrfExempt);
  app.use((_req, res) => res.sendStatus(204));
  app.use((err, _req, res, _next) => res.sendStatus(err.statusCode || 403));

  await request(app).post("/auth/saml/keycloak/callback").expect(204);
  await request(app).get("/auth/oidc/keycloak/callback").expect(204);
  await request(app).post("/auth/oidc/keycloak/callback").expect(403);
  await request(app).post("/auth/saml/callback").expect(403);
  await request(app).post("/auth/saml/keycloak/metadata").expect(403);
  await request(app).post("/api/saml/keycloak/callback").expect(403);
  await request(app).post("/auth/login").expect(403);
});
